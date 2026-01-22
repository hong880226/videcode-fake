package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns" // 需要运行: go get github.com/miekg/dns
)

const (
	fakeBaseIP = "127.0.0.0" // we'll allocate 127.0.0.x per qname
	defaultTTL = 60          // seconds, for our synthetic A answers
	dohTimeout = 6 * time.Second
)

type resolverFunc func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)

var defaultPrewarmDomains = []string{
	"api2.cursor.sh",
	"api3.cursor.sh",
	"api4.cursor.sh",
	"repo42.cursor.sh",
	"downloads.cursor.com",
	"cursor.com",
	"marketplace.cursorapi.com",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type stringListFlag struct {
	values []string
}

func (s *stringListFlag) String() string {
	return strings.Join(s.values, ",")
}

func (s *stringListFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		s.values = append(s.values, "")
		return nil
	}
	// allow both repeated flag and comma-separated for convenience
	if strings.Contains(v, ",") {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			s.values = append(s.values, p)
		}
		return nil
	}
	s.values = append(s.values, v)
	return nil
}

func (s *stringListFlag) Values() []string {
	var out []string
	for _, v := range s.values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

type realInfo struct {
	ips    []net.IP
	domain string
}

type cursorIPMap struct {
	mu sync.RWMutex

	// qname (fqdn, lower-case) -> fake loopback IP (v4)
	domainToFake map[string]net.IP

	// fake IP string -> real remote ips (v4/v6) WITHOUT port and qname
	fakeToReal map[string]*realInfo

	nextOctet byte // allocate 127.0.0.nextOctet
}

func newCursorIPMap() *cursorIPMap {
	return &cursorIPMap{
		domainToFake: make(map[string]net.IP),
		fakeToReal:   make(map[string]*realInfo),
		nextOctet:    2, // 127.0.0.1 often used; start from .2
	}
}

func (m *cursorIPMap) getOrAllocFakeLocked(qname string) net.IP {
	if ip, ok := m.domainToFake[qname]; ok {
		return ip
	}
	base := net.ParseIP(fakeBaseIP).To4()
	if base == nil {
		// should never happen
		base = net.IPv4(127, 0, 0, 0)
	}
	ip := net.IPv4(base[0], base[1], base[2], m.nextOctet)
	// best-effort: avoid 127.0.0.0 and wrap; collisions are unlikely in small usage
	if m.nextOctet == 255 {
		m.nextOctet = 2
	} else {
		m.nextOctet++
	}
	m.domainToFake[qname] = ip
	return ip
}

func (m *cursorIPMap) RecordMany(qname string, realIPs []net.IP) net.IP {
	qname = strings.ToLower(dns.Fqdn(qname))
	m.mu.Lock()
	defer m.mu.Unlock()
	fake := m.getOrAllocFakeLocked(qname)
	if len(realIPs) == 0 {
		return fake
	}

	key := fake.String()
	existing := m.fakeToReal[key]
	if existing == nil {
		existing = &realInfo{domain: qname}
	} else {
		existing.domain = qname
	}
	for _, rip := range realIPs {
		if rip == nil {
			continue
		}
		dup := false
		for _, e := range existing.ips {
			if e != nil && e.Equal(rip) {
				dup = true
				break
			}
		}
		if !dup {
			existing.ips = append(existing.ips, rip)
		}
	}
	m.fakeToReal[key] = existing
	return fake
}

func (m *cursorIPMap) LookupRealByFake(fake net.IP) (net.IP, string, bool) {
	if fake == nil {
		return nil, "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	realInfo, ok := m.fakeToReal[fake.String()]
	if !ok || len(realInfo.ips) == 0 {
		return nil, "", false
	}
	return realInfo.ips[rand.Intn(len(realInfo.ips))], realInfo.domain, true
}

// --- 1. DNS 劫持部分 ---
func startDNSServer(listenAddr string, resolve resolverFunc) {
	handler := dns.NewServeMux()

	handler.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
		defer cancel()

		resp, err := resolve(ctx, r)
		if err != nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(resp)
	})

	udpServer := &dns.Server{Addr: listenAddr, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: listenAddr, Net: "tcp", Handler: handler}

	log.Printf("DNS server started at %s (udp/tcp). hijackSuffix=cursor", listenAddr)

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Failed to start DNS TCP server: %v", err)
		}
	}()
	if err := udpServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS UDP server: %v", err)
	}
}

// --- 2. TCP 透明转发部分 (不触碰 TLS 内容) ---
func startForwarder(localListen string, cmap *cursorIPMap, rp *remoteProxyConfig) {
	listener, err := net.Listen("tcp", localListen)
	if err != nil {
		log.Fatalf("Failed to start forwarder: %v", err)
	}
	log.Printf("Traffic Forwarder started at %s (routes by local dst ip)\n", localListen)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go func(src net.Conn) {
			defer src.Close()
			laddr, ok := src.LocalAddr().(*net.TCPAddr)
			if !ok {
				log.Printf("Unexpected local addr type: %T", src.LocalAddr())
				return
			}
			realIP, domain, ok := cmap.LookupRealByFake(laddr.IP)
			if !ok {
				log.Printf("No mapping for dst=%s; drop", laddr.IP.String())
				return
			}

			var remote string
			var dst net.Conn
			var err error
			if rp != nil {
				ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
				defer cancel()
				remote = net.JoinHostPort(domain, fmt.Sprintf("%d", laddr.Port))
				log.Printf("Dial remote=%s via proxy=%s (client=%s -> dst=%s)", remote, rp.addr, src.RemoteAddr().String(), laddr.String())
				dst, err = dialViaRemoteProxy(ctx, rp, remote)
			} else {
				// 每次发起 remote 请求（拨号）都打印日志
				remote = net.JoinHostPort(realIP.String(), fmt.Sprintf("%d", laddr.Port))
				log.Printf("Dial remote=%s (client=%s -> dst=%s)", remote, src.RemoteAddr().String(), laddr.String())
				dst, err = net.Dial("tcp", remote)
			}
			if err != nil {
				log.Printf("Remote dial error (%s): %v", remote, err)
				return
			}
			defer dst.Close()

			// 双向透传流量 (HTTP/2 帧会原样通过)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { io.Copy(dst, src); wg.Done() }()
			go func() { io.Copy(src, dst); wg.Done() }()
			wg.Wait()
		}(clientConn)
	}
}

type remoteProxyConfig struct {
	scheme     string // "http" or "https"
	addr       string // host:port
	serverName string // for https
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func parseRemoteProxy(raw string) (*remoteProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// allow "host:port" shorthand
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse remote proxy: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy host empty")
	}

	host := u.Host
	// if no port, default based on scheme
	if _, _, err := net.SplitHostPort(host); err != nil {
		if strings.Contains(host, ":") {
			return nil, fmt.Errorf("proxy needs explicit port: %s", host)
		}
		if u.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}

	h, _, _ := net.SplitHostPort(host)
	return &remoteProxyConfig{
		scheme:     u.Scheme,
		addr:       host,
		serverName: h,
	}, nil
}

func dialViaRemoteProxy(ctx context.Context, proxy *remoteProxyConfig, targetAddr string) (net.Conn, error) {
	if proxy == nil {
		return nil, fmt.Errorf("proxy is nil")
	}

	dialer := &net.Dialer{Timeout: dohTimeout}

	var conn net.Conn
	var err error
	if proxy.scheme == "https" {
		baseConn, err := dialer.DialContext(ctx, "tcp", proxy.addr)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
		tlsConn := tls.Client(baseConn, &tls.Config{
			ServerName: proxy.serverName,
			MinVersion: tls.VersionTLS12,
		})
		if deadline, ok := ctx.Deadline(); ok {
			_ = tlsConn.SetDeadline(deadline)
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = baseConn.Close()
			return nil, fmt.Errorf("proxy tls handshake: %w", err)
		}
		conn = tlsConn
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", proxy.addr)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
	}

	// HTTP CONNECT tunnel
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy write CONNECT: %w", err)
	}

	br := bufio.NewReaderSize(conn, 8192)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy read status: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.Contains(statusLine, " 200 ") && !strings.HasSuffix(statusLine, " 200") {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", statusLine)
	}

	// consume headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy read headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Keep any buffered bytes for the tunnel
	return &bufferedConn{Conn: conn, r: br}, nil
}

func handleDNSQuery(ctx context.Context, r *dns.Msg, upstream resolverFunc, cmap *cursorIPMap) (*dns.Msg, error) {
	if r == nil || len(r.Question) == 0 {
		return nil, fmt.Errorf("empty dns msg")
	}
	q := r.Question[0]
	qname := strings.ToLower(dns.Fqdn(q.Name))

	// only hijack cursor.sh (domain-suffix)
	if (strings.HasSuffix(qname, "cursor.sh") ||
		strings.HasSuffix(qname, "cursor.com") ||
		strings.HasSuffix(qname, "cursorapi.com")) && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
		realResp, err := upstream(ctx, r)
		if err != nil {
			return nil, err
		}

		realIPs := extractAllIPs(realResp)
		if len(realIPs) == 0 {
			// If upstream has no IP answer, propagate upstream response as-is
			return realResp, nil
		}

		fake := cmap.RecordMany(qname, realIPs)
		return buildSyntheticAReply(r, q.Name, fake), nil
	}

	// default: passthrough
	return upstream(ctx, r)
}

func extractAllIPs(resp *dns.Msg) []net.IP {
	if resp == nil {
		return nil
	}
	var out []net.IP
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if v.A != nil {
				out = append(out, v.A.To4())
			}
		case *dns.AAAA:
			if v.AAAA != nil {
				out = append(out, v.AAAA.To16())
			}
		}
	}
	// de-dup
	var uniq []net.IP
	for _, ip := range out {
		if ip == nil {
			continue
		}
		found := false
		for _, u := range uniq {
			if u != nil && u.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			uniq = append(uniq, ip)
		}
	}
	return uniq
}

func resolveHostIP(ctx context.Context, upstream resolverFunc, host string) ([]net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	// Prefer A, then AAAA
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		resp, err := upstream(ctx, m)
		if err != nil {
			continue
		}
		ips := extractAllIPs(resp)
		if len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("no ip answer for host=%s", host)
}

func buildSyntheticAReply(req *dns.Msg, qname string, fake net.IP) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	ip4 := fake.To4()
	if ip4 == nil {
		return m
	}

	fqdn := dns.Fqdn(qname)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
		A:   ip4,
	})
	return m
}

func resolveViaDoH(ctx context.Context, c *http.Client, dohURL string, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("new http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := c.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("doh http status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack doh dns msg: %w", err)
	}

	// 保持与客户端请求一致的 ID
	out.Id = req.Id
	return out, nil
}

func resolveViaDoT(ctx context.Context, addr string, serverName string, insecureSkipVerify bool, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	dialer := &net.Dialer{Timeout: dohTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("dot dial: %w", err)
	}
	defer conn.Close()

	// honor ctx
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// RFC1035 TCP framing: 2-byte length prefix
	var lenBuf [2]byte
	if len(wire) > 65535 {
		return nil, fmt.Errorf("dns message too large: %d", len(wire))
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, fmt.Errorf("dot write len: %w", err)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("dot write msg: %w", err)
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("dot read len: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > 65535 {
		return nil, fmt.Errorf("dot invalid response length: %d", n)
	}
	respBuf := make([]byte, n)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("dot read msg: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("unpack dot dns msg: %w", err)
	}
	out.Id = req.Id
	return out, nil
}

func resolveViaUDP(ctx context.Context, addr string, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	dialer := &net.Dialer{Timeout: dohTimeout}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udp dial: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// For UDP, miekg/dns expects raw DNS message without TCP length prefix.
	dc := &dns.Conn{Conn: conn}
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("udp write msg: %w", err)
	}
	respBuf := make([]byte, 65535)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("udp read msg: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(respBuf[:n]); err != nil {
		return nil, fmt.Errorf("unpack udp dns msg: %w", err)
	}
	out.Id = req.Id
	_ = dc
	return out, nil
}

func chainResolvers(resolvers ...resolverFunc) resolverFunc {
	// returns first successful response; falls back only on transport/parse errors (err != nil)
	return func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		var lastErr error
		for _, r := range resolvers {
			if r == nil {
				continue
			}
			resp, err := r(ctx, req)
			if err == nil && resp != nil {
				return resp, nil
			}
			if err != nil {
				lastErr = err
			}
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no upstream resolvers configured")
		}
		return nil, lastErr
	}
}

func main() {
	var (
		listenAddr = flag.String("listen", "127.0.0.1:53", "DNS listen address (udp/tcp). Note: :53 requires root on Linux.")

		dotAddr    = flag.String("dot-addr", "1.1.1.1:853", "DoT upstream address (host:port), e.g. 1.1.1.1:853. When set, upstream uses DoT instead of DoH.")
		dotSNI     = flag.String("dot-server-name", "cloudflare-dns.com", "DoT TLS ServerName (SNI) / certificate name, e.g. cloudflare-dns.com")
		dotInsec   = flag.Bool("dot-insecure", false, "Skip TLS certificate verification for DoT (NOT recommended)")
		prewarmDef = flag.Bool("defaults", false, "Pre-warm fake-ip allocation for built-in cursor domains (api2/api3/api4/repo42.cursor.sh)")

		forwardListen = flag.String("forward-listen", ":443", "TCP forward listen addr, e.g. :443 or 127.0.0.1:443 (empty to disable)")
		remoteProxy   = flag.String("remote-proxy", "", "Optional remote HTTP proxy for forwarding (CONNECT). Example: 10.0.0.2:3128 or https://proxy.example.com:443. Empty to disable.")
	)

	var (
		udpAddrs stringListFlag
		dohURLs  stringListFlag
	)
	// defaults (repeatable)
	_ = udpAddrs.Set("114.114.114.114:53")
	_ = udpAddrs.Set("223.5.5.5:53")
	_ = dohURLs.Set("https://114.114.114.114/dns-query")
	_ = dohURLs.Set("https://223.5.5.5/dns-query")
	flag.Var(&udpAddrs, "udp-addr", "UDP DNS upstream address (host:port). Can be repeated. Tried first (in order); then DoT; then DoH. Use empty to disable.")
	flag.Var(&dohURLs, "doh", "DoH endpoint URL (RFC8484, application/dns-message). Can be repeated. Tried after DoT (in order). Use empty to disable.")

	flag.Parse()

	cmap := newCursorIPMap()

	rp, err := parseRemoteProxy(*remoteProxy)
	if err != nil {
		log.Fatalf("Invalid -remote-proxy: %v", err)
	}
	if rp != nil {
		log.Printf("Remote proxy enabled: scheme=%s addr=%s", rp.scheme, rp.addr)
	}

	var udpUp resolverFunc
	if addrs := udpAddrs.Values(); len(addrs) > 0 {
		log.Printf("Upstream(1st): UDP addr=%v", addrs)
		udpUp = func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
			var lastErr error
			for _, a := range addrs {
				resp, err := resolveViaUDP(ctx, a, req)
				if err == nil && resp != nil {
					return resp, nil
				}
				if err != nil {
					lastErr = err
				}
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("udp upstream disabled")
			}
			return nil, lastErr
		}
	}

	var dohUp resolverFunc
	if urls := dohURLs.Values(); len(urls) > 0 {
		httpClient := &http.Client{Timeout: dohTimeout}
		log.Printf("Upstream(2nd): DoH url=%v", urls)
		dohUp = func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
			var lastErr error
			for _, u := range urls {
				resp, err := resolveViaDoH(ctx, httpClient, u, req)
				if err == nil && resp != nil {
					return resp, nil
				}
				if err != nil {
					lastErr = err
				}
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("doh upstream disabled")
			}
			return nil, lastErr
		}
	}

	var dotUp resolverFunc
	if *dotAddr != "" {
		log.Printf("Upstream(3rd): DoT addr=%s serverName=%s insecure=%v", *dotAddr, *dotSNI, *dotInsec)
		dotUp = func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
			return resolveViaDoT(ctx, *dotAddr, *dotSNI, *dotInsec, req)
		}
	}

	upstream := chainResolvers(udpUp, dotUp, dohUp)

	// Prewarm must happen after upstream is ready so we can also record real IPs.
	if *prewarmDef {
		for _, d := range defaultPrewarmDomains {
			// Allocate fake regardless
			fake := cmap.RecordMany(d, nil)

			ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
			ips, err := resolveHostIP(ctx, upstream, d)
			cancel()

			if err != nil || len(ips) == 0 {
				log.Printf("Prewarm: %s -> fake=%s (real unresolved: %v)", dns.Fqdn(d), fake.String(), err)
				continue
			}

			// Record real IP for this domain (updates fake->real mapping)
			_ = cmap.RecordMany(d, ips)
			log.Printf("Prewarm: %s -> fake=%s real=%v", dns.Fqdn(d), fake.String(), ips)
		}
	}

	resolve := func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		return handleDNSQuery(ctx, req, upstream, cmap)
	}

	if *forwardListen != "" {
		go startForwarder(*forwardListen, cmap, rp)
	}

	startDNSServer(*listenAddr, resolve)
}
