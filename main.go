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

	"github.com/miekg/dns"
)

const (
	defaultTTL        = 60 * time.Second
	defaultTimeout    = 6 * time.Second
	defaultMapTTL     = 24 * time.Hour
	defaultCleanupInt = 30 * time.Minute
)

// 命中这些域名后缀时，执行 fake-IP 劫持。
var defaultHijackSuffixes = []string{
	"cursor.sh",
	"cursor.com",
	"cursorapi.com",

	// Claude / Anthropic
	"claude.ai",
	"anthropic.com",
	"claudeusercontent.com",
}

var defaultPrewarmDomains = []string{
	"api2.cursor.sh",
	"api3.cursor.sh",
	"api4.cursor.sh",
	"repo42.cursor.sh",
	"downloads.cursor.com",
	"cursor.com",
	"marketplace.cursorapi.com",
	"agent.global.api5.cursor.sh",
	"us-only.gcpp.cursor.sh",

	// Claude / Anthropic
	"claude.ai",
	"api.anthropic.com",
	"console.anthropic.com",
	"docs.anthropic.com",
	"anthropic.com",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type resolverFunc func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)

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
	if strings.Contains(v, ",") {
		for _, p := range strings.Split(v, ",") {
			s.values = append(s.values, strings.TrimSpace(p))
		}
		return nil
	}
	s.values = append(s.values, v)
	return nil
}

func (s *stringListFlag) Values() []string {
	out := make([]string, 0, len(s.values))
	for _, v := range s.values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Fake-IP 映射表
// -----------------------------------------------------------------------------

type realInfo struct {
	ips       []net.IP
	domain    string
	updatedAt time.Time
}

type fakeIPMap struct {
	mu sync.RWMutex

	// fqdn(lower-case) -> fake IP
	domainToFake map[string]net.IP

	// fake IP string -> real target info
	fakeToReal map[string]*realInfo

	// 在 127.0.0.2 ~ 127.255.255.254 范围内分配
	// 用 uint32 逻辑分配，避免只局限于最后一个字节。
	next uint32

	ttl time.Duration
}

func newFakeIPMap(ttl time.Duration) *fakeIPMap {
	if ttl <= 0 {
		ttl = defaultMapTTL
	}
	return &fakeIPMap{
		domainToFake: make(map[string]net.IP),
		fakeToReal:   make(map[string]*realInfo),
		// 从 127.0.0.2 开始
		next: ipToUint32(net.IPv4(127, 0, 0, 2)),
		ttl:  ttl,
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func isUsableLoopback(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 127.0.0.0/8 都是 loopback；这里避开 .0 和 .1
	if ip4[0] != 127 {
		return false
	}
	if ip4[1] == 0 && ip4[2] == 0 && (ip4[3] == 0 || ip4[3] == 1) {
		return false
	}
	return true
}

func normalizeQname(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func trimTrailingDot(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func (m *fakeIPMap) allocFakeLocked(qname string) net.IP {
	if ip, ok := m.domainToFake[qname]; ok {
		return ip
	}

	start := m.next
	cur := start

	for {
		ip := uint32ToIP(cur)
		if isUsableLoopback(ip) {
			if _, used := m.fakeToReal[ip.String()]; !used {
				m.domainToFake[qname] = ip
				m.next = cur + 1
				// 回绕保护：保证仍在 127/8；不满足则回到 127.0.0.2
				if uint32ToIP(m.next).To4()[0] != 127 {
					m.next = ipToUint32(net.IPv4(127, 0, 0, 2))
				}
				return ip
			}
		}

		cur++
		if uint32ToIP(cur).To4()[0] != 127 {
			cur = ipToUint32(net.IPv4(127, 0, 0, 2))
		}
		if cur == start {
			// 理论上几乎不可能用满整个 127/8
			panic("fake IP pool exhausted")
		}
	}
}

func (m *fakeIPMap) RecordMany(qname string, realIPs []net.IP) net.IP {
	qname = normalizeQname(qname)

	m.mu.Lock()
	defer m.mu.Unlock()

	fake := m.allocFakeLocked(qname)

	now := time.Now()
	key := fake.String()
	info := m.fakeToReal[key]
	if info == nil {
		info = &realInfo{
			domain:    qname,
			updatedAt: now,
		}
	} else {
		info.domain = qname
		info.updatedAt = now
	}

	for _, rip := range realIPs {
		if rip == nil {
			continue
		}
		dup := false
		for _, e := range info.ips {
			if e.Equal(rip) {
				dup = true
				break
			}
		}
		if !dup {
			info.ips = append(info.ips, rip)
		}
	}

	m.fakeToReal[key] = info
	return fake
}

func (m *fakeIPMap) LookupRealByFake(fake net.IP) (net.IP, string, bool) {
	if fake == nil {
		return nil, "", false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	info, ok := m.fakeToReal[fake.String()]
	if !ok || len(info.ips) == 0 {
		return nil, "", false
	}

	info.updatedAt = time.Now()
	return info.ips[rand.Intn(len(info.ips))], info.domain, true
}

func (m *fakeIPMap) CleanupExpired() int {
	now := time.Now()
	expired := 0

	m.mu.Lock()
	defer m.mu.Unlock()

	validDomains := make(map[string]bool)

	for fake, info := range m.fakeToReal {
		if info == nil {
			delete(m.fakeToReal, fake)
			expired++
			continue
		}
		if now.Sub(info.updatedAt) > m.ttl {
			delete(m.fakeToReal, fake)
			expired++
			continue
		}
		validDomains[info.domain] = true
	}

	for domain, fake := range m.domainToFake {
		info, ok := m.fakeToReal[fake.String()]
		if !ok || info == nil || !validDomains[domain] {
			delete(m.domainToFake, domain)
			expired++
		}
	}

	return expired
}

func (m *fakeIPMap) StartCleanupLoop(interval time.Duration) {
	if interval <= 0 {
		interval = defaultCleanupInt
	}
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			n := m.CleanupExpired()
			if n > 0 {
				log.Printf("[map] cleanup removed=%d", n)
			}
		}
	}()
}

// -----------------------------------------------------------------------------
// 上游 DNS 解析器
// -----------------------------------------------------------------------------

type upstreamResolver struct {
	udpAddrs []string
	dotAddr  string
	dotSNI   string
	dotInsec bool
	dohURLs  []string

	httpClient *http.Client
	timeout    time.Duration
}

func newUpstreamResolver(udpAddrs []string, dotAddr, dotSNI string, dotInsec bool, dohURLs []string, timeout time.Duration) *upstreamResolver {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &upstreamResolver{
		udpAddrs: udpAddrs,
		dotAddr:  strings.TrimSpace(dotAddr),
		dotSNI:   strings.TrimSpace(dotSNI),
		dotInsec: dotInsec,
		dohURLs:  dohURLs,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

func (u *upstreamResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	// 1) UDP
	for _, addr := range u.udpAddrs {
		resp, err := resolveViaUDP(ctx, addr, req)
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	// 2) DoT
	if u.dotAddr != "" {
		resp, err := resolveViaDoT(ctx, u.dotAddr, u.dotSNI, u.dotInsec, req)
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	// 3) DoH
	for _, dohURL := range u.dohURLs {
		resp, err := resolveViaDoH(ctx, u.httpClient, dohURL, req)
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

func resolveViaUDP(ctx context.Context, addr string, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	dialer := &net.Dialer{Timeout: defaultTimeout}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udp dial %s: %w", addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("udp write: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("udp read: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("udp unpack: %w", err)
	}
	out.Id = req.Id
	return out, nil
}

func resolveViaDoT(ctx context.Context, addr, serverName string, insecure bool, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	dialer := &net.Dialer{Timeout: defaultTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("dot dial %s: %w", addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if len(wire) > 65535 {
		return nil, fmt.Errorf("dns message too large")
	}

	var lenBuf [2]byte
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
		return nil, fmt.Errorf("dot invalid length: %d", n)
	}

	respBuf := make([]byte, n)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("dot read msg: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("dot unpack: %w", err)
	}
	out.Id = req.Id
	return out, nil
}

func resolveViaDoH(ctx context.Context, c *http.Client, dohURL string, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns msg: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("new doh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := c.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh request %s: %w", dohURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("doh status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh read: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh unpack: %w", err)
	}
	out.Id = req.Id
	return out, nil
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

	var uniq []net.IP
	for _, ip := range out {
		if ip == nil {
			continue
		}
		dup := false
		for _, u := range uniq {
			if u.Equal(ip) {
				dup = true
				break
			}
		}
		if !dup {
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
	return nil, fmt.Errorf("no ip answer for %s", host)
}

// -----------------------------------------------------------------------------
// 域名命中与 synthetic reply
// -----------------------------------------------------------------------------

func shouldHijackQname(qname string, suffixes []string) bool {
	q := trimTrailingDot(qname)
	for _, s := range suffixes {
		s = trimTrailingDot(s)
		if q == s || strings.HasSuffix(q, "."+s) {
			return true
		}
	}
	return false
}

/*
buildSyntheticReply 的增强策略：
- A 查询：返回 fake A
- AAAA 查询：返回 NOERROR 但不给 AAAA（空 Answer）
- ANY 查询：返回 fake A
- 其他类型：返回空 Answer

这样比“AAAA 也返回 A”更符合协议预期。
*/
func buildSyntheticReply(req *dns.Msg, qname string, fake net.IP, ttl time.Duration) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if len(req.Question) == 0 {
		return m
	}

	q := req.Question[0]
	fqdn := dns.Fqdn(qname)
	ip4 := fake.To4()
	if ip4 == nil {
		return m
	}

	switch q.Qtype {
	case dns.TypeA, dns.TypeANY:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl.Seconds()),
			},
			A: ip4,
		})
	case dns.TypeAAAA:
		// 返回 NOERROR + 空回答
		// 表示“这个名字存在，但当前不提供 fake AAAA”
	default:
	}

	return m
}

// -----------------------------------------------------------------------------
// DNS Server
// -----------------------------------------------------------------------------

type dnsServer struct {
	listenAddr string
	resolve    resolverFunc
	timeout    time.Duration
}

func (s *dnsServer) Start() error {
	handler := dns.NewServeMux()
	handler.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()

		resp, err := s.resolve(ctx, r)
		if err != nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(resp)
	})

	udpServer := &dns.Server{
		Addr:    s.listenAddr,
		Net:     "udp",
		Handler: handler,
	}
	tcpServer := &dns.Server{
		Addr:    s.listenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	log.Printf("[dns] start listen=%s", s.listenAddr)

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("[dns] tcp server stopped: %v", err)
		}
	}()

	return udpServer.ListenAndServe()
}

func makeDNSHandler(upstream resolverFunc, fmap *fakeIPMap, suffixes []string) resolverFunc {
	return func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		if req == nil || len(req.Question) == 0 {
			return nil, fmt.Errorf("empty dns request")
		}

		q := req.Question[0]
		qname := normalizeQname(q.Name)

		if shouldHijackQname(qname, suffixes) &&
			(q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {

			realResp, err := upstream(ctx, req)
			if err != nil {
				return nil, err
			}

			realIPs := extractAllIPs(realResp)
			if len(realIPs) == 0 {
				// 上游无 A/AAAA 时，直接透传原响应
				return realResp, nil
			}

			fake := fmap.RecordMany(qname, realIPs)
			return buildSyntheticReply(req, q.Name, fake, defaultTTL), nil
		}

		return upstream(ctx, req)
	}
}

// -----------------------------------------------------------------------------
// Forwarder
// -----------------------------------------------------------------------------

type remoteProxyConfig struct {
	scheme     string
	addr       string
	serverName string
}

func parseRemoteProxy(raw string) (*remoteProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proxy: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy host empty")
	}

	host := u.Host
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

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func dialViaRemoteProxy(ctx context.Context, proxy *remoteProxyConfig, targetAddr string) (net.Conn, error) {
	if proxy == nil {
		return nil, fmt.Errorf("proxy is nil")
	}

	dialer := &net.Dialer{Timeout: defaultTimeout}

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

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(conn, req); err != nil {
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

	// 隧道已建立，取消 deadline，避免长连接被误杀
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

type forwarder struct {
	listenAddr string
	mapper     *fakeIPMap
	proxy      *remoteProxyConfig
	timeout    time.Duration
}

func (f *forwarder) Start() error {
	ln, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		return fmt.Errorf("forwarder listen %s: %w", f.listenAddr, err)
	}
	log.Printf("[fwd] start listen=%s", f.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[fwd] accept error: %v", err)
			continue
		}
		go f.handleConn(conn)
	}
}

func (f *forwarder) handleConn(src net.Conn) {
	defer src.Close()

	laddr, ok := src.LocalAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("[fwd] unexpected local addr type=%T", src.LocalAddr())
		return
	}

	realIP, domain, ok := f.mapper.LookupRealByFake(laddr.IP)
	if !ok {
		log.Printf("[fwd] no mapping for fake=%s client=%s", laddr.IP, src.RemoteAddr())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()

	var (
		dst    net.Conn
		target string
		err    error
	)

	if f.proxy != nil {
		target = net.JoinHostPort(trimTrailingDot(domain), fmt.Sprintf("%d", laddr.Port))
		log.Printf("[fwd] client=%s fake=%s target=%s via proxy=%s", src.RemoteAddr(), laddr.IP, target, f.proxy.addr)
		dst, err = dialViaRemoteProxy(ctx, f.proxy, target)
	} else {
		target = net.JoinHostPort(realIP.String(), fmt.Sprintf("%d", laddr.Port))
		log.Printf("[fwd] client=%s fake=%s target=%s domain=%s", src.RemoteAddr(), laddr.IP, target, domain)
		dialer := &net.Dialer{Timeout: f.timeout}
		dst, err = dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		log.Printf("[fwd] dial target=%s failed: %v", target, err)
		return
	}
	defer dst.Close()

	// 建连后清理 deadline，允许长连接
	_ = src.SetDeadline(time.Time{})
	_ = dst.SetDeadline(time.Time{})

	relayBidirectional(src, dst)
}

func relayBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()

	wg.Wait()
}

func closeWrite(c net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	var (
		listenAddr    = flag.String("listen", "127.0.0.1:53", "DNS listen address (udp/tcp)")
		forwardListen = flag.String("forward-listen", ":443", "TCP forward listen addr, empty to disable")
		remoteProxy   = flag.String("remote-proxy", "", "Optional remote HTTP/HTTPS proxy for CONNECT")

		dotAddr  = flag.String("dot-addr", "1.1.1.1:853", "DoT upstream address")
		dotSNI   = flag.String("dot-server-name", "cloudflare-dns.com", "DoT TLS SNI / certificate server name")
		dotInsec = flag.Bool("dot-insecure", false, "Skip TLS cert verification for DoT")

		prewarmDef = flag.Bool("defaults", false, "Prewarm default Cursor domains")
		mapTTL     = flag.Duration("map-ttl", defaultMapTTL, "Fake-IP mapping TTL")
	)

	var udpAddrs stringListFlag
	var dohURLs stringListFlag

	_ = udpAddrs.Set("114.114.114.114:53")
	_ = udpAddrs.Set("223.5.5.5:53")
	_ = dohURLs.Set("https://114.114.114.114/dns-query")
	_ = dohURLs.Set("https://223.5.5.5/dns-query")

	flag.Var(&udpAddrs, "udp-addr", "UDP DNS upstream address, repeatable")
	flag.Var(&dohURLs, "doh", "DoH URL, repeatable")

	flag.Parse()

	proxyCfg, err := parseRemoteProxy(*remoteProxy)
	if err != nil {
		log.Fatalf("invalid -remote-proxy: %v", err)
	}
	if proxyCfg != nil {
		log.Printf("[cfg] remote proxy enabled scheme=%s addr=%s", proxyCfg.scheme, proxyCfg.addr)
	}

	fmap := newFakeIPMap(*mapTTL)
	fmap.StartCleanupLoop(defaultCleanupInt)

	udpList := udpAddrs.Values()
	dohList := dohURLs.Values()

	log.Printf("[cfg] upstream udp=%v dot=%s doh=%v", udpList, *dotAddr, dohList)

	upstreamImpl := newUpstreamResolver(
		udpList,
		*dotAddr,
		*dotSNI,
		*dotInsec,
		dohList,
		defaultTimeout,
	)
	upstream := resolverFunc(upstreamImpl.Resolve)

	if *prewarmDef {
		for _, d := range defaultPrewarmDomains {
			fake := fmap.RecordMany(d, nil)
			ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
			ips, err := resolveHostIP(ctx, upstream, d)
			cancel()

			if err != nil || len(ips) == 0 {
				log.Printf("[prewarm] domain=%s fake=%s unresolved err=%v", dns.Fqdn(d), fake, err)
				continue
			}

			_ = fmap.RecordMany(d, ips)
			log.Printf("[prewarm] domain=%s fake=%s real=%v", dns.Fqdn(d), fake, ips)
		}
	}

	resolve := makeDNSHandler(upstream, fmap, defaultHijackSuffixes)

	if *forwardListen != "" {
		fwd := &forwarder{
			listenAddr: *forwardListen,
			mapper:     fmap,
			proxy:      proxyCfg,
			timeout:    defaultTimeout,
		}
		go func() {
			if err := fwd.Start(); err != nil {
				log.Fatalf("[fwd] fatal: %v", err)
			}
		}()
	}

	dnsSrv := &dnsServer{
		listenAddr: *listenAddr,
		resolve:    resolve,
		timeout:    defaultTimeout,
	}
	if err := dnsSrv.Start(); err != nil {
		log.Fatalf("[dns] fatal: %v", err)
	}
}package main

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
	"agent.global.api5.cursor.sh",
	"us-only.gcpp.cursor.sh",
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
