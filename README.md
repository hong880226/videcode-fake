# tools

一个用于 **Cursor 相关域名** 的 DNS 劫持 + fake-ip 映射 + TCP 转发的小工具：

- 对匹配的域名（`*.cursor.sh` / `*.cursor.com` / `*.cursorapi.com`）：
  - 先用上游解析得到 **real IP 列表** 并缓存
  - 为每个域名分配一个本地 **fake-ip（127.0.0.x）** 并在 DNS 查询中返回
  - 后续客户端访问该 fake-ip 的 `:443` 时，本地 forwarder 会将流量转发到缓存的 real IP（**随机挑选一个**）
- 其他域名：正常走上游解析并原样返回

## 上游解析优先级

上游解析按如下顺序依次尝试（失败才回退）：

1. **普通 UDP DNS**（`-udp-addr`）
2. **DoT** DNS-over-TLS（`-dot-addr`）
3. **DoH** DNS-over-HTTPS（`-doh`）

## 运行

### 直接运行

> 注意：监听 `:53` 和 `:443` 通常需要 root 权限，或给二进制授予绑定特权端口权限。

## Linux / Windows 系统设置（把系统 DNS 指向本工具）

本工具默认 DNS 监听在 `127.0.0.1:53`，因此你需要把系统 DNS 设置为 **127.0.0.1**，并确保本工具在后台持续运行。

### Linux（systemd-resolved / NetworkManager）

#### 1) 处理端口占用与权限

- **端口占用**：如果 `:53` 被系统 DNS 服务占用（常见于 `systemd-resolved`），需要先停用/调整它，或把本工具的 `-listen` 改到其它端口（但系统 DNS 通常只能用 53）。
- **端口权限**：监听 `:53/:443` 需要 root。建议用 `setcap` 给二进制授权：

```bash
go build -o tools .
sudo setcap 'cap_net_bind_service=+ep' ./tools
```

然后用普通用户启动：

```bash
./tools -defaults
```

#### 2) 设置系统 DNS 为 127.0.0.1

- **NetworkManager（常见桌面发行版）**：

```bash
nmcli dev show | grep -E 'GENERAL.DEVICE|IP4.DNS|IP6.DNS'
```

在 GUI（网络设置）里把 DNS 改为 `127.0.0.1`，或用 `nmcli` 对指定连接配置（不同发行版连接名不同）。

- **systemd-resolved**（快速验证当前 DNS）：

```bash
resolvectl status
```

改完后用下面命令验证：

```bash
dig @127.0.0.1 api2.cursor.sh +short
```

### Windows（10/11）

#### 1) 运行工具（管理员权限）

建议用管理员权限运行（否则绑定 `:53/:443` 可能失败）。

验证工具已启动后，再设置系统 DNS。

#### 2) 把网卡 DNS 设置为 127.0.0.1

- **GUI**：设置 → 网络和 Internet → 更改适配器选项 → 选中网卡 → 属性 → Internet 协议版本 4 (TCP/IPv4) → 使用下面的 DNS 服务器地址 → **首选 DNS：`127.0.0.1`**。

- **PowerShell（管理员）**（把 “以太网/无线” 名称换成你实际接口名）：

```powershell
Get-DnsClientServerAddress
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
ipconfig /flushdns
```

验证：

```powershell
nslookup api2.cursor.sh 127.0.0.1
```

#### （更简单）hosts 文件法：不改系统 DNS

如果你只关心少数 Cursor 域名，可以直接在 Windows 的 hosts 文件里把域名映射到本工具的 **fake-ip（127.0.0.x）**，这样不用修改网卡 DNS，也不用运行本地 DNS 服务器（避免端口 53 的权限/占用问题）。

1) 以管理员打开记事本，编辑：

`C:\Windows\System32\drivers\etc\hosts`

2) 添加映射（示例）：

> 说明：`-defaults` 预热时会按 `defaultPrewarmDomains` 的顺序分配 `127.0.0.2` 起的 fake-ip。你也可以以日志里打印的 `Prewarm: ... fake=...` 为准。

```text
127.0.0.2 api2.cursor.sh
127.0.0.3 api3.cursor.sh
127.0.0.4 api4.cursor.sh
127.0.0.5 repo42.cursor.sh
127.0.0.6 downloads.cursor.com
127.0.0.7 cursor.com
127.0.0.8 marketplace.cursorapi.com
```

3) 刷新 DNS 缓存：

```powershell
ipconfig /flushdns
```

4) 启动工具并预热 real IP（让 `fake-ip -> realIP[]` 缓存就绪）：

```powershell
go run . -defaults -listen 127.0.0.1:0
```

> 说明：`-listen 127.0.0.1:0` 会让 DNS 服务绑定到随机端口（基本等同于“不开本地 DNS 用途”），核心是让 `-forward-listen :443` 的转发器运行，并且 `-defaults` 预热 real IP。

## 常见排错

- **无法绑定 53/443**：检查是否有其它服务占用（Linux 常见 `systemd-resolved`），或是否缺少权限。
- **设置 127.0.0.1 后无法上网**：说明本工具没在运行/崩溃/未监听在 `127.0.0.1:53`，先恢复 DNS 再排查日志。

### 使用 DoT / DoH

- **DoT（推荐给需要纯 TLS 的场景）**

```bash
go run . -dot-addr 1.1.1.1:853 -dot-server-name cloudflare-dns.com
```

- **DoH**

```bash
go run . -doh https://1.1.1.1/dns-query
```

### 启用默认预热（fake-ip + real IP）

`-defaults` 会对内置域名列表做预热：分配 fake-ip，并立即通过上游解析 real IP 写入缓存。

```bash
go run . -defaults
```

内置域名默认包含（可在 `main.go` 的 `defaultPrewarmDomains` 中修改）：

- `api2.cursor.sh`
- `api3.cursor.sh`
- `api4.cursor.sh`
- `repo42.cursor.sh`
- `downloads.cursor.com`
- `cursor.com`
- `marketplace.cursorapi.com`

## TCP 转发（:443）

默认会开启 `-forward-listen :443` 的 forwarder（可置空禁用）。

```bash
go run . -forward-listen :443
```

### 通过远端代理转发（remote-proxy）

如果你想把 forwarder 的出站连接先发到一个远端 HTTP 代理（使用 **HTTP CONNECT** 建立隧道），可以设置：

- `-remote-proxy host:port`
- 或 `-remote-proxy http://host:port`
- 或 `-remote-proxy https://host:port`

示例：

```bash
go run . -remote-proxy 10.0.0.2:3128
```

## 参数一览

- **`-listen`**：本地 DNS 监听地址（udp/tcp），默认 `127.0.0.1:53`
- **`-udp-addr`**：UDP 上游 DNS 地址（第 1 优先级），默认 `1.1.1.1:53`（**可重复指定**，按顺序依次尝试；空字符串禁用）
- **`-dot-addr`**：DoT 上游地址（第 2 优先级），默认空（不启用）
- **`-dot-server-name`**：DoT 的 TLS SNI/证书名（仅 `-dot-addr` 生效）
- **`-dot-insecure`**：DoT 跳过证书校验（不推荐）
- **`-doh`**：DoH URL（第 3 优先级），默认 `https://1.1.1.1/dns-query`（**可重复指定**，按顺序依次尝试；空字符串禁用）
- **`-forward-listen`**：本地转发监听地址，默认 `:443`（空字符串禁用）
- **`-remote-proxy`**：可选远端 HTTP 代理（CONNECT），默认空（直连）
- **`-defaults`**：预热内置域名的 fake-ip + real IP，默认关闭

## 工作原理（简述）

1. DNS 查询命中 Cursor 域名：
   - 上游解析获取 A/AAAA 列表，缓存到 `fake-ip -> realIP[]`
   - 返回 `127.0.0.x` 的 A 记录（fake-ip）
2. 客户端对该 `127.0.0.x:443` 建连：
   - forwarder 根据本地目的地址（`LocalAddr()`）取到 fake-ip
   - 从缓存 realIP 列表中随机选一个，拨号到 `realIP:443`（或经 `-remote-proxy` CONNECT）
   - 双向 `io.Copy` 透传，不解析 TLS 内容

## 来源说明
1. 原始代码来自https://github.com/tiechui1994/cursor-fake

