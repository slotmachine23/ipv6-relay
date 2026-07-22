# ipv6-relay

轻量级 IPv6 中继守护进程，支持 DHCPv6 / RA / NDP 中继。

Go 实现，从原先基于 [odhcpd](https://git.openwrt.org/?p=project/odhcpd.git) 精简出来的 C
版本重写而来（C 版历史保留在 [`legacy-c`](../../tree/legacy-c) 分支），行为与部署方式保持一致：
同样的 JSON 配置格式、同样的命令行参数、同样的 systemd 部署模型（`AmbientCapabilities` 非
root 运行）。只是不再依赖 `libnl` / `json-c`，编译产物是一个静态链接的单文件二进制，跨平台
交叉编译非常简单。

## 功能

- DHCPv6 中继
- 路由通告中继（RA Relay）
- 邻居发现中继（NDP Relay）
- JSON 配置文件
- 自带 systemd 服务文件

## 编译

只需要 Go 工具链（1.22+），没有其他系统依赖：

```bash
git clone https://github.com/slotmachine23/ipv6-relay.git
cd ipv6-relay
go build -o ipv6-relay ./cmd/ipv6-relay
sudo install -m 755 ipv6-relay /usr/sbin/ipv6-relay
```

## 交叉编译

Go 自带交叉编译支持，例如给 arm64 路由器编译：

```bash
GOOS=linux GOARCH=arm64 go build -o ipv6-relay-arm64 ./cmd/ipv6-relay
```

产物是静态链接的二进制（`CGO_ENABLED=0` 是 Go 交叉编译时的默认值），可以直接拷贝到目标机
运行，不需要在目标机上安装任何运行库：

```bash
scp ipv6-relay-arm64 root@<router>:/usr/sbin/ipv6-relay
```

## 使用

### 1. 准备配置文件

```bash
sudo mkdir -p /etc/ipv6-relay
sudo cp config.json.example /etc/ipv6-relay/config.json
sudo editor /etc/ipv6-relay/config.json
```

配置文件本身不包含任何密钥/凭据，只有接口名和开关，所以给普通用户读权限没有安全风险：

```bash
sudo chmod 755 /etc/ipv6-relay
sudo chmod 644 /etc/ipv6-relay/config.json
```

配置文件示例：见 [`config.json.example`](config.json.example)（里面列出了每个可配置字段，没有隐藏参数）。

`interfaces` 下每个条目的键名（示例里的 `wan`/`lan`）只是自己起的标识名，随便叫什么都行，程序只认里面的字段：

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `ifname` | 必选 | 系统上真实的网卡名（如 `eth0`） |
| `master` | 可选，默认 `false` | 标记这是上游（WAN）接口 |
| `ndproxy_routing` | 可选，默认 `true` | 是否为这个接口上镜像的邻居地址安装 `/128` 主机路由（配合 proxy-NDP 一起生效，关掉后只装 proxy-NDP 代理表项、不装路由） |
| `ndp_from_link_local` | 可选，默认 `true` | 主动探测/中继报文（如邻居探测、路由器请求）发送时是否优先使用本接口的 link-local 地址作为源地址，而不是回退到默认的发送方式 |

`global` 下目前有以下字段：

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `log_level` | 可选，默认 4 | 日志级别 0-7（同 `-l` 命令行参数，配置文件优先级低于显式传入的 `-l`） |
| `notify_prefix_deprecation` | 可选，默认 `true` | 是否在检测到 WAN 口前缀被更新的前缀取代时，向 LAN 侧仍在使用旧前缀地址的邻居发送 lifetime=0 的终结通告（见下方说明） |
| `prefix_mismatch_packet_threshold` | 可选，默认 3 | 实时 snoop WAN 口收到的真实 RA 报文时，连续多少个报文携带同一个、与当前记录不同的 ULA/公网前缀，才判定前缀确实已经更换（防止上游把多个仍然有效的前缀分散在不同 RA 里发送时被误判） |
| `prefix_deprecation_interval_seconds` | 可选，默认 300 | 确认前缀被取代后，终结通告的重发间隔（秒），直到 LAN 侧不再有使用该前缀地址的邻居为止才停止 |

本项目会对每个 `master` 接口实时 snoop 收到的真实 RA 报文，解析其中的 PIO（Prefix Information
Option），只关心 ULA（`fc00::/7`）或公网可路由的前缀（不含 link-local、组播）。当连续
`prefix_mismatch_packet_threshold` 个 RA 都携带同一个、与当前记录不同的前缀时，才判定 WAN
前缀确实被替换了（例如上游重新编号/更换了前缀，但没有正确发送 `valid_lft=0`/`preferred_lft=0`
的撤回通告）——单个 RA 里出现一次不同的前缀不会立即触发，避免把上游偶尔把多个仍然有效的前缀
分散在不同 RA 里发送误判成前缀更换。接口刚启动收到的第一个真实 RA 只会静默记录当前前缀，不会
触发通告，避免把重启前就已存在的合法前缀误判为"过时"。一旦确认某个前缀被取代，就会向所有下游
（非 `master`）接口里仍有该前缀下地址的邻居，发送一份只带有该前缀 PIO（Valid/Preferred
Lifetime 均为 0）的合成 RA，之后每隔 `prefix_deprecation_interval_seconds` 重发一次，直到 LAN
侧的邻居表里再也找不到该前缀下的地址为止。

本项目只做 relay，不支持其他模式，所以**只要接口出现在配置里，就会同时中继 DHCPv6 / RA / NDP 三种服务**，不需要（也无法）单独开关；不想中继某个接口，直接把它从配置里删掉即可。`master` 用来标记哪一侧是上游：至少要有一个接口设为 `"master": true`，其余不带 `master` 的接口视为下游（LAN 侧）。

### 2. 运行

```bash
# 前台运行，方便调试
sudo ipv6-relay -c /etc/ipv6-relay/config.json -f -l 7

# 直接运行（生产环境推荐用 systemd，见下）
sudo ipv6-relay -c /etc/ipv6-relay/config.json
```

命令行选项：

| 选项 | 说明 |
|------|------|
| `-c <file>` | 必选，JSON 配置文件路径 |
| `-l <level>` | 日志级别 0-7，默认 4 |
| `-f` | 日志输出到 stderr，而不是 syslog |
| `-h` | 显示帮助 |

发送 `SIGHUP` 可以在不重启进程的情况下重新加载配置文件（`systemctl reload ipv6-relay`）。

### 3. 用 systemd 管理（推荐）

```bash
sudo cp ipv6-relay.service /usr/lib/systemd/system/ipv6-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-relay.service
sudo systemctl status ipv6-relay.service
sudo journalctl -u ipv6-relay -f
```

### 注意事项

- 进程本身不再强制要求以 UID 0 运行；`systemd` 单元通过 `DynamicUser=yes` 在启动时为它分配一个专属的临时系统 UID/GID（服务停止后回收），再通过 `AmbientCapabilities`（`CAP_NET_RAW` + `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`）获得操作原始套接字、netlink 路由表和绑定 DHCPv6 547 端口所需的权限，不需要完整 root。
- 如果不通过 systemd、而是手动在命令行执行 `ipv6-relay`，仍然需要 root（或者自行用 `setcap` 给二进制加上同样三个 capability 后再以非 root 用户运行）。
- 已在测试路由器上验证：`DynamicUser` 分配的临时用户 + 上述三个 capability 可以正常完成 DHCPv6 中继（绑定 547 端口）、RA 中继（原始套接字）、NDP 中继（写 `/proc/sys/net/ipv6/conf/<if>/proxy_ndp` 需要 `CAP_NET_ADMIN`）。
- 相比让服务以 `nobody` 这种所有服务共用的账户运行（systemd 会警告 `Special user nobody configured, this is not safe!`，因为多个服务共用同一 UID 存在互相干扰的风险），`DynamicUser` 为每个服务分配独占的临时 UID，隔离性更好，也不需要像 `useradd -r -s /sbin/nologin ipv6-relay` 那样手动创建专用系统账户。
- 确保内核已启用 IPv6。
- 检查防火墙是否放行 ICMPv6 / DHCPv6 流量。

## 项目结构

```
├── cmd/ipv6-relay/      # 主程序入口 (main.go, CLI 参数解析)
├── internal/relay/      # 核心实现：config/engine/log + router(RA)/dhcpv6/ndp 三个中继子系统
├── config.json.example  # 配置示例
├── ipv6-relay.service   # systemd 服务文件
├── go.mod / go.sum
└── LICENSE
```

C 语言版本的历史实现保留在 [`legacy-c`](../../tree/legacy-c) 分支，仅供参考，不再维护。

## 许可证

[GPLv2](LICENSE)
