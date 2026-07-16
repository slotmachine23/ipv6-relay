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

配置文件示例：

```json
{
    "global": {
        "log_level": 5
    },
    "interfaces": {
        "wan": { "ifname": "eth0", "master": true },
        "lan": { "ifname": "eth1" }
    }
}
```

`interfaces` 下每个条目的键名（示例里的 `wan`/`lan`）只是自己起的标识名，随便叫什么都行，程序只认里面的字段：

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `ifname` | 必选 | 系统上真实的网卡名（如 `eth0`） |
| `master` | 可选，默认 `false` | 标记这是上游（WAN）接口 |

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

- 进程本身不再强制要求以 UID 0 运行；`systemd` 单元默认以 `nobody` 用户运行，通过 `AmbientCapabilities`（`CAP_NET_RAW` + `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`）获得操作原始套接字、netlink 路由表和绑定 DHCPv6 547 端口所需的权限，不需要完整 root。
- 如果不通过 systemd、而是手动在命令行执行 `ipv6-relay`，仍然需要 root（或者自行用 `setcap` 给二进制加上同样三个 capability 后再以非 root 用户运行）。
- 已在测试路由器上验证：`nobody` 用户 + 上述三个 capability 可以正常完成 DHCPv6 中继（绑定 547 端口）、RA 中继（原始套接字）、NDP 中继（写 `/proc/sys/net/ipv6/conf/<if>/proxy_ndp` 需要 `CAP_NET_ADMIN`）。
- 注意：systemd 会对使用 `nobody`/`nogroup` 这种"通用"账户运行服务发出警告（`Special user nobody configured, this is not safe!`），因为它是共享账户，理论上多个服务共用同一 UID 存在互相干扰的风险。如果更看重隔离性，可以自建专用系统账户（如 `useradd -r -s /sbin/nologin ipv6-relay`）并把 `User=`/`Group=` 改成该账户，原理相同。
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
