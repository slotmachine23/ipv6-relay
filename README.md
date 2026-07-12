# ipv6-relay

轻量级 IPv6 中继守护进程，支持 DHCPv6 / RA / NDP 中继。

基于 [odhcpd](https://git.openwrt.org/?p=project/odhcpd.git) 精简而来，去掉了 OpenWrt 专用库（libubox / ubus / uci）依赖，可以在普通 Linux 发行版上直接编译运行。

## 功能

- DHCPv6 中继
- 路由通告中继（RA Relay）
- 邻居发现中继（NDP Relay）
- JSON 配置文件，不依赖 uci
- 自带 systemd 服务文件

## 编译

### 安装依赖

**Debian / Ubuntu：**
```bash
sudo apt-get install build-essential libnl-3-dev libnl-route-3-dev libjson-c-dev pkg-config
```

**Fedora / RHEL / CentOS：**
```bash
sudo dnf install gcc make libnl3-devel json-c-devel pkgconfig
```

**Arch Linux：**
```bash
sudo pacman -S base-devel libnl json-c pkgconf
```

**Alpine Linux：**
```bash
sudo apk add build-base libnl3-dev json-c-dev pkgconfig
```

### 编译并安装

```bash
git clone https://github.com/slotmachine23/ipv6-relay.git
cd ipv6-relay
make
sudo make install        # 默认安装到 /usr/sbin/ipv6-relay
```

其他常用命令：`make clean` 清理编译产物；`make PREFIX=/usr/local install` 自定义安装路径。

## 交叉编译

通过 `CROSS_COMPILE` 指定工具链前缀即可，例如：

```bash
make CROSS_COMPILE=aarch64-linux-gnu-
```

交叉编译不仅需要交叉编译器本身，还需要**目标架构**的 glibc、libnl、json-c 头文件和库文件（即一个完整的 sysroot）。如果只装了交叉编译器（例如 `gcc-aarch64-linux-gnu`），编译时通常会报 `time.h: No such file or directory`，或者在链接阶段找不到 `-lnl-3` / `-ljson-c`。

准备好 sysroot 后，通过 `SYSROOT` 变量指定：

```bash
make CROSS_COMPILE=aarch64-linux-gnu- SYSROOT=/usr/aarch64-linux-gnu/sys-root
```

### RHEL 10 上编译 aarch64（实测可行）

RHEL 10 的官方仓库（含 CodeReady Builder）不提供 aarch64 目标的 glibc/libnl/json-c 开发包，EPEL 里的 `gcc-aarch64-linux-gnu` 也只有编译器、没有对应的 sysroot。以下步骤用 CentOS Stream 10 的公开 aarch64 仓库把这些库单独装进一个空目录里作为 sysroot，实测编译通过：

```bash
# 1. 安装交叉编译器
sudo dnf install epel-release
sudo dnf install gcc-aarch64-linux-gnu

# 2. 准备一个临时仓库配置，指向 CentOS Stream 10 的 aarch64 仓库
mkdir -p /tmp/centos-aarch64-repo
cat > /tmp/centos-aarch64-repo/centos-stream-aarch64.repo << 'EOF'
[cs10-baseos-aarch64]
name=CentOS Stream 10 - BaseOS (aarch64)
baseurl=https://mirror.stream.centos.org/10-stream/BaseOS/aarch64/os/
enabled=1
gpgcheck=0

[cs10-appstream-aarch64]
name=CentOS Stream 10 - AppStream (aarch64)
baseurl=https://mirror.stream.centos.org/10-stream/AppStream/aarch64/os/
enabled=1
gpgcheck=0
EOF

# 3. 把 aarch64 版本的 glibc / libnl3 / json-c 装到 sysroot 目录
sudo dnf --installroot=/usr/aarch64-linux-gnu/sys-root \
     --setopt=reposdir=/tmp/centos-aarch64-repo \
     --forcearch=aarch64 \
     --releasever=10-stream \
     --nogpgcheck \
     install -y glibc glibc-devel kernel-headers libnl3-devel json-c-devel

# 4. 编译
make CROSS_COMPILE=aarch64-linux-gnu- SYSROOT=/usr/aarch64-linux-gnu/sys-root
```

> 这里用 CentOS Stream 而不是 RHEL 自身仓库，是因为普通 RHEL 订阅一般只授权本机架构（x86_64），没有 aarch64 版本的仓库可用；CentOS Stream 是 RHEL 的上游，二进制兼容性很好，只用来取头文件和库，不影响最终产物（产物本身是给 aarch64 目标机器用的，不会装回本机）。

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
        "wan": { "ifname": "eth0", "ra": "relay", "dhcpv6": "relay", "ndp": "relay", "master": true },
        "lan": { "ifname": "eth1", "ra": "relay", "dhcpv6": "relay", "ndp": "relay" }
    }
}
```

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

### 3. 用 systemd 管理（推荐）

`make install` 会自动安装 `ipv6-relay.service`，固定使用 `/etc/ipv6-relay/config.json` 作为配置文件。

```bash
sudo systemctl enable --now ipv6-relay.service
sudo systemctl status ipv6-relay.service
sudo journalctl -u ipv6-relay -f
```

### 注意事项

- 进程本身不再强制要求以 UID 0 运行；`systemd` 单元默认以 `nobody` 用户运行，通过 `AmbientCapabilities`（`CAP_NET_RAW` + `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`）获得操作原始套接字、netlink 路由表和绑定 DHCPv6 547 端口所需的权限，不需要完整 root。
- 如果不通过 systemd、而是手动在命令行执行 `ipv6-relay`，仍然需要 root（或者自行用 `setcap` 给二进制加上同样三个 capability 后再以非 root 用户运行）。
- 已在测试机上验证：`nobody` 用户 + 上述三个 capability 可以正常完成 DHCPv6 中继（绑定 547 端口）、RA 中继（原始套接字）、NDP 中继（写 `/proc/sys/net/ipv6/conf/<if>/proxy_ndp` 需要 `CAP_NET_ADMIN`）。
- 注意：systemd 会对使用 `nobody`/`nogroup` 这种"通用"账户运行服务发出警告（`Special user nobody configured, this is not safe!`），因为它是共享账户，理论上多个服务共用同一 UID 存在互相干扰的风险。如果更看重隔离性，可以自建专用系统账户（如 `useradd -r -s /sbin/nologin ipv6-relay`）并把 `User=`/`Group=` 改成该账户，原理相同。
- 确保内核已启用 IPv6。
- 检查防火墙是否放行 ICMPv6 / DHCPv6 流量。

## 项目结构

```
├── src/                  # 源码
├── config.json.example   # 配置示例
├── ipv6-relay.service    # systemd 服务文件
├── Makefile
└── LICENSE
```

## 许可证

[GPLv2](LICENSE)
