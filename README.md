# ipv6-relay

轻量级 IPv6 中继守护进程，支持 DHCPv6/RA/NDP 中继。

本项目基于 [odhcpd](https://git.openwrt.org/?p=project/odhcpd.git) 开发，移除了对 OpenWrt 特定库（libubox / ubus / uci）的依赖，可直接在标准 Linux 发行版上编译运行。

## 功能特性

- **DHCPv6 中继**：在有状态地址分配场景下中继 DHCPv6 报文
- **路由通告中继 (RA Relay)**：转发 IPv6 路由通告报文，帮助下游网络获取前缀信息
- **邻居发现中继 (NDP Relay)**：代理邻居发现协议报文，解决不同链路间的主机可达性问题
- **JSON 配置文件**：使用标准 JSON 格式进行配置，不依赖 uci
- **systemd 集成**：提供 systemd 服务模板，支持多实例运行

## 编译

### 依赖

编译前请确保系统已安装以下开发库：

| 依赖 | 说明 |
|------|------|
| `libnl-3.0` / `libnl-route-3.0` | Netlink 协议库，用于内核网络接口操作 |
| `json-c` | JSON 解析库 |
| `gcc` / `clang` | C 编译器 |
| `make` | 构建工具 |
| `pkg-config` | 库信息检索工具 |

#### 各发行版安装依赖命令

**Debian / Ubuntu:**
```bash
sudo apt-get install build-essential libnl-3-dev libnl-route-3-dev libjson-c-dev pkg-config
```

**Fedora / RHEL / CentOS / openSUSE:**
```bash
sudo dnf install gcc make libnl3-devel json-c-devel pkgconfig
# 或旧版系统：
sudo yum install gcc make libnl3-devel json-c-devel pkgconfig
```

**Arch Linux:**
```bash
sudo pacman -S base-devel libnl json-c pkgconf
```

**Alpine Linux:**
```bash
sudo apk add build-base libnl3-dev json-c-dev pkgconfig
```

### 编译命令

```bash
# 克隆源码
git clone https://github.com/slotmachine23/ipv6-relay.git
cd ipv6-relay

# 编译
make

# 清理编译产物
make clean

# 安装（默认安装到 /usr/sbin/）
sudo make install

# 指定安装前缀
sudo make PREFIX=/usr/local install
```

编译完成后，当前目录会生成 `ipv6-relay` 可执行文件。

## 交叉编译

本项目 Makefile 内置了交叉编译支持，通过 `CROSS_COMPILE` 变量指定交叉编译工具链前缀。

### 常用示例

**ARM (32-bit):**
```bash
make CROSS_COMPILE=arm-linux-gnueabi-
```

**ARM (64-bit, aarch64):**
```bash
make CROSS_COMPILE=aarch64-linux-gnu-
```

**MIPS:**
```bash
make CROSS_COMPILE=mips-linux-gnu-
```

**RISC-V:**
```bash
make CROSS_COMPILE=riscv64-linux-gnu-
```

**指定交叉编译的 sysroot（针对自定义根文件系统）：**
```bash
make CROSS_COMPILE=arm-linux-gnueabihf- \
     CFLAGS="--sysroot=/path/to/sysroot" \
     LDFLAGS="--sysroot=/path/to/sysroot"
```

**安装到目标文件系统目录：**
```bash
make CROSS_COMPILE=aarch64-linux-gnu-
make CROSS_COMPILE=aarch64-linux-gnu- \
     DESTDIR=/path/to/target-rootfs \
     install
```

### 交叉编译环境准备

使用 [crosstool-NG](https://crosstool-ng.github.io/) 或发行版自带的交叉编译器。例如 Ubuntu 安装 ARM 交叉编译器：

```bash
sudo apt-get install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu
```

## 使用

### 配置文件

参考 `ipv6-relay.json.example` 创建配置文件：

```bash
sudo mkdir -p /etc/ipv6-relay
sudo cp ipv6-relay.json.example /etc/ipv6-relay/default.json
sudo editor /etc/ipv6-relay/default.json
```

配置文件采用 JSON 格式，示例结构：

```json
{
    "interfaces": [
        {
            "name": "wan",
            "role": "master",
            "ipv6": true
        },
        {
            "name": "lan",
            "role": "slave",
            "ipv6": true
        }
    ]
}
```

### 运行

**前台运行（调试时使用）：**
```bash
sudo ./ipv6-relay -c /etc/ipv6-relay/default.json -f -l 7
```

**后台运行（系统服务）：**
```bash
sudo ./ipv6-relay -c /etc/ipv6-relay/default.json
```

### 命令行选项

| 选项 | 说明 |
|------|------|
| `-c <file>` | **必选**，指定 JSON 配置文件路径 |
| `-l <level>` | 设置日志级别，0-7（默认 4，WARNING） |
| `-f` | 日志输出到 stderr，而不是 syslog |
| `-h` | 显示帮助信息并退出 |

日志级别对照：
- 0 = LOG_EMERG
- 1 = LOG_ALERT
- 2 = LOG_CRIT
- 3 = LOG_ERR
- 4 = LOG_WARNING
- 5 = LOG_NOTICE
- 6 = LOG_INFO
- 7 = LOG_DEBUG

### 使用 systemd 服务

安装时会自动将 `ipv6-relay@.service` 安装到 systemd 服务目录。

**启用并启动实例（以 `default` 配置为例）：**
```bash
sudo systemctl enable ipv6-relay@default.service
sudo systemctl start ipv6-relay@default.service
```

**查看状态：**
```bash
sudo systemctl status ipv6-relay@default.service
```

**查看日志：**
```bash
sudo journalctl -u ipv6-relay@default.service -f
```

systemd 服务实例名对应配置文件名，即 `ipv6-relay@<实例名>.service` 会加载 `/etc/ipv6-relay/<实例名>.json`。

### 注意事项

1. **必须以 root 权限运行**：程序需要创建原始套接字、操作网络接口和修改 IPv6 路由表。
2. 确保系统内核已启用 IPv6 支持。
3. 配置接口时，注意防火墙规则是否允许相应的 ICMPv6 / DHCPv6 流量。

## 项目结构

```
├── src/
│   ├── ipv6_relay.c    # 主程序入口
│   ├── ipv6_relay.h    # 公共头文件
│   ├── config.c        # JSON 配置解析
│   ├── dhcpv6.c/h      # DHCPv6 中继
│   ├── ndp.c           # 邻居发现中继
│   ├── router.c        # 路由通告中继
│   ├── netlink.c       # Netlink 接口操作
│   └── compat.c/h      # 兼容性封装
├── ipv6-relay.json.example   # 配置示例
├── ipv6-relay@.service       # systemd 服务模板
├── Makefile            # 构建脚本
├── LICENSE             # GPLv2 许可证
└── COPYING             # 版权声明
```

## 许可证

本项目基于 [GPLv2](LICENSE) 许可证开源。