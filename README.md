# hakutaku（白澤）

> 局域网设备侦察：在 Android / Termux **免 root** 上跑，顺带识别 IP 摄像头。
> A single-file C LAN scout that works **without root** on Android/Termux.

```sh
haku                        # 扫本机网段
haku -w                     # 顺带勘查周边无线
haku -t 192.168.2.0/24
```

> ## ⚠️ 使用范围（先读这段）
>
> **只允许用于你本人拥有管理权、或已获得明确授权的网络。**
> 扫描他人网络在多数司法辖区是违法行为（中国：《网络安全法》《刑法》第 285 条）。
> 本项目不提供、也不接受任何用于未授权访问的功能或补丁。

---

## 它是什么

一台普通手机（无 root、无越狱）想看清自家局域网有什么设备，通常得先装 nmap 或一堆 Python 包，还常常因为拿不到原始套接字而失败。hakutaku 是一个**单文件 C 程序**，在这些限制下把能拿到的东西都拿到：

- ICMP 存活（调用系统的 `ping`，不依赖原始套接字）
- TCP 端口扫描（非阻塞 `connect()` + `poll()`，批量并发）
- 反向 DNS、mDNS、SSDP/UPnP
- HTTP(S) 横幅：`Server` 头与页面标题
- 无线侧勘查（Termux 走 `termux-wifi-scaninfo`，桌面 Linux 走 `nmcli` / `iw`）
- 摄像头指纹：WS-Discovery、RTSP、ONVIF
- Linux 上读 `/proc/net/arp` 拿 MAC，并用 IEEE OUI 库查厂商

输出按终端宽度自适应：宽屏是表格，手机竖屏（约 44 列）每台设备一块，不会折行。

## 它不是什么

这是判断"会不会被当成渗透工具"的关键，所以写死在这里：

| 不做 | 说明 |
|---|---|
| 口令爆破 / 字典攻击 | 没有任何登录尝试功能 |
| 漏洞利用 | 不发送畸形包，不针对任何 CVE |
| 认证绕过 / 提权 | 不涉及 |
| 抓包 / 中间人 / ARP 欺骗 | 没有监听模式，没有包注入 |
| Deauth / 干扰 | 不碰 802.11 管理帧 |
| 痕迹隐藏 / 反检测 | 没有伪装、没有随机化规避 |
| 互联网批量扫描 | 默认只扫本机所在子网，超过 4096 个地址退化为 /24 |
| 摄像头取流 / 登录 | 只读取设备**公开声明**的信息，不猜密码、不拉 RTSP 流 |

它发送的都是标准协议请求：ICMP echo、TCP connect、mDNS/SSDP 组播、ONVIF `GetDeviceInformation`——和浏览器、投屏客户端、打印驱动会发的包属于同一类。

## 构建

依赖：一个 C 编译器、`pthread`；https 指纹可选 `libssl`。

```sh
make                 # 自动检测 openssl，缺头文件会自动关闭 https 指纹
sudo make install    # 装到 /usr/local/bin/haku
```

Termux 上不用 sudo，`make && make install` 会自动装到 `$PREFIX/bin`。
Ubuntu 缺头文件时：`sudo apt install libssl-dev`。

## 用法

```
haku [选项]
  -t, --target <IP/CIDR/范围>  如 192.168.2.0/24、192.168.2.1-60，逗号分隔
  -p, --ports <列表>           如 1-1024 或 22,80,443（默认内置 32 个常用端口）
  -w, --wifi                   同时勘查周边无线（SSID/加密/信号/信道/厂商）
      --wifi-only              只勘查无线，不扫局域网
      --timeout <ms>           单个 TCP 连接超时（默认 700）
      --threads <n>            并发主机数（默认 64）
      --no-mdns                跳过 mDNS
      --no-ssdp                跳过 SSDP/UPnP
      --no-http                不抓 Web 标题 / Server 头
      --no-cam                 跳过摄像头指纹
      --json <路径>            导出 JSON
```

示例：

```sh
haku                                  # 自动识别网段（全段 254 台约 7 秒）
haku -t 192.168.2.1-60 -p 1-1024
haku -w --json ~/lan.json
```

手机竖屏输出：

```
本机 192.168.2.51
网段 192.168.2.0/24  在线 4/254  7.0s

192.168.2.110  MiWiFi-CR8808-srv 14.5ms
  80,443,631,9100
  打印机 · HTTP

192.168.2.1    XiaoQiang 3.8ms
  53,80,443
  Linux / IoT · nginx/1.20.1 / 「小米路由器
```

宽屏（≥96 列）自动切成表格；被管道/重定向时按 120 列输出，一行一台，方便 `grep`。

## 摄像头是怎么判的

命中任意一条，就会在表格下方单独列出「疑似摄像头」并附证据：

| 判据 | 说明 |
|---|---|
| WS-Discovery（`239.255.255.250:3702`） | ONVIF 摄像头会回 `ProbeMatch`，带 `NetworkVideoTransmitter` 与 XAddrs |
| RTSP `OPTIONS`（554 / 8554） | 回包里的 `Server:` 常直接写明型号 |
| ONVIF `GetDeviceInformation` | 能取到 Manufacturer/Model；要求认证本身也是特征 |
| 厂商关键字 | Dahua / Hikvision / Uniview / Hipcam / GoAhead-Webs … |
| 端口画像 | `37777`（大华 SDK）、`34567`（XMeye）、`554`、`8554` |

**误报与漏报都要知道**：

- 只有 SD 卡或 4G 回传的摄像头**不在局域网内**，网络扫描永远看不到。
- 公共网络若开启客户端隔离（AP isolation），你只能看到网关。
- 电视盒子、投屏器、打印机也可能命中"疑似"，这是启发式的固有代价——请把它当线索，不是结论。

## 两个平台的差别

| 能力 | Termux (Android) | Ubuntu / Linux |
|---|---|---|
| ICMP 存活、TCP 端口、反向 DNS | 有 | 有 |
| mDNS / SSDP / HTTP(S) 指纹 | 有 | 有 |
| **MAC 地址** | 拿不到（SELinux 挡 `/proc/net/arp`） | 读 `/proc/net/arp`，普通用户即可 |
| **厂商** | 仅无线 BSSID（需自备 OUI 库） | 自动读 `ieee-data/oui.txt` 或 `nmap-mac-prefixes` |
| 无线勘查 | `termux-wifi-scaninfo`（需 termux-api + 定位权限） | `nmcli` → `iw` |

Android 上为什么没有 MAC：SELinux 拒绝读取 `/proc/net/arp`，netlink 绑定与 `AF_PACKET` 也一并被拒。这不是缺实现，是平台限制——所以本工具不假装能 ARP 扫描。

### 在 Termux 上补厂商库（可选）

```sh
mkdir -p $PREFIX/share/ieee-data
# 从任意有 ieee-data 的机器抽精简表（约 3.6 万条 / 1.1MB）
ssh <host> "grep -F '(hex)' /usr/share/ieee-data/oui.txt \
  | sed -E 's/^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})[[:space:]]+\(hex\)[[:space:]]*/\1\2\3 /' \
  | gzip -9" | gunzip > $PREFIX/share/ieee-data/oui.txt
```

查找顺序：`$HAKU_OUI_FILE` → `$PREFIX/share/ieee-data/oui.txt` → `/usr/share/ieee-data/oui.txt` → `/usr/share/nmap/nmap-mac-prefixes` → `/usr/share/ieee-data/oui.csv`。

## 环境变量

| 变量 | 用途 |
|---|---|
| `HAKU_ARP_FILE` | 覆盖 ARP 表路径（测试用） |
| `HAKU_OUI_FILE` | 指定 OUI 库（`oui.txt` / `nmap-mac-prefixes` 格式都认） |
| `COLUMNS` | 覆盖终端宽度（排版用） |

## 测试

仓库带一个假设备桩，用来验证摄像头指纹真的会命中（只监听本机，不碰外网）：

```sh
python3 tests/cam_stub.py --http 18080 &
./haku -t 127.0.0.1 -p 18080 --no-mdns --no-ssdp
# 期望：疑似摄像头  ONVIF:18080 TestCam IPC-9000
```

## 已知限制

- 分段小范围端口扫描可能漏掉开放端口（有些设备对未开放端口丢包而非拒绝）；要全端口用 `-p 1-65535`，或用 `nmap -sT -Pn -p-`。
- 反查名来自路由器 DHCP，设备改名后不会自动更新。
- `nmcli` / `iw` 分支只在没有无线网卡的机器上验证过"缺失时优雅退让"，真无线网卡路径欢迎反馈。
- 只有 ICMP、其余全不应答的设备（物联网家电常见）无法识别，只能靠 MAC 定厂。

## 安全与合法使用

- 本工具**不收集、不上传**任何数据；没有遥测、没有联网回传。
- 扫描只针对命令行指定的网段，默认不跨子网。
- 请只在自有网络使用；在他人网络中扫描可能违法，后果由使用者承担。
- 发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue 贴出可复现的攻击链。

## 许可证

GPL-3.0-or-later，见 [LICENSE](LICENSE)。
