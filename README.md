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
- TCP 端口扫描（非阻塞 `connect()` + `poll()`，批量并发）；**回 RST 也算证据**，能发现那种挡了 ICMP 却在拒绝连接的设备
- 反向 DNS、mDNS、SSDP/UPnP、NetBIOS 名称（NBSTAT）
- HTTP(S) 横幅：`Server` 头与页面标题
- 无线侧勘查（Termux 走 `termux-wifi-scaninfo`，桌面 Linux 走 `nmcli` / `iw`）
- 摄像头指纹：WS-Discovery、RTSP、ONVIF
- Linux 上读 `/proc/net/arp` 拿 MAC，并用 IEEE OUI 库查厂商

判定不是「命中第一条规则就定论」，而是**收集证据再下结论**：每台主机记录它回答过哪些层（ICMP / RST / 开放端口 / mDNS / SSDP / WS-D / NetBIOS / ARP），只有 ICMP 的会被明确标成弱证据，回包特征与网关一致的会标成「疑似网关代答」。理由见[判定模型](#判定模型证据而不是单条猜)。

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
      --timeout <ms>           有 ICMP 应答的主机：单端口连接超时（默认 700）
      --live-timeout <ms>      无 ICMP 应答的主机：发现阶段端口超时（默认 300）
      --threads <n>            并发主机数（默认 64）
      --no-mdns                跳过 mDNS
      --no-ssdp                跳过 SSDP/UPnP
      --no-nbns                跳过 NetBIOS 名称查询
      --no-http                不抓 Web 标题 / Server 头
      --no-cam                 跳过摄像头指纹
      --json <路径>            导出 JSON
```

示例：

```sh
haku                                  # 自动识别网段（全段 254 台约 7 秒）
haku -t 192.168.2.1-60 -p 1-1024
haku -t 10.0.0.0/22 --live-timeout 600   # 大网段 / 慢网络：放宽发现阶段超时
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

宽屏（≥100 列）自动切成表格；被管道/重定向时按 120 列输出，一行一台，方便 `grep`。

## 判定模型：证据，而不是单条猜

不同网络差别很大：家庭光猫可能开 ARP 代理，公司网络整段丢 ICMP，访客网络可能有客户端隔离，机顶盒与 AP 的 TTL 常是 255 而 Linux 是 64。**任何单条信号都不足以判断一台设备是否存在、是什么**，所以这里按层记证据：

| 证据 | 强度 | 说明 |
|---|---|---|
| 端口接受连接 | 硬 | 真的有人在监听 |
| 端口回 RST | 硬 | 真的 TCP 栈在——挡掉 ICMP 的网络也能被发现 |
| mDNS / SSDP / WS-D / NetBIOS 应答 | 硬 | 应用层自报，顺带给出设备名 |
| ARP 表里的独立 MAC（仅 Linux） | 硬 | 二层真实存在过 |
| 仅 ICMP echo | 弱 | **代理 ARP 的网关可以替任何空 IP 回包** |

于是输出里会出现这些标记，而不是把它们混成一条「在线」：

- `仅 ICMP` —— 只回了 ping，没端口、没服务发现。存在性弱，可能只是网关代答。
- `⚠ 疑似网关代答` —— 回包的 TTL 与延迟跟网关几乎一致，且成批出现（≥5 台、占纯 ICMP 主机的 3/4 以上）。**拿不到网关基线时这个判断完全不做**，宁可不标也不误标。
- `端口拒绝(RST)` —— 设备在，但 ICMP 被挡、端口全关。这类主机以前发现不了。
- `ICMP 不回` —— 全程没回 ping，靠端口或服务发现才看见。
- 不再用 TTL 猜类型：实测同一网段里 TTL 255 的既有 AP/机顶盒也有真机，猜出来的「网络设备」只是噪声；类型说不准就留空。

`--json` 里对应 `evidence: [...]`（`icmp`/`rst`/`tcp`/`mdns`/`ssdp`/`wsd`/`nbstat`/`arp`/`http`）与 `suspect`（`none`/`icmp_only`/`gateway_proxy`），方便自己再过滤。

## 摄像头是怎么判的

**只有拿到应用层证据才算**，命中后进入表格下方单独的「疑似摄像头」区：

| 判据 | 说明 |
|---|---|
| WS-Discovery 的 `NetworkVideoTransmitter` | ONVIF 摄像头会回 `ProbeMatch` 并声明该类型；**没声明的一律当普通设备**（NAS、路由器、电视也会答 WS-D） |
| RTSP `OPTIONS`（554 / 8554） | 回包里的 `Server:` 常直接写明型号 |
| ONVIF `GetDeviceInformation` | 能取到 Manufacturer/Model；要求认证本身也是特征 |
| 端口画像 | `37777`（大华 SDK）、`34567`（XMeye）、`554`、`8554` |
| 厂商关键字 | Dahua / Hikvision / Uniview / Hipcam / GoAhead-Webs …；**主机已开 631 / 9100 / 445（打印机、NAS）时该条不生效**，页面里带 camera 字样不算证据 |

Web / ONVIF 探测按**实际开放的端口**逐个试（跳过 21/22/23/25/53/110/139/143/445/515/631/993/995/1883/3306/3389/5900/62078），最多试 3 个 —— 摄像头挂在 8000、8081、9000 甚至随机高位端口都很常见，写死端口表会漏。

**误报与漏报都要知道**：

- 只有 SD 卡或 4G 回传的摄像头**不在局域网内**，网络扫描永远看不到。
- 公共网络若开启客户端隔离（AP isolation），你只能看到网关。
- 电视盒子、投屏器也可能命中「疑似」，这是启发式的固有代价——把它当线索，不是结论。

## 两个平台的差别

| 能力 | Termux (Android) | Ubuntu / Linux |
|---|---|---|
| ICMP 存活、TCP 端口、反向 DNS | 有 | 有 |
| 端口 RST 探测（挡 ICMP 也能发现） | 有 | 有 |
| mDNS / SSDP / WS-D / NetBIOS | 有 | 有 |
| HTTP(S) 指纹 | 有 | 有 |
| **MAC 地址** | 拿不到（SELinux 挡 `/proc/net/arp`） | 读 `/proc/net/arp`，普通用户即可 |
| **厂商** | 仅无线 BSSID（需自备 OUI 库） | 自动读 `ieee-data/oui.txt` 或 `nmap-mac-prefixes` |
| **网关 MAC 比对**（代答铁证） | 不可用（无 ARP 表） | 可用 |
| 无线勘查 | `termux-wifi-scaninfo`（需 termux-api + 定位权限） | `nmcli` → `iw` |

Android 上为什么没有 MAC：SELinux 拒绝读取 `/proc/net/arp`，netlink 绑定与 `AF_PACKET` 也一并被拒。这不是缺实现，是平台限制——所以本工具不假装能 ARP 扫描；代答判断在手机上也只靠「TTL + 延迟与网关同源」这条间接证据，并且拿不到网关基线时直接不做。

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

仓库带一个假设备桩，用来验证摄像头指纹真的会命中（只监听本机，不碰外网）。三种模式都是回归用例：

```sh
# 1) ONVIF：应出现「疑似摄像头」且证据含 ONVIF:18080
python3 tests/cam_stub.py --http 18080 &
./haku -t 127.0.0.1 -p 18080 --no-mdns --no-ssdp --no-nbns

# 2) WS-Discovery 的摄像头：说明里应写「WS-Discovery 摄像头」
python3 tests/cam_stub.py --wsd &
./haku -t 127.0.0.1,$(ifconfig 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1) \
       -p 22 --no-mdns --no-ssdp --no-nbns

# 3) WS-Discovery 的普通设备：**不许**进摄像头区，只写「WS-Discovery 设备」
python3 tests/cam_stub.py --wsd-device &
./haku -t 127.0.0.1,$(ifconfig 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1) \
       -p 22 --no-mdns --no-ssdp --no-nbns
```

第 2、3 条要把**本机 LAN IP 一起列进目标**：桩跑在同一台机器上，回包的源地址是本机 LAN IP，不在目标列表里就会被丢弃（扫描整段时不存在这个问题）。

## 已知限制

- **没有哪种单条信号能通吃所有网络**。这里能说的是：不回 ICMP 的会被端口探测补上，回 ICMP 但什么都没有的会被标成弱证据，而不是直接算作设备。
- **大范围**：自动模式超过 4096 个地址时退化为 /24；要扫更大范围请显式 `-t 10.0.0.0/22`，并把 `--live-timeout` 放宽（每个无 ICMP 的主机都要等一轮）。
- **发现阶段的端口范围**：无 ICMP 应答的主机只扫前 384 个端口（`-p 1-65535` 时），有 ICMP 应答的才扫全表 —— 否则一次扫描会把时间拖到不可用。要继续挖某台机器，用 `-t <ip> -p 1-65535`。
- **代理 ARP 的判断是间接的**：手机上只能比对 TTL 与延迟是否与网关同源，且必须 ≥5 台成批出现；Linux 上能用 MAC 与网关相同这条铁证。网关不是 `x.x.x.1` 的网络里，本工具拿不到基线，于是完全不做这个判断。
- **只合并目标范围内的主机**：mDNS/SSDP 应答若来自未扫描的地址，会被丢弃（整段扫描时无此问题）。
- 分段小范围端口扫描可能漏掉开放端口（有些设备对未开放端口丢包而非拒绝）；要全端口用 `-p 1-65535`，或用 `nmap -sT -Pn -p-`。
- 反查名与 NetBIOS 名可能过期（设备改名后路由器/缓存要过一阵才更新）。
- 客户端隔离（AP isolation）下看不到同级设备，这由网络策略决定，工具无解。
- `nmcli` / `iw` 分支只在没有无线网卡的机器上验证过"缺失时优雅退让"，真无线网卡路径欢迎反馈。

## 安全与合法使用

- 本工具**不收集、不上传**任何数据；没有遥测、没有联网回传。
- 扫描只针对命令行指定的网段，默认不跨子网。
- 请只在自有网络使用；在他人网络中扫描可能违法，后果由使用者承担。
- 发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue 贴出可复现的攻击链。

## 许可证

GPL-3.0-or-later，见 [LICENSE](LICENSE)。
