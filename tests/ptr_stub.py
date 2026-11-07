#!/data/data/com.termux/files/usr/bin/python3
"""假网关 DNS —— 验证 haku 的 PTR 命名与「只回 IP 的网关」判断。

  python3 ptr_stub.py --port 5354 --name JEF-AN00
      -> 对任何 PTR 查询都回 JEF-AN00（模拟会答租约名的 dnsmasq）
  python3 ptr_stub.py --port 5354 --map 127.0.0.1=Pixel-7
      -> 按地址给名字
  python3 ptr_stub.py --port 5354 --dumb
      -> 复刻中国电信智能网关：PTR 回 IP 本身，等于没名字

用法（haku 侧用 HAKU_PTR_SERVER 指过来，53 端口不用 root 绑不了）：

  python3 tests/ptr_stub.py --port 5354 --name JEF-AN00 &
  HAKU_PTR_SERVER=127.0.0.1:5354 ./haku -t 127.0.0.1 -p 22 \
      --no-mdns --no-ssdp --no-nbns --no-cam
      -> 名称列应为 JEF-AN00，且**不**出现「PTR 只回 IP」的注

  python3 tests/ptr_stub.py --port 5354 --dumb &
  HAKU_PTR_SERVER=127.0.0.1:5354 ./haku -t 127.0.0.1 -p 22 \
      --no-mdns --no-ssdp --no-nbns --no-cam
      -> 名称列应为 "-"，并打出一行「网关 ... 的 PTR 只把 IP 原样回你」
"""
import argparse
import socket
import struct
import sys


def read_name(buf, off):
    parts = []
    while off < len(buf):
        n = buf[off]
        if n == 0:
            return ".".join(parts), off + 1
        if n & 0xC0 == 0xC0:
            return ".".join(parts), off + 2
        parts.append(buf[off + 1:off + 1 + n].decode("latin-1"))
        off += 1 + n
    return ".".join(parts), off


def enc(name):
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part)]) + part.encode("latin-1")
    return out + b"\x00"


def arpa_to_ip(name):
    labels = name.split(".")
    if [x.lower() for x in labels[-2:]] != ["in-addr", "arpa"] or len(labels) < 6:
        return None
    try:
        return ".".join(reversed(labels[:4]))
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--name", help="对任何地址都回这个名字")
    ap.add_argument("--map", action="append", default=[], metavar="IP=NAME")
    ap.add_argument("--dumb", action="store_true", help="回 IP 本身（复刻只会原样回的网关）")
    args = ap.parse_args()

    mapping = {}
    for item in args.map:
        ip, _, name = item.partition("=")
        if ip and name:
            mapping[ip] = name
    if not args.name and not mapping and not args.dumb:
        ap.error("要么 --name，要么 --map，要么 --dumb")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", args.port))
    print(f"假网关 DNS: 127.0.0.1:{args.port}（{'只回 IP' if args.dumb else '回名字'}）",
          flush=True)
    while True:
        data, peer = s.recvfrom(2048)
        if len(data) < 16:
            continue
        qname, off = read_name(data, 12)
        if off + 4 > len(data):
            continue
        qtype, _qclass = struct.unpack(">HH", data[off:off + 4])
        if qtype != 12:
            continue
        qend = off + 4
        ip = arpa_to_ip(qname)
        if args.dumb:
            answer = ip or qname
        else:
            answer = mapping.get(ip) or args.name
        rid = struct.unpack(">H", data[0:2])[0]
        if not answer:
            header = struct.pack(">HHHHHH", rid, 0x8183, 1, 0, 0, 0)  # NXDOMAIN
            s.sendto(header + data[12:qend], peer)
            continue
        body = enc(answer)
        header = struct.pack(">HHHHHH", rid, 0x8180, 1, 1, 0, 0)
        rr = enc(qname) + struct.pack(">HHIH", 12, 1, 30, len(body)) + body
        s.sendto(header + data[12:qend] + rr, peer)
        print(f"  PTR {ip or qname} -> {answer}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
