#!/data/data/com.termux/files/usr/bin/python3
"""假摄像头桩 —— 用来验证 haku 的摄像头指纹能不能真命中。

两个模式：
  python3 cam_stub.py --http 18080        # 假 ONVIF 设备（HTTP），回 Manufacturer/Model
  python3 cam_stub.py --wsd               # 假 WS-Discovery 摄像头，监听 3702 并回 ProbeMatch

验证：
  ./haku -t 127.0.0.1 -p 18080 --no-mdns --no-ssdp
      -> 应出现「疑似摄像头」且证据含 ONVIF:18080 TestCam IPC-9000
  python3 cam_stub.py --wsd &
  ./haku -t 127.0.0.1 --no-mdns --no-ssdp
      -> 127.0.0.1 应带「WS-Discovery 摄像头」

回归（曾经把所有 WS-Discovery 响应都当摄像头）：
  python3 cam_stub.py --wsd-device &
  ./haku -t 127.0.0.1 --no-mdns --no-ssdp
      -> 必须**不**出现在「疑似摄像头」区，只在说明里写 WS-Discovery 设备
"""
import argparse
import http.server
import socket
import struct
import sys

SOAP = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    "<s:Body>"
    '<GetDeviceInformationResponse xmlns="http://www.onvif.org/ver10/device/wsdl">'
    "<Manufacturer>TestCam</Manufacturer><Model>IPC-9000</Model>"
    "</GetDeviceInformationResponse></s:Body></s:Envelope>"
).encode()

_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    "<e:Header>"
    "<w:MessageID>uuid:11111111-2222-3333-4444-555555555555</w:MessageID>"
    "<w:RelatesTo>uuid:5c0e1c2a-9d61-4a3b-8f7e-1b2c3d4e5f60</w:RelatesTo>"
    "<w:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</w:To>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</w:Action>"
    "</e:Header><e:Body><d:ProbeMatches><d:ProbeMatch>"
    "<w:EndpointReference><w:Address>urn:uuid:stub-camera</w:Address></w:EndpointReference>"
    "<d:Types>{types}</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/type/video_encoder</d:Scopes>"
    "<d:XAddrs>http://127.0.0.1:18080/onvif/device_service</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>"
)

PROBE_MATCH = _BODY.format(types="dn:NetworkVideoTransmitter").encode()
# 非 NVT：NAS / 路由器也会答 WS-Discovery，这种不能算摄像头
PROBE_MATCH_DEVICE = _BODY.format(types="wsdd:Device").encode()


def run_http(port: int) -> None:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
            self.send_header("Content-Length", str(len(SOAP)))
            self.end_headers()
            self.wfile.write(SOAP)

        do_POST = _reply
        do_GET = _reply

        def log_message(self, *_args) -> None:
            pass

    print(f"ONVIF 假设备: http://127.0.0.1:{port}/onvif/device_service", flush=True)
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()


def run_wsd(device: bool = False) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 3702))
    # 只 bind 收不到组播，必须显式加入 239.255.255.250，否则 Probe 根本进不来
    mreq = struct.pack("4sl", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    reply = PROBE_MATCH_DEVICE if device else PROBE_MATCH
    what = "设备（非摄像头）" if device else "摄像头"
    print(f"WS-Discovery 假{what}: 监听 3702", flush=True)
    while True:
        data, addr = s.recvfrom(8192)
        if b"Probe" not in data:
            continue
        s.sendto(reply, addr)
        print(f"已回 ProbeMatch -> {addr[0]}:{addr[1]}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", type=int, metavar="PORT", help="假 ONVIF 设备端口")
    ap.add_argument("--wsd", action="store_true", help="假 WS-Discovery 响应器")
    ap.add_argument(
        "--wsd-device",
        action="store_true",
        help="假 WS-Discovery 响应器，但 Types 不含 NetworkVideoTransmitter（应判成普通设备）",
    )
    args = ap.parse_args()
    if args.wsd_device:
        run_wsd(device=True)
        return 0
    if args.wsd:
        run_wsd()
        return 0
    if args.http:
        run_http(args.http)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
