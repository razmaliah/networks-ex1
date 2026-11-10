"""Builds small synthetic capture files for the tests."""

from __future__ import annotations

import struct

CLIENT_MAC, SERVER_MAC = bytes.fromhex("aabbccddeeff"), bytes.fromhex("112233445566")


def _ip(text: str) -> bytes:
    return bytes(int(x) for x in text.split("."))


def ethernet_ipv4(src: str, dst: str, proto: int, transport: bytes, to_server: bool = True) -> bytes:
    ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, proto, 0, _ip(src), _ip(dst))
    macs = SERVER_MAC + CLIENT_MAC if to_server else CLIENT_MAC + SERVER_MAC
    return macs + b"\x08\x00" + ip_header + transport


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(tid: int, name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def dns_response(tid: int, name: str, address: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + _ip(address)
    return struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0) + qname + struct.pack(">HH", 1, 1) + answer


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(sni_ext)) + sni_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def write_pcap(frames: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, data in frames:
        out += struct.pack("<IIII", int(ts), round((ts - int(ts)) * 1e6), len(data), len(data)) + data
    return out


def write_pcapng(frames: list[tuple[float, bytes]]) -> bytes:
    def block(block_type: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    tsresol_option = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # nanoseconds
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + tsresol_option)
    for ts, data in frames:
        units = round(ts * 1e9)
        out += block(6, struct.pack("<IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(data), len(data)) + data)
    return out


SYN, ACK, PSH_ACK, SYN_ACK, FIN_ACK = 0x02, 0x10, 0x18, 0x12, 0x11


def sample_frames() -> list[tuple[float, bytes]]:
    """DNS lookup, an HTTP GET split over 2 segments, a gzip response split over 2 segments,
    a chunked POST response on the same connection, a retransmission, and a TLS Client Hello."""
    import gzip
    import random

    c, s, t0 = "192.168.1.19", "93.184.216.34", 1_700_000_000.0
    html = b"<html>" + random.Random(1).randbytes(1500).hex().encode() + b"</html>"  # does not compress much
    gz = gzip.compress(html)
    resp1 = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n"
             b"Content-Length: " + str(len(gz)).encode() + b"\r\n\r\n" + gz)
    req1 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n"
    req2 = b"POST /form HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\n\r\nname=ab"
    resp2 = b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"

    split_req, split_resp = 30, 1000
    cs, ss = 1000, 5000  # initial sequence numbers
    f = []

    def add(dt, frame):
        f.append((t0 + dt, frame))

    add(0.000, ethernet_ipv4(c, "8.8.8.8", 17, udp(50000, 53, dns_query(0x1234, "example.com"))))                       # 1
    add(0.020, ethernet_ipv4("8.8.8.8", c, 17, udp(53, 50000, dns_response(0x1234, "example.com", s)), False))         # 2
    add(0.030, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs, 0, SYN)))                                                      # 3
    add(0.040, ethernet_ipv4(s, c, 6, tcp(80, 51000, ss, cs + 1, SYN_ACK), False))                                      # 4
    add(0.041, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs + 1, ss + 1, ACK)))                                             # 5
    add(0.050, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs + 1, ss + 1, ACK, req1[:split_req])))                           # 6
    add(0.051, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs + 1 + split_req, ss + 1, PSH_ACK, req1[split_req:])))           # 7
    add(0.150, ethernet_ipv4(s, c, 6, tcp(80, 51000, ss + 1, cs + 1 + len(req1), ACK, resp1[:split_resp]), False))     # 8
    add(0.151, ethernet_ipv4(s, c, 6, tcp(80, 51000, ss + 1, cs + 1 + len(req1), ACK, resp1[:split_resp]), False))     # 9 retransmission
    add(0.160, ethernet_ipv4(s, c, 6, tcp(80, 51000, ss + 1 + split_resp, cs + 1 + len(req1), PSH_ACK, resp1[split_resp:]), False))  # 10
    cs2, ss2 = cs + 1 + len(req1), ss + 1 + len(resp1)
    add(0.300, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs2, ss2, PSH_ACK, req2)))                                         # 11
    add(0.380, ethernet_ipv4(s, c, 6, tcp(80, 51000, ss2, cs2 + len(req2), PSH_ACK, resp2), False))                     # 12
    add(0.500, ethernet_ipv4(c, "151.101.1.69", 6, tcp(52000, 443, 7000, 1, PSH_ACK, client_hello("secure.example.org"))))  # 13
    add(0.600, ethernet_ipv4(c, s, 6, tcp(51000, 80, cs2 + len(req2), ss2 + len(resp2), FIN_ACK)))                      # 14
    return f


def ethernet_ipv6_udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    datagram = udp(sport, dport, payload)
    header = struct.pack(">IHBB", 6 << 28, len(datagram), 17, 64) + src + dst
    return CLIENT_MAC + SERVER_MAC + b"\x86\xdd" + header + datagram
