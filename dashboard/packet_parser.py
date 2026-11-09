"""Decodes raw frames layer by layer: link (Ethernet etc.), network (IPv4/IPv6/ARP) and transport (TCP/UDP/ICMP)."""

from __future__ import annotations

import ipaddress
import struct

from app_protocols import is_tls_record, parse_client_hello_sni, parse_dns, tls_handshake_name
from models import Packet
from pcap_reader import RawFrame

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = (0x8100, 0x88A8)

TCP_FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]

UDP_PORT_PROTOCOLS = {
    53: "DNS", 5353: "MDNS", 5355: "LLMNR", 137: "NBNS", 138: "BROWSER", 67: "DHCP", 68: "DHCP",
    546: "DHCPv6", 547: "DHCPv6", 123: "NTP", 1900: "SSDP", 3702: "WS-Discovery", 161: "SNMP",
    443: "QUIC", 3478: "STUN", 500: "ISAKMP", 4500: "IPsec", 69: "TFTP", 514: "Syslog",
}
DNS_PORTS = (53, 5353, 5355)


def decode_frames(frames: list[RawFrame]) -> list[Packet]:
    return [decode_frame(number, frame) for number, frame in enumerate(frames, start=1)]


def decode_frame(number: int, frame: RawFrame) -> Packet:
    packet = Packet(number=number, timestamp=frame.timestamp, length=frame.orig_len)
    try:
        ethertype, network_data = _decode_link(frame, packet)
        if ethertype is not None:
            _decode_network(ethertype, network_data, packet)
    except (struct.error, IndexError, ValueError):
        packet.malformed = True
        packet.info = packet.info or "Malformed packet"
    return packet


# ---------- link layer ----------

def _decode_link(frame: RawFrame, packet: Packet) -> tuple[int | None, bytes]:
    data, link = frame.data, frame.link_type
    if link == LINKTYPE_ETHERNET:
        packet.dst_mac, packet.src_mac = _mac(data[0:6]), _mac(data[6:12])
        ethertype, offset = struct.unpack_from(">H", data, 12)[0], 14
        while ethertype in VLAN_ETHERTYPES:
            ethertype, offset = struct.unpack_from(">H", data, offset + 2)[0], offset + 4
        if ethertype <= 1500:  # IEEE 802.3 length field -> LLC frame (e.g. STP)
            packet.protocol, packet.info = "LLC", "IEEE 802.3 frame"
            return None, b""
        return ethertype, data[offset:]
    if link in (LINKTYPE_NULL, LINKTYPE_LOOP):  # loopback captures (e.g. Npcap Loopback Adapter)
        family = struct.unpack_from("<I" if link == LINKTYPE_NULL else ">I", data, 0)[0]
        if family > 0xFFFF:  # written in the other byte order
            family = struct.unpack_from(">I", data, 0)[0]
        return (ETHERTYPE_IPV4 if family == 2 else ETHERTYPE_IPV6), data[4:]
    if link in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return (ETHERTYPE_IPV4 if data[0] >> 4 == 4 else ETHERTYPE_IPV6), data
    if link == LINKTYPE_LINUX_SLL:
        return struct.unpack_from(">H", data, 14)[0], data[16:]
    if link == LINKTYPE_LINUX_SLL2:
        return struct.unpack_from(">H", data, 0)[0], data[20:]
    packet.protocol, packet.info = "Unknown", f"Unsupported link type {link}"
    return None, b""


# ---------- network layer ----------

def _decode_network(ethertype: int, data: bytes, packet: Packet) -> None:
    if ethertype == ETHERTYPE_ARP:
        _decode_arp(data, packet)
    elif ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(data, packet)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(data, packet)
    else:
        packet.protocol, packet.info = f"0x{ethertype:04x}", f"Ethertype 0x{ethertype:04x}"


def _decode_arp(data: bytes, packet: Packet) -> None:
    opcode = struct.unpack_from(">H", data, 6)[0]
    sender_mac, sender_ip, target_ip = _mac(data[8:14]), _ipv4(data[14:18]), _ipv4(data[24:28])
    packet.protocol = "ARP"
    if opcode == 1:
        packet.info = f"Who has {target_ip}? Tell {sender_ip}"
    else:
        packet.info = f"{sender_ip} is at {sender_mac}"


def _decode_ipv4(data: bytes, packet: Packet) -> None:
    header_len = (data[0] & 0x0F) * 4
    total_len, frag_field = struct.unpack_from(">H", data, 2)[0], struct.unpack_from(">H", data, 6)[0]
    packet.ip_version, packet.ttl, proto = 4, data[8], data[9]
    packet.src_ip, packet.dst_ip = _ipv4(data[12:16]), _ipv4(data[16:20])
    end = total_len if 0 < total_len <= len(data) else len(data)  # total_len is 0 with TCP offload
    packet.protocol = "IPv4"
    if frag_field & 0x1FFF:  # not the first fragment: no transport header here
        packet.info = "Fragmented IP packet"
        return
    _decode_transport(proto, data[header_len:end], packet)


def _decode_ipv6(data: bytes, packet: Packet) -> None:
    payload_len, next_header, packet.ttl = struct.unpack_from(">HBB", data, 4)
    packet.ip_version = 6
    packet.src_ip, packet.dst_ip = _ipv6(data[8:24]), _ipv6(data[24:40])
    payload = data[40:40 + payload_len] if payload_len else data[40:]
    packet.protocol = "IPv6"
    while next_header in (0, 43, 44, 60):  # extension headers
        if next_header == 44 and struct.unpack_from(">H", payload, 2)[0] & 0xFFF8:
            packet.info = "Fragmented IPv6 packet"
            return
        ext_len = 8 if next_header == 44 else (payload[1] + 1) * 8
        next_header, payload = payload[0], payload[ext_len:]
    _decode_transport(next_header, payload, packet)


# ---------- transport layer ----------

def _decode_transport(proto: int, data: bytes, packet: Packet) -> None:
    if proto == 6:
        _decode_tcp(data, packet)
    elif proto == 17:
        _decode_udp(data, packet)
    elif proto in (1, 58):
        icmp_type, code = data[0], data[1]
        packet.transport = packet.protocol = "ICMP" if proto == 1 else "ICMPv6"
        packet.info = _icmp_info(proto, icmp_type, code)
    elif proto == 2:
        packet.transport = packet.protocol = "IGMP"
        packet.info = "IGMP"
    else:
        packet.info = f"IP protocol {proto}"


def _decode_tcp(data: bytes, packet: Packet) -> None:
    packet.transport = "TCP"
    packet.src_port, packet.dst_port, packet.tcp_seq, packet.tcp_ack = struct.unpack_from(">HHII", data, 0)
    header_len = (data[12] >> 4) * 4
    packet.tcp_flags = [name for bit, name in TCP_FLAG_NAMES if data[13] & bit]
    packet.payload = data[header_len:]
    packet.protocol = "TCP"
    packet.info = f"{packet.src_port} → {packet.dst_port} [{', '.join(packet.tcp_flags)}] Len={len(packet.payload)}"

    payload = packet.payload
    if not payload:
        return
    if is_tls_record(payload):
        packet.protocol = "TLS"
        packet.tls_sni = parse_client_hello_sni(payload)
        packet.info = tls_handshake_name(payload) or "TLS record"
        if packet.tls_sni:
            packet.info += f" (SNI={packet.tls_sni})"
    elif 53 in (packet.src_port, packet.dst_port):
        packet.dns = parse_dns(payload[2:])  # DNS over TCP has a 2-byte length prefix
        if packet.dns:
            packet.protocol, packet.info = "DNS", _dns_info(packet.dns)


def _decode_udp(data: bytes, packet: Packet) -> None:
    packet.transport = "UDP"
    packet.src_port, packet.dst_port, udp_len = struct.unpack_from(">HHH", data, 0)
    packet.payload = data[8:udp_len] if udp_len >= 8 else data[8:]
    packet.protocol = "UDP"
    packet.info = f"{packet.src_port} → {packet.dst_port} Len={len(packet.payload)}"

    for port in (packet.src_port, packet.dst_port):
        if port in DNS_PORTS:
            packet.dns = parse_dns(packet.payload)
            if packet.dns:
                packet.protocol = UDP_PORT_PROTOCOLS[port]
                packet.info = _dns_info(packet.dns)
                return
    name = UDP_PORT_PROTOCOLS.get(packet.dst_port) or UDP_PORT_PROTOCOLS.get(packet.src_port)
    if name and packet.payload:
        packet.protocol = name


# ---------- helpers ----------

def _dns_info(dns) -> str:
    query = ", ".join(f"{qtype} {name}" for name, qtype in dns.questions)
    if not dns.is_response:
        return f"Standard query 0x{dns.transaction_id:04x} {query}"
    answers = ", ".join(f"{rtype} {value}" for _name, rtype, value in dns.answers)
    return f"Standard query response 0x{dns.transaction_id:04x} {query} {answers}".strip()


def _icmp_info(proto: int, icmp_type: int, code: int) -> str:
    names = {0: "Echo (ping) reply", 3: "Destination unreachable", 8: "Echo (ping) request", 11: "Time-to-live exceeded"}
    if proto == 58:
        names = {128: "Echo (ping) request", 129: "Echo (ping) reply", 133: "Router Solicitation",
                 134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}
    return names.get(icmp_type, f"Type={icmp_type} Code={code}")


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ipv4(raw: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(raw[:4])


def _ipv6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))
