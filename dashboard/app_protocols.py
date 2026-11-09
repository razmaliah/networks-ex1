"""Light decoders for application-layer data that stays readable: DNS messages and the TLS Client Hello (SNI)."""

from __future__ import annotations

import struct
from typing import Optional

from models import DnsInfo

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS"}


def parse_dns(data: bytes) -> Optional[DnsInfo]:
    """Decodes a DNS message; returns None if the bytes are not valid DNS."""
    try:
        tid, flags, qd_count, an_count, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
        offset = 12
        questions = []
        for _ in range(qd_count):
            name, offset = _read_name(data, offset)
            qtype = struct.unpack_from(">H", data, offset)[0]
            offset += 4
            questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
        answers = []
        for _ in range(an_count):
            name, offset = _read_name(data, offset)
            rtype, _cls, _ttl, rd_len = struct.unpack_from(">HHIH", data, offset)
            offset += 10
            rdata = data[offset:offset + rd_len]
            if rtype == 1 and rd_len == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rd_len == 16:
                value = _ipv6_text(rdata)
            elif rtype in (2, 5, 12):
                value = _read_name(data, offset)[0]
            else:
                value = f"<{rd_len} bytes>"
            answers.append((name, DNS_TYPES.get(rtype, str(rtype)), value))
            offset += rd_len
    except (struct.error, IndexError, ValueError):
        return None
    return DnsInfo(tid, bool(flags & 0x8000), questions, answers)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Reads a (possibly compressed) domain name; returns the name and the offset after it."""
    labels = []
    end_offset = None
    for _ in range(128):  # guard against pointer loops
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if end_offset is None:
                end_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    else:
        raise ValueError("DNS name too long")
    return ".".join(labels), end_offset if end_offset is not None else offset


def _ipv6_text(raw: bytes) -> str:
    import ipaddress

    return str(ipaddress.IPv6Address(raw))


def is_tls_record(payload: bytes) -> bool:
    """A TLS record starts with a content type 20-23 and a 0x03 major version."""
    return len(payload) >= 5 and 20 <= payload[0] <= 23 and payload[1] == 3 and payload[2] <= 4


def tls_handshake_name(payload: bytes) -> Optional[str]:
    names = {1: "Client Hello", 2: "Server Hello", 11: "Certificate", 16: "Client Key Exchange"}
    if len(payload) >= 6 and payload[0] == 22:
        return names.get(payload[5])
    if payload and payload[0] == 23:
        return "Application Data"
    return None


def parse_client_hello_sni(payload: bytes) -> Optional[str]:
    """Returns the server name (SNI) from a TLS Client Hello, if the whole hello is in this segment."""
    try:
        if payload[0] != 22 or payload[5] != 1:
            return None
        offset = 5 + 4 + 2 + 32  # record header, handshake header, client version, random
        offset += 1 + payload[offset]  # session id
        offset += 2 + struct.unpack_from(">H", payload, offset)[0]  # cipher suites
        offset += 1 + payload[offset]  # compression methods
        ext_end = offset + 2 + struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        while offset + 4 <= ext_end:
            ext_type, ext_len = struct.unpack_from(">HH", payload, offset)
            offset += 4
            if ext_type == 0:  # server_name
                name_len = struct.unpack_from(">H", payload, offset + 3)[0]
                return payload[offset + 5:offset + 5 + name_len].decode("ascii", "replace")
            offset += ext_len
    except (struct.error, IndexError):
        return None
    return None
