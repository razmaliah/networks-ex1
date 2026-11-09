"""Reads the raw frames out of a .pcap or .pcapng file (no external libraries)."""

from __future__ import annotations

import struct
from dataclasses import dataclass


class CaptureFormatError(Exception):
    """The file is not a pcap/pcapng capture we can read."""


@dataclass
class RawFrame:
    timestamp: float
    link_type: int
    data: bytes
    orig_len: int


PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# magic number -> (struct endianness, timestamp fraction divisor)
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 10**6),
    b"\xa1\xb2\xc3\xd4": (">", 10**6),
    b"\x4d\x3c\xb2\xa1": ("<", 10**9),
    b"\xa1\xb2\x3c\x4d": (">", 10**9),
}


def read_capture(data: bytes) -> list[RawFrame]:
    """Detects the format from the first bytes and returns all frames in file order."""
    if len(data) < 4:
        raise CaptureFormatError("The file is too short to be a capture file.")
    if data[:4] == PCAPNG_SHB:
        return _read_pcapng(data)
    if data[:4] in _PCAP_MAGICS:
        return _read_pcap(data)
    raise CaptureFormatError("Unknown file format: expected .pcap or .pcapng.")


def _read_pcap(data: bytes) -> list[RawFrame]:
    endian, divisor = _PCAP_MAGICS[data[:4]]
    if len(data) < 24:
        raise CaptureFormatError("Truncated pcap header.")
    link_type = struct.unpack_from(endian + "I", data, 20)[0] & 0x0FFFFFFF
    frames = []
    offset = 24
    while offset + 16 <= len(data):
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + captured > len(data):
            break  # last packet was cut off (capture stopped mid-write)
        frames.append(RawFrame(seconds + fraction / divisor, link_type, data[offset:offset + captured], original))
        offset += captured
    return frames


def _read_pcapng(data: bytes) -> list[RawFrame]:
    frames: list[RawFrame] = []
    interfaces: list[tuple[int, int]] = []  # (link_type, timestamp units per second)
    endian = "<"
    offset = 0
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == PCAPNG_SHB:
            byte_order = data[offset + 8:offset + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("Bad pcapng byte-order magic.")
            interfaces = []  # interface IDs restart in every section

        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8:offset + block_len - 4]

        if block_type == 1:  # Interface Description Block
            link_type = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((link_type, _timestamp_units(body[8:], endian)))
        elif block_type == 6:  # Enhanced Packet Block
            iface, ts_high, ts_low, captured, original = struct.unpack_from(endian + "IIIII", body, 0)
            link_type, units = interfaces[iface] if iface < len(interfaces) else (1, 10**6)
            frames.append(RawFrame(((ts_high << 32) | ts_low) / units, link_type, body[20:20 + captured], original))
        elif block_type == 3:  # Simple Packet Block (no timestamp)
            original = struct.unpack_from(endian + "I", body, 0)[0]
            link_type = interfaces[0][0] if interfaces else 1
            last_ts = frames[-1].timestamp if frames else 0.0
            frames.append(RawFrame(last_ts, link_type, body[4:4 + original], original))
        elif block_type == 2:  # obsolete Packet Block
            iface, _drops, ts_high, ts_low, captured, original = struct.unpack_from(endian + "HHIIII", body, 0)
            link_type, units = interfaces[iface] if iface < len(interfaces) else (1, 10**6)
            frames.append(RawFrame(((ts_high << 32) | ts_low) / units, link_type, body[20:20 + captured], original))

        offset += block_len
    return frames


def _timestamp_units(options: bytes, endian: str) -> int:
    """Reads the if_tsresol option of an interface; the default is microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[offset + 4]
            return 2 ** (value & 0x7F) if value & 0x80 else 10 ** value
        offset += 4 + ((length + 3) // 4) * 4
    return 10**6
