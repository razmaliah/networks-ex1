"""Data structures shared by all layers of the dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DnsInfo:
    """A decoded DNS message (query or response)."""

    transaction_id: int
    is_response: bool
    questions: list[tuple[str, str]]  # (name, type)
    answers: list[tuple[str, str, str]]  # (name, type, value)


@dataclass
class Packet:
    """One captured frame, decoded down to the transport layer."""

    number: int  # 1-based, same numbering as Wireshark's "No." column
    timestamp: float  # seconds since epoch
    length: int  # original length on the wire
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    transport: Optional[str] = None  # TCP / UDP / ICMP / ICMPv6 / IGMP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: list[str] = field(default_factory=list)
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload: bytes = b""  # transport-layer payload
    protocol: str = "Other"  # highest protocol identified (like Wireshark's Protocol column)
    info: str = ""
    dns: Optional[DnsInfo] = None
    tls_sni: Optional[str] = None
    malformed: bool = False


@dataclass
class HttpMessage:
    """A complete HTTP/1.x request or response, possibly reassembled from several TCP segments."""

    is_request: bool
    start_line: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes  # decoded body (de-chunked and decompressed when possible)
    body_wire_size: int  # body size as sent on the wire
    frames: list[int]  # all frames carrying bytes of this message
    timestamp: float  # time of the last frame (when the message was complete)
    method: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None

    @property
    def last_frame(self) -> int:
        return self.frames[-1]

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None


@dataclass
class HttpTransaction:
    """A request paired with its response (if one was captured)."""

    index: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request: HttpMessage
    response: Optional[HttpMessage] = None

    @property
    def host(self) -> Optional[str]:
        return self.request.header("Host")

    @property
    def response_time(self) -> Optional[float]:
        if self.response is None:
            return None
        return self.response.timestamp - self.request.timestamp


@dataclass
class CaptureSummary:
    packet_count: int
    start_time: Optional[float]
    end_time: Optional[float]
    total_bytes: int

    @property
    def duration(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time


@dataclass
class CaptureAnalysis:
    """Everything extracted from one capture file; this is what the UI and the AI layer consume."""

    file_name: str
    packets: list[Packet]
    summary: CaptureSummary
    transactions: list[HttpTransaction]
    frame_to_transaction: dict[int, HttpTransaction]
