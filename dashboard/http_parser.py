"""Rebuilds TCP byte streams from segments and extracts HTTP/1.x requests, responses and transactions."""

from __future__ import annotations

import zlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from models import HttpMessage, HttpTransaction, Packet

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")


@dataclass
class _Piece:
    """A run of stream bytes [start, end) contributed by one frame."""

    start: int
    end: int
    frame: int
    timestamp: float


@dataclass
class _Chunk:
    """A gap-free part of one direction of a TCP connection."""

    data: bytearray
    pieces: list[_Piece]


def extract_http(packets: list[Packet]) -> list[HttpTransaction]:
    """Finds all HTTP transactions in the capture and labels the HTTP frames in `packets`."""
    directions: dict[tuple, list[Packet]] = defaultdict(list)
    for packet in packets:
        if packet.transport == "TCP" and packet.src_ip is not None:
            directions[(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)].append(packet)

    transactions: list[HttpTransaction] = []
    seen: set[tuple] = set()
    for key in directions:
        if key in seen:
            continue
        reverse = (key[2], key[3], key[0], key[1])
        seen.update((key, reverse))
        transactions.extend(_connection_transactions(key, directions[key], directions.get(reverse, [])))

    transactions.sort(key=lambda t: t.request.last_frame)
    for index, transaction in enumerate(transactions, start=1):
        transaction.index = index
    _label_packets(packets, transactions)
    return transactions


def _connection_transactions(key: tuple, forward: list[Packet], backward: list[Packet]) -> list[HttpTransaction]:
    forward_chunks, backward_chunks = _reassemble(forward), _reassemble(backward)
    if _starts_with_request(forward_chunks):
        client, client_chunks, server_chunks = (key[0], key[1]), forward_chunks, backward_chunks
        server = (key[2], key[3])
    elif _starts_with_request(backward_chunks):
        client, client_chunks, server_chunks = (key[2], key[3]), backward_chunks, forward_chunks
        server = (key[0], key[1])
    else:
        return []

    requests = [msg for chunk in client_chunks for msg in _parse_messages(chunk, expect_request=True)]
    request_methods = [r.method for r in requests]
    responses = [msg for chunk in server_chunks for msg in _parse_messages(chunk, False, request_methods)]
    final_responses = [r for r in responses if not (r.status_code and 100 <= r.status_code < 200)]

    # HTTP/1.x answers requests in order, so the n-th final response belongs to the n-th request.
    return [
        HttpTransaction(0, client[0], client[1], server[0], server[1], request,
                        final_responses[i] if i < len(final_responses) else None)
        for i, request in enumerate(requests)
    ]


def _starts_with_request(chunks: list[_Chunk]) -> bool:
    return bool(chunks) and chunks[0].data.split(b" ", 1)[0] in HTTP_METHODS


# ---------- TCP reassembly ----------

def _reassemble(packets: list[Packet]) -> list[_Chunk]:
    """Orders the segments of one direction by sequence number, drops retransmitted bytes and splits at gaps."""
    base: Optional[int] = None
    segments = []
    for packet in packets:
        if "SYN" in packet.tcp_flags:
            base = (packet.tcp_seq + 1) % 2**32
        if packet.payload:
            if base is None:
                base = packet.tcp_seq
            offset = (packet.tcp_seq - base) % 2**32
            if offset >= 2**31:  # segment from before the first one we saw
                offset -= 2**32
            segments.append((offset, packet.number, packet.timestamp, packet.payload))
    segments.sort(key=lambda s: (s[0], s[1]))

    chunks: list[_Chunk] = []
    cursor: Optional[int] = None
    for offset, frame, timestamp, payload in segments:
        if cursor is None or offset > cursor:  # first segment, or bytes are missing from the capture
            chunks.append(_Chunk(bytearray(), []))
            cursor = offset
        end = offset + len(payload)
        if end <= cursor:
            continue  # pure retransmission
        new_bytes = payload[cursor - offset:]
        chunk = chunks[-1]
        chunk.pieces.append(_Piece(len(chunk.data), len(chunk.data) + len(new_bytes), frame, timestamp))
        chunk.data.extend(new_bytes)
        cursor = end
    return chunks


def _frames_between(pieces: list[_Piece], start: int, end: int) -> list[_Piece]:
    return [p for p in pieces if p.start < end and p.end > start]


# ---------- HTTP message parsing ----------

def _parse_messages(chunk: _Chunk, expect_request: bool, request_methods: Optional[list] = None) -> list[HttpMessage]:
    data, messages, position = chunk.data, [], 0
    final_index = 0  # which request the next final response answers (for HEAD)
    while position < len(data):
        header_end = data.find(b"\r\n\r\n", position)
        if header_end == -1:
            break  # headers not complete in the capture
        lines = bytes(data[position:header_end]).decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        if expect_request:
            if len(parts) < 3 or parts[0].encode() not in HTTP_METHODS or not parts[2].startswith("HTTP/"):
                break
            method, uri, version, status, reason = parts[0], parts[1], parts[2], None, None
        else:
            if not parts[0].startswith("HTTP/") or len(parts) < 2 or not parts[1].isdigit():
                break
            method, uri, version, status = None, None, parts[0], int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""

        headers = [(n.strip(), v.strip()) for n, _, v in (line.partition(":") for line in lines[1:]) if _]
        header_map = {n.lower(): v for n, v in headers}
        body_start = header_end + 4

        chunked = "chunked" in header_map.get("transfer-encoding", "").lower()
        if chunked:
            body_end, body = _dechunk(data, body_start)
        else:
            if "content-length" in header_map and header_map["content-length"].isdigit():
                body_end = body_start + int(header_map["content-length"])
            elif expect_request or _response_has_no_body(status, request_methods, final_index):
                body_end = body_start
            else:
                body_end = len(data)  # body ends when the server closes the connection
            body_end = min(body_end, len(data))
            body = bytes(data[body_start:body_end])

        pieces = _frames_between(chunk.pieces, position, body_end)
        messages.append(HttpMessage(
            is_request=expect_request, start_line=lines[0], version=version, headers=headers,
            body=_decompress(body, header_map.get("content-encoding", "")), body_wire_size=body_end - body_start,
            frames=[p.frame for p in pieces], timestamp=pieces[-1].timestamp,
            method=method, uri=uri, status_code=status, reason=reason,
        ))
        if status is not None and status >= 200:
            final_index += 1
        position = body_end
    return messages


def _response_has_no_body(status: int, request_methods: Optional[list], index: int) -> bool:
    if 100 <= status < 200 or status in (204, 304):
        return True
    return bool(request_methods) and index < len(request_methods) and request_methods[index] == "HEAD"


def _dechunk(data: bytearray, position: int) -> tuple[int, bytes]:
    """Decodes a chunked body; returns where it ends in the stream and the joined data."""
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end == -1:
            return len(data), bytes(body)
        try:
            size = int(bytes(data[position:line_end]).split(b";")[0].strip(), 16)
        except ValueError:
            return len(data), bytes(body)
        position = line_end + 2
        if size == 0:
            if data[position:position + 2] == b"\r\n":
                return position + 2, bytes(body)
            trailer_end = data.find(b"\r\n\r\n", position)
            return (len(data) if trailer_end == -1 else trailer_end + 4), bytes(body)
        body.extend(data[position:position + size])
        position += size + 2
        if position > len(data):
            return len(data), bytes(body)


def _decompress(body: bytes, encoding: str) -> bytes:
    encoding = encoding.lower()
    try:
        if "gzip" in encoding:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except zlib.error:
        pass  # truncated or unsupported (e.g. brotli): keep the raw bytes
    return body


# ---------- labeling ----------

def _label_packets(packets: list[Packet], transactions: list[HttpTransaction]) -> None:
    """Marks the frame that completes each HTTP message as HTTP, like Wireshark does."""
    for transaction in transactions:
        for message in (transaction.request, transaction.response):
            if message is None:
                continue
            packet = packets[message.last_frame - 1]
            packet.protocol = "HTTP"
            content_type = message.header("Content-Type")
            packet.info = message.start_line + (f"  ({content_type})" if content_type and not message.is_request else "")
