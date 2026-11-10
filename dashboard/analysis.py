"""Entry point of the analysis layer: turns a capture file into a CaptureAnalysis, plus statistics helpers."""

from __future__ import annotations

from collections import Counter

from http_parser import extract_http
from models import CaptureAnalysis, CaptureSummary, Packet
from packet_parser import decode_frames
from pcap_reader import read_capture


def analyze(data: bytes, file_name: str = "") -> CaptureAnalysis:
    packets = decode_frames(read_capture(data))
    transactions = extract_http(packets)
    frame_to_transaction = {}
    for transaction in transactions:
        frame_to_transaction[transaction.request.last_frame] = transaction
        if transaction.response is not None:
            frame_to_transaction[transaction.response.last_frame] = transaction
    return CaptureAnalysis(file_name, packets, summarize(packets), transactions, frame_to_transaction)


def summarize(packets: list[Packet]) -> CaptureSummary:
    if not packets:
        return CaptureSummary(0, None, None, 0)
    times = [p.timestamp for p in packets]
    return CaptureSummary(len(packets), min(times), max(times), sum(p.length for p in packets))


def ip_stats(packets: list[Packet], direction: str = "both", version: int | None = None) -> list[dict]:
    """Packets and bytes per IP address.

    direction: 'src', 'dst' or 'both' (address on either side). version: 4 or 6 to keep only that IP version.
    """
    count, size = Counter(), Counter()
    for packet in packets:
        if packet.src_ip is None or (version is not None and packet.ip_version != version):
            continue
        addresses = {"src": [packet.src_ip], "dst": [packet.dst_ip]}.get(direction, [packet.src_ip, packet.dst_ip])
        for address in set(addresses):
            count[address] += 1
            size[address] += packet.length
    return [{"ip": ip, "packets": n, "bytes": size[ip]} for ip, n in count.most_common()]


def protocol_stats(packets: list[Packet]) -> list[dict]:
    count, size = Counter(), Counter()
    for packet in packets:
        count[packet.protocol] += 1
        size[packet.protocol] += packet.length
    return [{"protocol": name, "packets": n, "bytes": size[name]} for name, n in count.most_common()]


def conversations(packets: list[Packet]) -> list[dict]:
    """Traffic between each pair of IP addresses (both directions together)."""
    stats: dict[tuple, dict] = {}
    for packet in packets:
        if packet.src_ip is None:
            continue
        key = tuple(sorted((packet.src_ip, packet.dst_ip)))
        entry = stats.setdefault(key, {"address_a": key[0], "address_b": key[1], "packets": 0, "bytes": 0,
                                       "first_frame": packet.number, "last_frame": packet.number, "protocols": set()})
        entry["packets"] += 1
        entry["bytes"] += packet.length
        entry["last_frame"] = packet.number
        entry["protocols"].add(packet.protocol)
    result = sorted(stats.values(), key=lambda e: e["packets"], reverse=True)
    for entry in result:
        entry["protocols"] = ", ".join(sorted(entry["protocols"]))
    return result


def packets_per_second(packets: list[Packet]) -> list[dict]:
    if not packets:
        return []
    start = min(p.timestamp for p in packets)
    buckets = Counter(int(p.timestamp - start) for p in packets)
    return [{"second": s, "packets": buckets.get(s, 0)} for s in range(max(buckets) + 1)]


def resolved_names(packets: list[Packet]) -> list[dict]:
    """Domain names seen in the capture: DNS answers (name -> addresses) and TLS SNI (name -> server address)."""
    names: dict[str, dict] = {}

    def entry(name: str, frame: int) -> dict:
        return names.setdefault(name, {"name": name, "addresses": set(), "sources": set(), "first_frame": frame})

    for packet in packets:
        if packet.dns and packet.dns.is_response:
            for name, rtype, value in packet.dns.answers:
                if rtype in ("A", "AAAA"):
                    e = entry(name, packet.number)
                    e["addresses"].add(value)
                    e["sources"].add("DNS")
            for name, _qtype in packet.dns.questions:  # also map the query name through CNAME chains
                targets = {v for _n, t, v in packet.dns.answers if t in ("A", "AAAA")}
                if targets:
                    e = entry(name, packet.number)
                    e["addresses"].update(targets)
                    e["sources"].add("DNS")
        if packet.tls_sni:
            e = entry(packet.tls_sni, packet.number)
            e["addresses"].add(packet.dst_ip)
            e["sources"].add("TLS SNI")
    rows = sorted(names.values(), key=lambda e: e["first_frame"])
    for row in rows:
        row["addresses"] = ", ".join(sorted(row["addresses"]))
        row["sources"] = ", ".join(sorted(row["sources"]))
    return rows


def relative_time(analysis: CaptureAnalysis, packet_or_ts) -> float:
    """Seconds since the first packet, like Wireshark's default Time column."""
    ts = packet_or_ts.timestamp if isinstance(packet_or_ts, Packet) else packet_or_ts
    return ts - (analysis.summary.start_time or 0.0)
