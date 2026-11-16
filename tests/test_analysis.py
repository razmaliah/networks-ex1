import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analysis import analyze, ip_stats, protocol_stats, resolved_names  # noqa: E402
from capture_builder import sample_frames, write_pcap, write_pcapng  # noqa: E402
from pcap_reader import CaptureFormatError  # noqa: E402


@pytest.fixture(params=["pcap", "pcapng"])
def capture(request):
    frames = sample_frames()
    data = write_pcap(frames) if request.param == "pcap" else write_pcapng(frames)
    return analyze(data, f"sample.{request.param}")


def test_summary(capture):
    assert capture.summary.packet_count == 14
    assert capture.summary.duration == pytest.approx(0.6, abs=1e-5)


def test_protocol_labels(capture):
    protocols = [p.protocol for p in capture.packets]
    assert protocols[0:2] == ["DNS", "DNS"]
    assert protocols[5] == "TCP"     # first segment of the split request
    assert protocols[6] == "HTTP"    # frame that completes the request
    assert protocols[7] == "TCP"     # first segment of the response
    assert protocols[9] == "HTTP"    # frame that completes the response
    assert protocols[12] == "TLS"
    assert capture.packets[12].tls_sni == "secure.example.org"


def test_http_transactions(capture):
    first, second = capture.transactions
    assert (first.request.method, first.request.uri, first.host) == ("GET", "/index.html", "example.com")
    assert first.request.frames == [6, 7]
    assert first.response.frames == [8, 10]  # frame 9 is a retransmission
    assert first.response.status_code == 200
    assert first.response.body.startswith(b"<html>")  # gzip decoded
    assert first.response_time == pytest.approx(0.109, abs=1e-5)
    assert (first.client_ip, first.client_port, first.server_ip, first.server_port) == ("192.168.1.19", 51000, "93.184.216.34", 80)

    assert second.request.method == "POST" and second.request.body == b"name=ab"
    assert second.response.status_code == 201 and second.response.body == b"hello world"
    assert capture.frame_to_transaction[12] is second


def test_statistics(capture):
    src = {row["ip"]: row["packets"] for row in ip_stats(capture.packets, "src")}
    assert src["192.168.1.19"] == 8
    both = {row["ip"]: row["packets"] for row in ip_stats(capture.packets, "both")}
    assert both["93.184.216.34"] == 11
    counts = {row["protocol"]: row["packets"] for row in protocol_stats(capture.packets)}
    assert counts["HTTP"] == 4 and counts["DNS"] == 2
    names = {row["name"]: row["addresses"] for row in resolved_names(capture.packets)}
    assert names["example.com"] == "93.184.216.34"
    assert names["secure.example.org"] == "151.101.1.69"


def test_rejects_other_files():
    with pytest.raises(CaptureFormatError):
        analyze(b"this is not a capture")


def test_ai_context_and_answer_parsing(capture):
    import json

    from ai_helper import build_context, parse_answer

    context = build_context(capture)
    json.dumps(context)  # must be serializable
    assert context["http_transactions"][0]["request_frame"] == 7
    assert context["http_transactions"][0]["response_segments"] == [8, 10]

    reply = 'Sure:\n{"answer": "GET to example.com", "evidence": [{"frame": 7, "t": 0.051, "detail": "request"}, {"frame": 99, "t": null, "detail": "x"}], "limitations": ""}'
    answer = parse_answer(reply, capture.summary.packet_count)
    assert answer.answer == "GET to example.com"
    assert answer.invalid_frames == [99]
    assert parse_answer("plain text", 14).answer == "plain text"


def test_ip_version_filter():
    from capture_builder import ethernet_ipv4, ethernet_ipv6_udp, udp

    v6_src, v6_dst = bytes.fromhex("fe80" + "00" * 12 + "0001"), bytes.fromhex("ff02" + "00" * 13 + "fb")
    frames = [(1.0, ethernet_ipv4("10.0.0.1", "10.0.0.2", 17, udp(1000, 2000, b"hi"))),
              (2.0, ethernet_ipv6_udp(v6_src, v6_dst, 5353, 5353, b"\x00" * 12))]
    packets = analyze(write_pcap(frames)).packets
    assert packets[1].src_ip == "fe80::1" and packets[1].ip_version == 6
    assert {r["ip"] for r in ip_stats(packets, "both", 4)} == {"10.0.0.1", "10.0.0.2"}
    assert {r["ip"] for r in ip_stats(packets, "src", 6)} == {"fe80::1"}
    assert len(ip_stats(packets, "both")) == 4


def test_gemini_default_model(monkeypatch):
    from ai_helper import pick_gemini_default

    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    names = ["gemini-2.5-flash", "gemini-3.8-flash", "gemini-3.8-flash-lite", "gemini-3.8-pro", "gemini-4-flash-preview"]
    assert pick_gemini_default(names) == "gemini-3.8-flash"
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-pro")
    assert pick_gemini_default(names) == "gemini-3.8-pro"


def test_follow_up_turns(capture):
    from ai_helper import build_turns

    assert [role for role, _ in build_turns("q1", capture, [])] == ["user"]
    turns = build_turns("q3", capture, [("q1", "a1"), ("q2", "a2")])
    assert [role for role, _ in turns] == ["user", "assistant", "user", "assistant", "user"]
    assert "<capture_data>" in turns[0][1] and turns[0][1].endswith("Question: q1")
    assert turns[1:] == [("assistant", "a1"), ("user", "Question: q2"), ("assistant", "a2"), ("user", "Question: q3")]


def test_http_statistics(capture):
    from analysis import http_statistics

    stats = http_statistics(capture)
    assert stats["requests"] == 2 and stats["requests_with_response"] == 2
    assert stats["requests_without_response"] == []
    times = [tx.response_time for tx in capture.transactions]
    assert stats["response_time"]["average_s"] == pytest.approx(sum(times) / 2, abs=1e-6)
    assert stats["response_time"]["max_s"] == pytest.approx(max(times), abs=1e-6)
    assert [row["transaction"] for row in stats["slowest"]] == [1, 2]  # 109 ms, then 80 ms
    assert stats["requests_per_host"] == [{"host": "example.com", "requests": 2, "request_frames": [7, 11]}]
    assert {row["status"]: row["count"] for row in stats["status_codes"]} == {"200": 1, "201": 1}


def test_selected_transaction_and_stream(capture):
    from ai_helper import build_turns, selected_transaction_context
    from analysis import connection_packets

    first = capture.transactions[0]
    # frames 3-12 and 14 belong to the client:51000 <-> server:80 connection (SYN ... FIN)
    assert [p.number for p in connection_packets(capture, first)] == [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14]

    selected = selected_transaction_context(capture, first)
    assert selected["transaction"]["id"] == 1
    assert selected["same_connection_transactions"] == [1, 2]
    assert selected["connection_packets"][0] == {"frame": 3, "t": 0.03, "direction": "client->server",
                                                 "tcp_flags": ["SYN"], "payload_bytes": 0,
                                                 "info": "51000 → 80 [SYN] Len=0"}
    assert selected["transaction"]["response_body_preview"].startswith("<html>")

    # the selection is sent with the newest question only
    turns = build_turns("q2", capture, [("q1", "a1")], selected=first)
    assert "<selected_transaction>" not in turns[0][1]
    assert turns[-1][1].startswith("<selected_transaction>") and turns[-1][1].endswith("Question: q2")
    assert '"http_statistics"' in turns[0][1]
