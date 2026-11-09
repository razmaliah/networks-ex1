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
