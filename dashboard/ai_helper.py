"""Answers free-text questions about a capture with Claude.

Only data already extracted by the analysis layer is sent to the model; the PCAP file itself never is.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime

from analysis import conversations, ip_stats, protocol_stats, relative_time, resolved_names
from models import CaptureAnalysis

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TRANSACTIONS = 150
MAX_ROWS = 40
MAX_HEADER_VALUE = 150

SYSTEM_PROMPT = """You are a network traffic analyst. You receive data that was already extracted from a packet capture \
(not the capture itself) and a question about it.

Rules:
- Answer ONLY from the provided data. If the data is not enough to answer, say so explicitly; never guess.
- Every claim must be backed by evidence: frame numbers ("frame") and times (the "t" values, seconds since the first packet).
- Only cite frame numbers that appear in the data.
- Answer in the language of the question.

Reply with ONLY a JSON object, no other text:
{"answer": "<the answer>", "evidence": [{"frame": <int>, "t": <float or null>, "detail": "<what this frame shows>"}], \
"limitations": "<what the data cannot tell, or empty>"}"""


@dataclass
class AiAnswer:
    answer: str
    evidence: list[dict] = field(default_factory=list)
    limitations: str = ""
    invalid_frames: list[int] = field(default_factory=list)  # cited frames that do not exist in the capture
    raw_text: str = ""


def build_context(analysis: CaptureAnalysis) -> dict:
    """The structured data sent to the model. Shown in the UI so the user sees exactly what was shared."""
    summary = analysis.summary

    def t(ts: float) -> float:
        return round(relative_time(analysis, ts), 6)

    transactions = []
    for tx in analysis.transactions[:MAX_TRANSACTIONS]:
        response = tx.response
        transactions.append({
            "id": tx.index,
            "request_frame": tx.request.last_frame,
            "request_segments": tx.request.frames,
            "t_request": t(tx.request.timestamp),
            "client": f"{tx.client_ip}:{tx.client_port}",
            "server": f"{tx.server_ip}:{tx.server_port}",
            "request_line": tx.request.start_line,
            "request_headers": _short_headers(tx.request.headers),
            "request_body_bytes": tx.request.body_wire_size,
            "response_frame": response.last_frame if response else None,
            "response_segments": response.frames if response else None,
            "t_response": t(response.timestamp) if response else None,
            "status": response.status_code if response else None,
            "status_line": response.start_line if response else None,
            "response_headers": _short_headers(response.headers) if response else None,
            "response_body_bytes": response.body_wire_size if response else None,
            "response_time_s": round(tx.response_time, 6) if response else None,
        })

    return {
        "file": analysis.file_name,
        "summary": {
            "packet_count": summary.packet_count,
            "first_packet_time": _iso(summary.start_time),
            "last_packet_time": _iso(summary.end_time),
            "duration_s": round(summary.duration, 6),
            "total_bytes": summary.total_bytes,
        },
        "protocols": protocol_stats(analysis.packets),
        "top_source_ips": ip_stats(analysis.packets, "src")[:MAX_ROWS],
        "top_destination_ips": ip_stats(analysis.packets, "dst")[:MAX_ROWS],
        "conversations": conversations(analysis.packets)[:MAX_ROWS],
        "domain_names": resolved_names(analysis.packets)[:MAX_ROWS * 3],
        "http_transactions": transactions,
        "http_transactions_total": len(analysis.transactions),
        "notes": "t values are seconds since the first packet. Frame numbers match Wireshark's No. column. "
                 "An HTTP message's frame is the last TCP segment that completed it.",
    }


def ask(question: str, analysis: CaptureAnalysis, api_key: str | None = None, model: str | None = None) -> AiAnswer:
    try:
        import anthropic
    except ImportError as error:
        raise RuntimeError("The 'anthropic' package is not installed: pip install -r requirements.txt") from error

    api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("No API key: set ANTHROPIC_API_KEY in the .env file.")

    context = build_context(analysis)
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model or os.getenv("AI_MODEL") or DEFAULT_MODEL,
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"<capture_data>\n{json.dumps(context, ensure_ascii=False)}\n</capture_data>\n\nQuestion: {question}",
        }],
    )
    text = "".join(block.text for block in response.content if block.type == "text")
    return parse_answer(text, analysis.summary.packet_count)


def parse_answer(text: str, packet_count: int) -> AiAnswer:
    """Reads the model's JSON reply and checks that every cited frame really exists."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    try:
        data = json.loads(match.group(0)) if match else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict) or "answer" not in data:
        return AiAnswer(answer=text, raw_text=text, limitations="The model did not return the expected format.")

    evidence = [e for e in data.get("evidence") or [] if isinstance(e, dict)]
    invalid = []
    for item in evidence:
        frame = item.get("frame")
        if not isinstance(frame, int) or not 1 <= frame <= packet_count:
            invalid.append(frame)
    return AiAnswer(str(data["answer"]), evidence, str(data.get("limitations") or ""), invalid, text)


def _short_headers(headers: list[tuple[str, str]]) -> dict:
    return {name: value[:MAX_HEADER_VALUE] for name, value in headers}


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="microseconds") if ts is not None else None
