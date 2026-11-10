"""Answers free-text questions about a capture with an AI model (Claude or Gemini).

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

# provider id -> settings
PROVIDERS = {
    "anthropic": {"label": "Claude (Anthropic)", "env_key": "ANTHROPIC_API_KEY", "env_model": "AI_MODEL",
                  "default_model": "claude-sonnet-5-5", "key_url": "https://console.anthropic.com/settings/keys"},
    "gemini": {"label": "Gemini (Google)", "env_key": "GEMINI_API_KEY", "env_model": "GEMINI_MODEL",
               "default_model": "gemini-3.8-flash", "key_url": "https://aistudio.google.com/apikey"},
}

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
    invalid_frames: list = field(default_factory=list)  # cited frames that do not exist in the capture
    raw_text: str = ""
    provider: str = ""
    model: str = ""


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


def api_key_from_env(provider: str) -> str | None:
    return os.getenv(PROVIDERS[provider]["env_key"]) or None


def default_model(provider: str) -> str:
    settings = PROVIDERS[provider]
    return os.getenv(settings["env_model"]) or settings["default_model"]


def ask(question: str, analysis: CaptureAnalysis, provider: str = "anthropic",
        api_key: str | None = None, model: str | None = None) -> AiAnswer:
    settings = PROVIDERS[provider]
    api_key = api_key or api_key_from_env(provider)
    if not api_key:
        raise RuntimeError(f"No API key: set {settings['env_key']} in the .env file.")
    model = model or default_model(provider)

    context = json.dumps(build_context(analysis), ensure_ascii=False)
    prompt = f"<capture_data>\n{context}\n</capture_data>\n\nQuestion: {question}"
    text = _ask_gemini(prompt, api_key, model) if provider == "gemini" else _ask_claude(prompt, api_key, model)

    answer = parse_answer(text, analysis.summary.packet_count)
    answer.provider, answer.model = settings["label"], model
    return answer


def _ask_claude(prompt: str, api_key: str, model: str) -> str:
    try:
        import anthropic
    except ImportError as error:
        raise RuntimeError("The 'anthropic' package is not installed: pip install -r requirements.txt") from error
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(model=model, max_tokens=2000, system=SYSTEM_PROMPT,
                                      messages=[{"role": "user", "content": prompt}])
    return "".join(block.text for block in response.content if block.type == "text")


def _ask_gemini(prompt: str, api_key: str, model: str) -> str:
    try:
        from google import genai
        from google.genai import types
    except ImportError as error:
        raise RuntimeError("The 'google-genai' package is not installed: pip install -r requirements.txt") from error
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            max_output_tokens=8192,  # thinking models count their reasoning in this limit too
        ),
    )
    if not response.text:
        raise RuntimeError("Gemini returned an empty answer (it may have been blocked or cut off).")
    return response.text


def list_gemini_models(api_key: str) -> list[str]:
    """Gemini models this key can use for text generation, so the user picks a real name instead of a guess."""
    from google import genai

    client = genai.Client(api_key=api_key)  # keep a reference: the list is fetched lazily, page by page
    names = []
    for model in list(client.models.list()):
        actions = getattr(model, "supported_actions", None) or []
        name = (model.name or "").removeprefix("models/")
        if name.startswith("gemini") and (not actions or "generateContent" in actions):
            names.append(name)
    return sorted(names)


def pick_gemini_default(names: list[str]) -> str | None:
    """Prefers GEMINI_MODEL from .env, otherwise the newest stable general-purpose 'flash' model."""
    preferred = os.getenv("GEMINI_MODEL")
    if preferred in names:
        return preferred
    skip = ("lite", "image", "tts", "live", "audio", "embedding", "preview", "exp", "thinking")
    stable_flash = [n for n in names if "flash" in n and not any(word in n for word in skip)]
    if stable_flash:
        return sorted(stable_flash, key=_version_key)[-1]
    return names[-1] if names else None


def _version_key(name: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", name))


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
