# networks-ex1

Ex1 in the communication networks course: manual Wireshark analysis (parts A-B) and a PCAP analysis dashboard with AI assistance (part C).

## Structure

```
part_a_b/      PDF answers and screenshots for the manual parts
captures/      the .pcap/.pcapng files used in the assignment
run.bat        one-click start on Windows (run.sh on macOS / Linux)
dashboard/
  app.py            UI (Streamlit)
  pcap_reader.py    reads frames from .pcap / .pcapng files
  packet_parser.py  decodes Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP
  app_protocols.py  DNS and TLS Client Hello (SNI) decoding
  http_parser.py    TCP stream reassembly, HTTP messages and request-response pairing
  analysis.py       entry point (analyze) and statistics
  models.py         data structures
  ai_helper.py      questions to Gemini / Claude over the extracted data only
tests/              unit tests on synthetic captures
```

Packets are decoded in pure Python, without tshark or scapy. Frame numbers match Wireshark's `No.` column,
and an HTTP message is reported at the frame that completed it, as in Wireshark.

## Quick start

Requirements: Python 3.10 or newer (on Windows, tick "Add python.exe to PATH" when installing it) and an internet
connection for the first run.

- **Windows:** double-click `run.bat`.
- **macOS / Linux:** run `./run.sh` in a terminal.

The first run creates a virtual environment (`.venv`) and installs the packages, which takes a minute or two.
The dashboard then opens in the browser at http://localhost:8501. Choose a file from `captures/` to start.
To stop it, close the terminal window or press `Ctrl+C`.

### AI tab (optional)

Everything except the AI tab works without an API key. To use it, either paste a key in the AI tab (kept for the
session only), or copy `.env.example` to `.env` and fill in a key:

- Gemini (default, has a free tier): https://aistudio.google.com/apikey -> `GEMINI_API_KEY=...`
- Claude: https://console.anthropic.com/settings/keys -> `ANTHROPIC_API_KEY=...`

No API keys are included in this submission.

## Manual setup (instead of run.bat)

```
python -m venv .venv
.venv\Scripts\activate          (macOS / Linux: source .venv/bin/activate)
pip install -r requirements.txt
streamlit run dashboard/app.py
```

If PowerShell refuses to run `activate`, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## Tests

```
python -m pytest tests
```
