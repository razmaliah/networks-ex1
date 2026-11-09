# networks-ex1

Ex1 in the communication networks course: manual Wireshark analysis (parts A-B) and a PCAP analysis dashboard with AI assistance (part C).

## Structure

```
part_a_b/      PDF answers and screenshots for the manual parts
captures/      sample .pcap/.pcapng files
dashboard/
  app.py            UI (Streamlit)
  pcap_reader.py    reads frames from .pcap / .pcapng files
  packet_parser.py  decodes Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP
  app_protocols.py  DNS and TLS Client Hello (SNI) decoding
  http_parser.py    TCP stream reassembly, HTTP messages and request-response pairing
  analysis.py       entry point (analyze) and statistics
  models.py         data structures
  ai_helper.py      questions to Claude over the extracted data only
tests/              unit tests on synthetic captures
```

Packets are decoded in pure Python, without tshark or scapy. Frame numbers match Wireshark's `No.` column,
and an HTTP message is reported at the frame that completed it, as in Wireshark.

## Setup (Windows)

```
git clone https://github.com/razmaliah/networks-ex1.git
cd networks-ex1
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Then put your Anthropic API key in `.env` (never commit it). The dashboard works without a key; only the AI tab needs it.

If PowerShell refuses to run `activate`, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## Run

```
streamlit run dashboard/app.py
```

## Tests

```
python -m pytest tests
```
