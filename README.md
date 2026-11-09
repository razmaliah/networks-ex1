# networks-ex1

Ex1 in the communication networks course: manual Wireshark analysis (parts A-B) and a PCAP analysis dashboard with AI assistance (part C).

## Structure

```
part_a_b/      PDF answers and screenshots for the manual parts
captures/      sample .pcap/.pcapng files
dashboard/
  app.py         UI
  parser.py      PCAP reading and data extraction
  models.py      data structures
  analysis.py    summary and HTTP transactions
  ai_helper.py   AI questions over the extracted data
```

## Setup (Windows)

```
git clone https://github.com/razmaliah/networks-ex1.git
cd networks-ex1
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Then put the API key in `.env` (never commit it).

## Run

```
streamlit run dashboard/app.py
```
