"""PCAP analysis dashboard (Streamlit). Run with:  streamlit run dashboard/app.py"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

import ai_helper
from analysis import analyze, ip_stats, packets_per_second, protocol_stats, relative_time, resolved_names
from models import CaptureAnalysis, Packet
from pcap_reader import CaptureFormatError

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

st.set_page_config(page_title="PCAP Dashboard", page_icon="📡", layout="wide")
st.markdown(
    """<style>
    [data-testid="stMarkdownContainer"], h1, h2, h3, .stAlert, [data-testid="stWidgetLabel"],
    [data-testid="stMetric"], [data-baseweb="tab-list"], .stRadio, .stCheckbox {direction: rtl; text-align: right;}
    code, pre {direction: ltr; text-align: left;}
    </style>""",
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="מנתח את ההקלטה...", max_entries=3)
def load_capture(data: bytes, file_name: str) -> CaptureAnalysis:
    return analyze(data, file_name)


def fmt_time(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S.%f") if ts is not None else "-"


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024


# ---------------------------------------------------------------- summary tab

def render_summary(analysis: CaptureAnalysis) -> None:
    s = analysis.summary
    cols = st.columns(5)
    cols[0].metric("מספר חבילות", f"{s.packet_count:,}")
    cols[1].metric("משך ההקלטה", f"{s.duration:,.3f} שניות")
    cols[2].metric("נפח כולל", fmt_bytes(s.total_bytes))
    cols[3].metric("טרנזקציות HTTP", len(analysis.transactions))
    cols[4].metric("כתובות IP שונות", len(ip_stats(analysis.packets, "both")))
    st.markdown(f"**חבילה ראשונה:** `{fmt_time(s.start_time)}`  \n**חבילה אחרונה:** `{fmt_time(s.end_time)}`")

    st.subheader("כתובות IP עיקריות")
    left, right = st.columns([1, 3])
    with left:
        mode = st.radio("פילוח לפי", ["הכל", "מקור (Source)", "יעד (Destination)"], key="ip_mode")
        top_n = st.slider("כמה כתובות להציג", 5, 30, 10, key="ip_top")
        metric = st.radio("מדד", ["חבילות", "בתים"], horizontal=True, key="ip_metric")
    direction = {"הכל": "both", "מקור (Source)": "src", "יעד (Destination)": "dst"}[mode]
    ips = pd.DataFrame(ip_stats(analysis.packets, direction))
    with right:
        if ips.empty:
            st.info("אין תעבורת IP בהקלטה.")
        else:
            column = "packets" if metric == "חבילות" else "bytes"
            top = ips.sort_values(column, ascending=False).head(top_n)
            fig = px.bar(top, x=column, y="ip", orientation="h", text=column, color=column,
                         color_continuous_scale="Blues", labels={"ip": "כתובת IP", column: metric})
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, coloraxis_showscale=False,
                              height=max(300, 32 * len(top)), margin={"l": 10, "r": 10, "t": 10, "b": 10})
            st.plotly_chart(fig, width="stretch")
    with st.expander("טבלת כל הכתובות"):
        st.dataframe(ips.rename(columns={"ip": "IP", "packets": "חבילות", "bytes": "בתים"}), hide_index=True, width="stretch")

    st.subheader("פרוטוקולים עיקריים")
    protocols = pd.DataFrame(protocol_stats(analysis.packets))
    fig = px.bar(protocols, x="protocol", y="packets", text="packets", color="protocol",
                 labels={"protocol": "פרוטוקול", "packets": "חבילות"},
                 color_discrete_sequence=px.colors.qualitative.Bold)
    fig.update_traces(textposition="outside")
    fig.update_layout(showlegend=False, margin={"l": 10, "r": 10, "t": 30, "b": 10})
    st.plotly_chart(fig, width="stretch")
    st.caption("הפרוטוקול של כל חבילה הוא השכבה הגבוהה ביותר שזוהתה, כמו בעמודת Protocol ב-Wireshark.")

    st.subheader("חבילות לאורך זמן")
    timeline = pd.DataFrame(packets_per_second(analysis.packets))
    if not timeline.empty:
        fig = px.area(timeline, x="second", y="packets", labels={"second": "שניות מתחילת ההקלטה", "packets": "חבילות לשנייה"})
        fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10})
        st.plotly_chart(fig, width="stretch")

    names = pd.DataFrame(resolved_names(analysis.packets))
    if not names.empty:
        st.subheader("שמות דומיין שזוהו (DNS / TLS SNI)")
        st.dataframe(names.rename(columns={"name": "שם", "addresses": "כתובות", "sources": "מקור", "first_frame": "Frame ראשון"}),
                     hide_index=True, width="stretch")


# ---------------------------------------------------------------- packets tab

def render_packets(analysis: CaptureAnalysis) -> None:
    left, right = st.columns([1, 2])
    http_only = left.toggle("הצג רק תעבורת HTTP", key="http_only")
    ip_filter = right.text_input("סינון לפי כתובת IP (אופציונלי)", key="ip_filter").strip()

    packets = analysis.packets
    if http_only:
        packets = [p for p in packets if p.protocol == "HTTP"]
    if ip_filter:
        packets = [p for p in packets if ip_filter in (p.src_ip or "") or ip_filter in (p.dst_ip or "")]

    table = pd.DataFrame([{
        "No.": p.number,
        "Time": round(relative_time(analysis, p), 6),
        "Source": p.src_ip or p.src_mac or "",
        "Destination": p.dst_ip or p.dst_mac or "",
        "Protocol": p.protocol,
        "Length": p.length,
        "Info": p.info,
    } for p in packets])
    st.caption(f"מוצגות {len(table):,} חבילות. לחצו על שורה כדי לראות את פרטי החבילה.")
    if table.empty:
        st.info("אין חבילות שמתאימות לסינון.")
        return

    event = st.dataframe(table, hide_index=True, width="stretch", height=420, on_select="rerun",
                         selection_mode="single-row", key=f"packets_{http_only}_{ip_filter}")
    rows = event.selection.rows
    if rows and rows[0] < len(table):
        render_packet_details(analysis, analysis.packets[int(table.iloc[rows[0]]["No."]) - 1])


def render_packet_details(analysis: CaptureAnalysis, packet: Packet) -> None:
    st.divider()
    st.subheader(f"פרטי חבילה {packet.number}")
    rows = {
        "Frame": packet.number,
        "Time (relative)": f"{relative_time(analysis, packet):.6f} s",
        "Arrival time": fmt_time(packet.timestamp),
        "Length": f"{packet.length} bytes",
        "Source MAC": packet.src_mac,
        "Destination MAC": packet.dst_mac,
        "IP version": packet.ip_version,
        "Source IP": packet.src_ip,
        "Destination IP": packet.dst_ip,
        "TTL / Hop limit": packet.ttl,
        "Transport": packet.transport,
        "Source port": packet.src_port,
        "Destination port": packet.dst_port,
        "TCP flags": ", ".join(packet.tcp_flags) or None,
        "TCP seq / ack": f"{packet.tcp_seq} / {packet.tcp_ack}" if packet.transport == "TCP" else None,
        "Payload length": len(packet.payload) if packet.transport in ("TCP", "UDP") else None,
        "Protocol": packet.protocol,
        "Info": packet.info,
    }
    st.table(pd.DataFrame([(k, str(v)) for k, v in rows.items() if v not in (None, "")], columns=["שדה", "ערך"]))

    if packet.dns:
        st.markdown("**DNS**")
        st.dataframe(pd.DataFrame(
            [{"סוג": "Query", "שם": n, "Type": t, "ערך": ""} for n, t in packet.dns.questions]
            + [{"סוג": "Answer", "שם": n, "Type": t, "ערך": v} for n, t, v in packet.dns.answers]), hide_index=True)
    if packet.tls_sni:
        st.markdown(f"**TLS Server Name (SNI):** `{packet.tls_sni}`")

    transaction = analysis.frame_to_transaction.get(packet.number)
    if transaction:
        render_transaction(analysis, transaction)
    elif packet.protocol == "TCP" and packet.payload:
        for tx in analysis.transactions:  # segment that belongs to a reassembled HTTP message
            for message in (tx.request, tx.response):
                if message and packet.number in message.frames:
                    st.info(f"החבילה היא מקטע של הודעת HTTP שהורכבה מהחבילות {message.frames} "
                            f"(טרנזקציה {tx.index}). פרטי ה-HTTP מוצגים בחבילה {message.last_frame}.")


# ---------------------------------------------------------------- HTTP transactions

def transactions_table(analysis: CaptureAnalysis) -> pd.DataFrame:
    return pd.DataFrame([{
        "#": tx.index,
        "Request frame": tx.request.last_frame,
        "Response frame": tx.response.last_frame if tx.response else None,
        "Method": tx.request.method,
        "Host": tx.host,
        "URI": tx.request.uri,
        "Status": tx.response.status_code if tx.response else None,
        "Response time (ms)": round(tx.response_time * 1000, 3) if tx.response else None,
        "Client": f"{tx.client_ip}:{tx.client_port}",
        "Server": f"{tx.server_ip}:{tx.server_port}",
    } for tx in analysis.transactions])


def render_transactions(analysis: CaptureAnalysis) -> None:
    if not analysis.transactions:
        st.info("לא נמצאו טרנזקציות HTTP בהקלטה (ייתכן שכל התעבורה מוצפנת ב-HTTPS).")
        return
    table = transactions_table(analysis)
    st.caption(f"{len(table)} טרנזקציות (זוגות בקשה–תגובה). לחצו על שורה לפרטים מלאים.")
    event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row", key="transactions")
    rows = event.selection.rows
    if rows and rows[0] < len(table):
        st.divider()
        render_transaction(analysis, analysis.transactions[rows[0]])


def render_transaction(analysis: CaptureAnalysis, tx) -> None:
    request, response = tx.request, tx.response
    st.markdown(f"#### טרנזקציית HTTP {tx.index}")
    fields = {
        "Method": request.method,
        "Host": tx.host,
        "URI": request.uri,
        "HTTP version": request.version,
        "Status": f"{response.status_code} {response.reason}" if response else "לא נקלטה תגובה",
        "Client IP : port": f"{tx.client_ip} : {tx.client_port}",
        "Server IP : port": f"{tx.server_ip} : {tx.server_port}",
        "Request frame": f"{request.last_frame}  (segments: {request.frames})",
        "Response frame": f"{response.last_frame}  (segments: {response.frames})" if response else "-",
        "Request time": f"{relative_time(analysis, request.timestamp):.6f} s",
        "Response time": f"{tx.response_time * 1000:.3f} ms" if response else "-",
        "User-Agent": request.header("User-Agent"),
        "Server header": (response.header("Server") or "לא קיים") if response else None,
        "Content-Type": response.header("Content-Type") if response else None,
        "Body size (request / response)": f"{request.body_wire_size} / {response.body_wire_size if response else '-'} bytes",
    }
    st.table(pd.DataFrame([(k, str(v)) for k, v in fields.items() if v is not None], columns=["שדה", "ערך"]))

    left, right = st.columns(2)
    with left:
        st.markdown("**בקשה**")
        st.code(_message_text(request), language="http")
    with right:
        st.markdown("**תגובה**")
        st.code(_message_text(response) if response else "(no response captured)", language="http")


def _message_text(message, body_limit: int = 3000) -> str:
    head = message.start_line + "\n" + "\n".join(f"{n}: {v}" for n, v in message.headers)
    if not message.body:
        return head
    content_type = (message.header("Content-Type") or "").lower()
    if any(t in content_type for t in ("text", "json", "xml", "javascript", "x-www-form-urlencoded")) or not content_type:
        body = message.body[:body_limit].decode("utf-8", "replace")
        suffix = f"\n... ({len(message.body) - body_limit} more bytes)" if len(message.body) > body_limit else ""
        return f"{head}\n\n{body}{suffix}"
    return f"{head}\n\n<{len(message.body)} bytes of {content_type}>"


# ---------------------------------------------------------------- AI tab

def render_ai(analysis: CaptureAnalysis) -> None:
    st.markdown("שאלו שאלה חופשית על ההקלטה. ל-AI נשלחים **רק הנתונים שחולצו** (סיכום, סטטיסטיקות, "
                "שמות דומיין וטרנזקציות HTTP), ולא קובץ ה-PCAP עצמו.")
    key_from_env = os.getenv("ANTHROPIC_API_KEY")
    api_key = key_from_env
    if not key_from_env:
        st.warning("לא נמצא ANTHROPIC_API_KEY בקובץ .env. אפשר להזין מפתח כאן לסשן הנוכחי בלבד (הוא לא נשמר).")
        api_key = st.text_input("API key", type="password", key="api_key")

    question = st.text_area("השאלה שלך", placeholder="למשל: לאילו אתרים נשלחו בקשות HTTP, ומה היה זמן התגובה הארוך ביותר?",
                            key="ai_question")
    if st.button("שלח שאלה", type="primary", disabled=not question.strip()):
        try:
            with st.spinner("שולח ל-AI..."):
                answer = ai_helper.ask(question.strip(), analysis, api_key=api_key)
            st.session_state.setdefault("ai_history", []).insert(0, (analysis.file_name, question.strip(), answer))
        except Exception as error:  # network, authentication or quota errors are shown, not raised
            st.error(f"השאלה נכשלה: {error}")

    for file_name, asked, answer in st.session_state.get("ai_history", []):
        if file_name != analysis.file_name:
            continue
        with st.container(border=True):
            st.markdown(f"**שאלה:** {asked}")
            st.markdown(f"**תשובה:** {answer.answer}")
            if answer.evidence:
                st.markdown("**ראיות:**")
                evidence = pd.DataFrame([
                    {**item, "קיים בהקלטה": "⚠️ לא קיים" if item.get("frame") in answer.invalid_frames else "✅"}
                    for item in answer.evidence
                ])
                st.dataframe(evidence, hide_index=True, width="stretch")
            if answer.invalid_frames:
                st.warning(f"ה-AI ציטט חבילות שלא קיימות בהקלטה: {answer.invalid_frames}. יש לבדוק את התשובה ידנית.")
            if answer.limitations:
                st.caption(f"מגבלות: {answer.limitations}")

    with st.expander("הנתונים שנשלחים ל-AI"):
        st.json(ai_helper.build_context(analysis), expanded=False)


# ---------------------------------------------------------------- main

def main() -> None:
    st.title("📡 ניתוח הקלטות רשת")
    uploaded = st.file_uploader("בחרו קובץ הקלטה (pcap / pcapng)", type=["pcap", "pcapng", "cap"])
    if uploaded is None:
        st.info("העלו קובץ הקלטה מ-Wireshark כדי להתחיל.")
        return
    try:
        analysis = load_capture(uploaded.getvalue(), uploaded.name)
    except CaptureFormatError as error:
        st.error(f"לא ניתן לקרוא את הקובץ: {error}")
        return
    if not analysis.packets:
        st.warning("הקובץ לא מכיל חבילות.")
        return

    summary_tab, packets_tab, http_tab, ai_tab = st.tabs(["סיכום", "חבילות", "טרנזקציות HTTP", "שאלה ל-AI"])
    with summary_tab:
        render_summary(analysis)
    with packets_tab:
        render_packets(analysis)
    with http_tab:
        render_transactions(analysis)
    with ai_tab:
        render_ai(analysis)


main()
