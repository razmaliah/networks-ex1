"""PCAP analysis dashboard (Streamlit). Run with:  streamlit run dashboard/app.py"""

from __future__ import annotations

import time
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
# Hebrew UI: the whole page is right-to-left (so columns, buttons and labels start from the right),
# while data views (tables, charts, code, sliders) stay left-to-right.
st.markdown(
    """<style>
    [data-testid="stMain"], [data-testid="stMainBlockContainer"], section.main {direction: rtl;}
    h1, h2, h3, h4, [data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"], [data-testid="stCaptionContainer"] {
        text-align: right;
    }
    [data-testid="stDataFrame"], [data-testid="stPlotlyChart"], .stPlotlyChart, [data-testid="stJson"], code, pre,
    [data-testid="stSlider"] [data-baseweb="slider"], [data-testid="stSlider"] [data-baseweb="slider"] * {
        direction: ltr; text-align: left;
    }
    [data-testid="stTabs"] [role="tablist"] {justify-content: flex-start;}
    /* typed text: each line gets its direction from its first letters (Hebrew right-to-left, English left-to-right) */
    textarea, input[type="text"] {unicode-bidi: plaintext; text-align: start;}
    input[type="password"] {direction: ltr;}
    .st-key-new_conversation {direction: ltr;}
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
        version_label = st.radio("גרסת IP", ["IPv4 + IPv6", "IPv4 בלבד", "IPv6 בלבד"], key="ip_version")
        top_n = st.slider("כמה כתובות להציג", 5, 30, 10, key="ip_top")
        metric = st.radio("מדד", ["חבילות", "בתים"], horizontal=True, key="ip_metric")
    direction = {"הכל": "both", "מקור (Source)": "src", "יעד (Destination)": "dst"}[mode]
    version = {"IPv4 + IPv6": None, "IPv4 בלבד": 4, "IPv6 בלבד": 6}[version_label]
    ips = pd.DataFrame(ip_stats(analysis.packets, direction, version))
    with right:
        if ips.empty:
            st.info("אין תעבורת IP מהסוג שנבחר בהקלטה.")
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
    render_response_times(table)
    st.subheader("רשימת הטרנזקציות")
    st.caption(f"{len(table)} טרנזקציות (זוגות בקשה–תגובה). לחצו על שורה לפרטים מלאים.")
    event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row", key="transactions")
    rows = event.selection.rows
    if rows and rows[0] < len(table):
        st.divider()
        render_transaction(analysis, analysis.transactions[rows[0]])


def render_response_times(table: pd.DataFrame) -> None:
    """Response time of every transaction that got a response, plus summary numbers."""
    st.subheader("זמני תגובה")
    times = table.dropna(subset=["Response time (ms)"])
    if times.empty:
        st.info("לא נקלטו תגובות, ולכן אין זמני תגובה להציג.")
        return
    column = times["Response time (ms)"]
    slowest = times.loc[column.idxmax()]
    cols = st.columns(4)
    cols[0].metric("ממוצע", f"{column.mean():,.1f} ms")
    cols[1].metric("חציון", f"{column.median():,.1f} ms")
    cols[2].metric("מינימום", f"{column.min():,.1f} ms")
    cols[3].metric("מקסימום", f"{column.max():,.1f} ms", help=f"טרנזקציה {slowest['#']}: {slowest['Method']} {slowest['URI']}")

    chart = times.assign(Host=times["Host"].fillna("(ללא Host)"), Transaction=times["#"].astype(str))
    fig = px.bar(chart, x="Transaction", y="Response time (ms)", color="Host",
                 hover_data=["Method", "URI", "Status", "Request frame", "Response frame"],
                 labels={"Transaction": "טרנזקציה", "Response time (ms)": "זמן תגובה (ms)"})
    fig.add_hline(y=column.median(), line_dash="dot", annotation_text="חציון")
    fig.update_xaxes(type="category")
    fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10}, legend_title_text="Host")
    st.plotly_chart(fig, width="stretch")
    st.caption("זמן תגובה = הזמן מהחבילה שהשלימה את הבקשה ועד החבילה שהשלימה את התגובה (כמו http.time ב-Wireshark).")


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

def render_ai_answer(analysis: CaptureAnalysis, asked: str, answer) -> None:
    with st.container(border=True):
        st.caption(f"{answer.provider} · {answer.model} · {answer.elapsed_s:.1f} s")
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


def render_ai(analysis: CaptureAnalysis) -> None:
    st.markdown("שאלו שאלה חופשית על ההקלטה. ל-AI נשלחים **רק הנתונים שחולצו** (סיכום, סטטיסטיקות, "
                "שמות דומיין וטרנזקציות HTTP), ולא קובץ ה-PCAP עצמו.")
    provider = st.radio("ספק AI", list(ai_helper.PROVIDERS), horizontal=True, key="ai_provider",
                        format_func=lambda p: ai_helper.PROVIDERS[p]["label"])
    settings = ai_helper.PROVIDERS[provider]
    api_key = ai_helper.api_key_from_env(provider)
    if api_key:
        st.success(f"נמצא מפתח {settings['env_key']} בקובץ .env.")
    else:
        st.info(f"לא נמצא {settings['env_key']} בקובץ .env. כדי לשמור מפתח קבוע, הוסיפו לקובץ .env את השורה "
                f"`{settings['env_key']}=...` והפעילו מחדש את הדשבורד. אפשר גם להזין מפתח כאן לסשן הנוכחי בלבד "
                f"(הוא לא נשמר). יצירת מפתח: {settings['key_url']}")
        api_key = st.text_input(f"{settings['label']} API key", type="password", key=f"api_key_{provider}")

    model = render_model_picker(provider, api_key)

    conversation = [entry for entry in st.session_state.setdefault("ai_history", []) if entry[0] == analysis.file_name]
    for _file, asked, answer in conversation:
        render_ai_answer(analysis, asked, answer)

    toggle_column, button_column = st.columns([3, 1])  # right-to-left page: the first column is on the right
    follow_up = toggle_column.toggle("שאלת המשך: ה-AI רואה את השאלות והתשובות הקודמות", value=True, key="ai_follow_up",
                            disabled=not conversation)
    if button_column.button("שיחה חדשה", disabled=not conversation, key="new_conversation"):
        st.session_state["ai_history"] = [e for e in st.session_state["ai_history"] if e[0] != analysis.file_name]
        st.rerun()

    question = st.text_area("השאלה שלך", placeholder="למשל: לאילו אתרים נשלחו בקשות HTTP, ומה היה זמן התגובה הארוך ביותר?",
                            key="ai_question")
    if st.button("שלח שאלה", type="primary", disabled=not question.strip() or not api_key):
        status = st.status(f"שולח ל-{settings['label']}...", expanded=True)
        started = time.monotonic()

        def show_progress(text: str) -> None:
            status.write(f"`{time.monotonic() - started:5.1f}s`  {text}")

        history = [(asked, answer.raw_text) for _f, asked, answer in conversation] if follow_up else []
        try:
            answer = ai_helper.ask(question.strip(), analysis, provider=provider, api_key=api_key, model=model,
                                   on_progress=show_progress, history=history)
            status.update(label=f"התקבלה תשובה אחרי {answer.elapsed_s:.1f} שניות", state="complete", expanded=False)
            st.session_state["ai_history"].append((analysis.file_name, question.strip(), answer))
            st.rerun()  # show the new answer at the end of the conversation, above the question box
        except Exception as error:  # network, authentication or quota errors are shown, not raised
            status.update(label=f"נכשל אחרי {time.monotonic() - started:.1f} שניות", state="error", expanded=True)
            st.error(f"השאלה נכשלה: {error}")

    with st.expander("הנתונים שנשלחים ל-AI"):
        st.json(ai_helper.build_context(analysis), expanded=False)


@st.cache_data(ttl=3600, show_spinner="טוען את רשימת המודלים של Gemini...")
def cached_gemini_models(api_key: str) -> list[str]:
    return ai_helper.list_gemini_models(api_key)


def render_model_picker(provider: str, api_key: str | None) -> str:
    """Gemini: choose from the models this key can really use. Claude: a model name with a sensible default."""
    if provider == "gemini" and api_key:
        try:
            names = cached_gemini_models(api_key)
        except Exception as error:
            st.warning(f"לא הצלחתי לטעון את רשימת המודלים ({error}). אפשר להקליד שם מודל ידנית.")
            names = []
        if names:
            default = ai_helper.pick_gemini_default(names)
            return st.selectbox("מודל", names, index=names.index(default) if default in names else 0, key="gemini_model")
    return st.text_input("מודל", value=ai_helper.default_model(provider), key=f"model_{provider}")


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
