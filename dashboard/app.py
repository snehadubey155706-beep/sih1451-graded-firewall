import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from dlp_matcher import load_registry, scan_payload, block_transfer_and_log

st.set_page_config(page_title="Sentinel — Graded Response Firewall", layout="wide", page_icon="🛡️")

# ---------------- STYLING ----------------
st.markdown("""
<style>
.stApp { background-color: #0b0f14; color: #e6edf3; }
.metric-card {
    background: #131a21; border: 1px solid #1f2833; border-radius: 12px;
    padding: 18px; text-align: center;
}
.metric-value { font-size: 32px; font-weight: 700; margin: 0; }
.metric-label { font-size: 13px; color: #8b949e; margin: 0; }
.tier-badge {
    display: inline-block; padding: 3px 12px; border-radius: 20px;
    font-size: 12px; font-weight: 600; white-space: nowrap;
}
.tier-monitor { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
.tier-supervise { background: rgba(210, 153, 34, 0.15); color: #d29922; }
.tier-high_alert { background: rgba(248, 81, 73, 0.15); color: #f85149; }
.incident-card {
    background: #1a1015; border: 1px solid #f85149; border-radius: 12px;
    padding: 16px 20px; margin-bottom: 12px;
}
.section-header { margin-top: 8px; margin-bottom: 4px; }
.subtitle { color: #8b949e; font-size: 14px; }
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
header_l, header_r = st.columns([5, 1])
with header_l:
    st.title("🛡️ Sentinel — Graded Response Firewall")
    st.caption("Non-IoC behavioral detection · Honeypot deception · Selective DLP blocking")
with header_r:
    st.write("")
    if st.button("🔄 Reset demo data", use_container_width=True):
        if os.path.exists("data/incidents.json"):
            os.remove("data/incidents.json")
        st.cache_data.clear()
        st.success("Demo data cleared.")
        st.rerun()

# ---------------- LOAD MODEL PIECES ----------------
@st.cache_resource
def load_pieces():
    model = joblib.load("models/baseline_isolation_forest.pkl")
    scaler = joblib.load("models/scaler.pkl")
    features = joblib.load("models/feature_list.pkl")
    return model, scaler, features

model, scaler, FEATURES = load_pieces()
LOG_COLS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

TIER_1, TIER_2 = 25, 45


@st.cache_data
def score_sessions(csv_path, sample_size=4000):
    df_raw = pd.read_csv(csv_path)
    df_raw.columns = df_raw.columns.str.strip()
    keep = FEATURES + (["Label"] if "Label" in df_raw.columns else [])
    df_raw = df_raw[keep].copy()
    df_raw = df_raw.replace([np.inf, -np.inf], np.nan).dropna()
    if len(df_raw) > sample_size:
        df_raw = df_raw.sample(sample_size, random_state=1).reset_index(drop=True)

    df = df_raw[FEATURES].copy()
    for col in LOG_COLS:
        df[col] = np.log1p(df[col].clip(lower=0))
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df_raw = df_raw.loc[df.index].reset_index(drop=True)
    df = df.reset_index(drop=True)

    X_scaled = scaler.transform(df[FEATURES])
    raw_scores = model.decision_function(X_scaled)
    sus = 100 * (raw_scores.max() - raw_scores) / (raw_scores.max() - raw_scores.min())

    df_raw["sus_score"] = sus
    df_raw["tier"] = pd.cut(sus, bins=[-1, TIER_1, TIER_2, 101],
                             labels=["MONITOR", "SUPERVISE", "HIGH_ALERT"])
    df_raw["session_id"] = ["SESS-" + str(i).zfill(5) for i in range(len(df_raw))]
    rng = np.random.default_rng(7)
    df_raw["source_ip"] = [
        f"10.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
        for _ in range(len(df_raw))
    ]
    return df_raw


DATA_FILE = "data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
sessions = score_sessions(DATA_FILE)

# ---------------- TOP METRICS ----------------
tier_counts = sessions["tier"].value_counts()

if os.path.exists("data/incidents.json"):
    with open("data/incidents.json") as f:
        incident_count = len(json.load(f))
else:
    incident_count = 0

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f'<div class="metric-card"><p class="metric-value">{len(sessions)}</p><p class="metric-label">Sessions monitored</p></div>', unsafe_allow_html=True)
with c2:
    st.markdown(f'<div class="metric-card"><p class="metric-value" style="color:#d29922">{tier_counts.get("SUPERVISE",0)}</p><p class="metric-label">Under supervision</p></div>', unsafe_allow_html=True)
with c3:
    st.markdown(f'<div class="metric-card"><p class="metric-value" style="color:#f85149">{tier_counts.get("HIGH_ALERT",0)}</p><p class="metric-label">High alert</p></div>', unsafe_allow_html=True)
with c4:
    st.markdown(f'<div class="metric-card"><p class="metric-value" style="color:#f85149">{incident_count}</p><p class="metric-label">Data-theft attempts blocked</p></div>', unsafe_allow_html=True)

st.write("")

# ---------------- LIVE SESSIONS + DEMO TRIGGER ----------------
left, right = st.columns([1.4, 1])

with left:
    st.markdown('<h3 class="section-header">Live sessions</h3>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Ranked by suspicion score, highest first</p>', unsafe_allow_html=True)
    top = sessions.sort_values("sus_score", ascending=False).head(15)
    for _, row in top.iterrows():
        tier_class = f'tier-{row["tier"].lower()}'
        cols = st.columns([2, 1, 4, 1.3])
        cols[0].write(row["source_ip"])
        cols[1].write(f'{row["sus_score"]:.0f}%')
        cols[2].progress(min(int(row["sus_score"]), 100))
        cols[3].markdown(f'<span class="tier-badge {tier_class}">{row["tier"]}</span>', unsafe_allow_html=True)

with right:
    st.markdown('<h3 class="section-header">🎯 Live demo trigger</h3>', unsafe_allow_html=True)
    st.write("Simulate an attacker attempting to exfiltrate data through a supervised session.")

    if st.button("▶ Simulate data-theft attempt", type="primary", use_container_width=True):
        registry = load_registry()
        with st.spinner("Attacker exploring supervised session..."):
            time.sleep(1.2)

        rng = np.random.default_rng()
        fake_card = rng.choice(registry["card_numbers"])
        fake_email = rng.choice(registry["emails"])
        fake_payload = f"""
        Uploading extracted data...
        contact: {fake_email}
        card: {fake_card}
        """
        matches = scan_payload(fake_payload, registry)
        if matches:
            source_ip = f"203.0.113.{rng.integers(1,254)}"
            incident = block_transfer_and_log(
                session_id="LIVE-DEMO-" + str(int(time.time() * 1000))[-8:],
                source_ip=source_ip,
                matches=matches,
                sus_score=round(float(rng.uniform(80, 95)), 1),
            )
            st.error(f"🚨 Sensitive data transfer blocked from {source_ip}")
            st.success("Connection kept alive — attacker unaware. Evidence captured.")
            st.rerun()
        else:
            st.info("No sensitive data detected.")

    st.write("")
    st.markdown('<p class="subtitle">Every click simulates a fresh attacker session with a new IP and a different honeytoken caught in the act.</p>', unsafe_allow_html=True)

# ---------------- INCIDENT CASE FILES ----------------
st.markdown('<h3 class="section-header">📁 Incident case files</h3>', unsafe_allow_html=True)

if os.path.exists("data/incidents.json"):
    with open("data/incidents.json") as f:
        incidents = json.load(f)
else:
    incidents = []

if incidents:
    for inc in reversed(incidents[-5:]):
        match_lines = "".join(
            f"<br>&nbsp;&nbsp;• <b>{m['type']}</b>: {m['value_redacted']}" for m in inc["matches"]
        )
        sus = f' | <b>Suspicion score</b> {inc["sus_score"]}%' if inc.get("sus_score") is not None else ""
        st.markdown(f"""
        <div class="incident-card">
            <b>Case</b> {inc['session_id']} &nbsp;|&nbsp; <b>Source</b> {inc['source_ip']} &nbsp;|&nbsp; <b>Time</b> {inc['timestamp']}{sus}
            <br><b>Action:</b> Transfer blocked, session kept alive for observation
            <br><b>Evidence:</b>{match_lines}
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No incidents yet — click 'Simulate data-theft attempt' to generate one.")

st.write("")
st.caption("SIH1451 · Team Sentinel · Non-IoC behavioral compromise detection")