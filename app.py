import streamlit as st
from promptshield import check_prompt
from sentinelhawk import scan_email_or_link

# ThreatCostAI logic (built-in, no separate file)
def calculate_threat_cost(threat_type, target, severity):
    base_risk = {
        "Phishing": 30,
        "LLM Abuse": 40,
        "Ransomware": 60,
        "Data Leak": 50,
        "Other": 20
    }.get(threat_type, 20)

    target_multiplier = {
        "User": 1,
        "System": 1.5,
        "AI Model": 2,
        "Email Gateway": 1.2
    }.get(target, 1)

    risk_score = min(100, base_risk + (severity * target_multiplier / 100 * 60))
    estimated_loss = risk_score * 1000

    return round(risk_score), round(estimated_loss)

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="NeuroDefend Dashboard", page_icon="🧠", layout="wide")

st.title("🧠 NeuroDefend: AI-Powered Cyber Defense Suite")
st.markdown("A 3-in-1 tool to detect prompt injection, phishing emails, and estimate threat impact.")

# Tabs
tab1, tab2, tab3 = st.tabs(["🛡 PromptShield", "🦅 SentinelHawk", "💸 ThreatCostAI"])

# ---------------- Tab 1: PromptShield ----------------
with tab1:
    st.header("🛡 PromptShield – Prompt Injection Detector")
    user_input = st.text_area("Enter a user prompt to scan:")
    if st.button("Scan Prompt"):
        flagged, msg = check_prompt(user_input)
        st.warning(msg) if flagged else st.success(msg)

# ---------------- Tab 2: SentinelHawk ----------------
with tab2:
    st.header("🦅 SentinelHawk – Phishing Detection")
    email_input = st.text_area("Paste suspicious email content:")
    if st.button("Scan Email"):
        flagged, msg = scan_email_or_link(email_input)
        st.warning(msg) if flagged else st.success(msg)

# ---------------- Tab 3: ThreatCostAI ----------------
with tab3:
    st.header("💸 ThreatCostAI – Risk & Cost Estimator")
    threat_type = st.selectbox("Threat Type", ["Phishing", "LLM Abuse", "Ransomware", "Data Leak", "Other"])
    target = st.selectbox("Target Asset", ["User", "System", "AI Model", "Email Gateway"])
    severity = st.slider("Threat Severity", 0, 100, 50)

    if st.button("Calculate Threat Impact"):
        score, damage = calculate_threat_cost(threat_type, target, severity)
        st.metric("🔐 Risk Score", f"{score}/100")
        st.metric("💸 Estimated Financial Loss", f"${damage:,}")
