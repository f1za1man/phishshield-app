import streamlit as st
import requests
import re
from openai import OpenAI

# 🔑 Load secrets from Streamlit Cloud
client = OpenAI(api_key=st.secrets["OPENAI_KEY"])
VT_KEY = st.secrets["VT_KEY"]
ABUSE_KEY = st.secrets["ABUSE_KEY"]

# -------------------------------
# 🛠 IOC Extraction
# -------------------------------
def extract_iocs(text):
    urls = re.findall(r'https?://[^\s]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    return urls, ips

# -------------------------------
# 🌐 VirusTotal Scan
# -------------------------------
def vt_scan(url):
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# -------------------------------
# 🖥 AbuseIPDB Scan
# -------------------------------
def abuse_scan(ip):
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            headers=headers,
            timeout=10
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# -------------------------------
# 🧠 Rule-Based Phishing Engine
# -------------------------------
def rule_engine(email):
    score = 0
    reasons = []

    keywords = [
        "urgent", "verify", "locked", "suspended", "confirm",
        "immediately", "security alert", "unusual activity",
        "account", "click", "login"
    ]

    for k in keywords:
        if k in email.lower():
            score += 8
            reasons.append(f"Suspicious keyword detected: '{k}'")

    brands = ["ubl", "microsoft", "google", "paypal", "dhl", "fedex"]
    for b in brands:
        if b in email.lower() and f"{b}.com" not in email.lower():
            score += 25
            reasons.append(f"Possible brand impersonation: {b.upper()}")

    if "http://" in email.lower():
        score += 15
        reasons.append("Insecure (HTTP) link detected")

    return score, reasons

# -------------------------------
# 🎨 Streamlit UI
# -------------------------------
st.set_page_config(page_title="PhishShield", layout="centered")
st.title("🛡 PhishShield – SOC Phishing Investigation Tool")

email = st.text_area("📩 Paste suspicious email content below:")

if st.button("🔍 Analyze Email") and email.strip():

    urls, ips = extract_iocs(email)

    # 🧠 Rule Engine
    rule_score, reasons = rule_engine(email)
    score = rule_score

    st.subheader("🧠 Behavioral & Rule-Based Detection")
    for r in reasons:
        st.warning(r)

    # 🤖 AI Analysis
    st.subheader("🤖 AI Analysis")
    try:
        ai = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": f"Is this a phishing email? Explain clearly:\n{email}"}
            ]
        )
        st.write(ai.choices[0].message.content)
    except Exception as e:
        st.error(f"AI analysis unavailable: {e}")

    # 🌐 URL Threat Intel
    if urls:
        st.subheader("🌐 URL Threat Intelligence")
        for u in urls:
            res = vt_scan(u)
            if "error" in res:
                st.warning(f"Error scanning {u}: {res['error']}")
            else:
                st.write("Scanned:", u)
                score += 20

    # 🖥 IP Reputation
    if ips:
        st.subheader("🖥 IP Reputation")
        for ip in ips:
            res = abuse_scan(ip)
            if "error" in res:
                st.warning(f"Error scanning {ip}: {res['error']}")
            else:
                abuse_score = int(res.get("data", {}).get("abuseConfidenceScore", 0))
                st.write(ip, f"Abuse Score: {abuse_score}%")
                score += abuse_score

    # 📊 Final Risk Score
    st.subheader("📊 Final Risk Score")
    st.progress(min(score, 100))

    if score > 60:
        st.error("🚨 HIGH RISK – Phishing Detected")
    elif score > 30:
        st.warning("⚠️ MEDIUM RISK – Suspicious Email")
    else:
        st.success("✅ LOW RISK – Likely Safe")
