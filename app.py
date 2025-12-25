import streamlit as st
import requests
import re
from openai import OpenAI

# 🔑 Load secrets from Streamlit Cloud
client = OpenAI(api_key=st.secrets["OPENAI_KEY"])
VT_KEY = st.secrets["VT_KEY"]
ABUSE_KEY = st.secrets["ABUSE_KEY"]

# 🛠 IOC Extraction
def extract_iocs(text: str):
    urls = re.findall(r'https?://[^\s]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    return urls, ips

# 🌐 VirusTotal Scan
def vt_scan(url: str):
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# 🖥 AbuseIPDB Scan
def abuse_scan(ip: str):
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    try:
        r = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# 🎨 Streamlit UI
st.set_page_config(page_title="PhishShield", layout="centered")
st.title("🛡 PhishShield – SOC Phishing Investigation Tool")

email = st.text_area("📩 Paste suspicious email content below:")

if st.button("🔍 Analyze Email") and email.strip():

    urls, ips = extract_iocs(email)

    # 🤖 AI Analysis
    st.subheader("🤖 AI Analysis")
    try:
        ai = client.chat.completions.create(
            model="gpt-4o-mini",  # ✅ updated model name
            messages=[{"role": "user", "content": f"Is this a phishing email? Explain:\n{email}"}]
        )
        st.write(ai.choices[0].message.content)
    except Exception as e:
        st.error(f"AI analysis failed: {e}")

    score = 0

    # 🌐 URL Threat Intel
    if urls:
        st.subheader("🌐 URL Threat Intel")
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
                st.write(ip, res.get("data", {}).get("abuseConfidenceScore", "N/A"))
                score += int(res.get("data", {}).get("abuseConfidenceScore", 0))

    # 📊 Final Risk Score
    st.subheader("📊 Final Risk Score")
    st.progress(min(score, 100))

    if score > 60:
        st.error("🚨 HIGH RISK – Phishing Detected")
    elif score > 30:
        st.warning("⚠️ Medium Risk – Needs Review")
    else:
        st.success("✅ Low Risk – Likely Safe")

