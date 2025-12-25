import streamlit as st
import requests, re
from openai import OpenAI

# Load keys from Streamlit Secrets
client = OpenAI(api_key=st.secrets["OPENAI_KEY"])
VT = st.secrets["VT_KEY"]
ABUSE = st.secrets["ABUSE_KEY"]

def extract_iocs(text):
    urls = re.findall(r'https?://[^\s]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    return urls, ips

def vt_scan(url):
    headers = {"x-apikey": VT}
    r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    return r.json()

def abuse_scan(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSE, "Accept": "application/json"}
    return requests.get(url, headers=headers).json()

st.set_page_config(page_title="PhishShield", layout="centered")
st.title("🛡 PhishShield – SOC Phishing Investigation Tool")

email = st.text_area("Paste suspicious email")

if st.button("Analyze"):

    urls, ips = extract_iocs(email)

    st.subheader("🤖 AI Analysis")
    ai = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Is this a phishing email? Explain:\n{email}"}]
    )
    st.write(ai.choices[0].message.content)

    score = 0

    st.subheader("🌐 URL Threat Intel")
    for u in urls:
        res = vt_scan(u)
        st.write("Scanned:", u)
        score += 20

    st.subheader("🖥 IP Reputation")
    for ip in ips:
        res = abuse_scan(ip)
        st.write(ip, res["data"]["abuseConfidenceScore"])
        score += int(res["data"]["abuseConfidenceScore"])

    st.subheader("📊 Final Risk Score")
    st.progress(min(score, 100))

    if score > 60:
        st.error("🚨 HIGH RISK – Phishing Detected")
    else:
        st.success("Low or Medium Risk")
