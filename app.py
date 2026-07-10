
import streamlit as st
import database
import scanner
import utils
import report

st.set_page_config(page_title="Phishing URL Detection System", page_icon="🛡️", layout="wide")

if "theme" not in st.session_state:
    st.session_state.theme="dark"
if "manual_api_key" not in st.session_state:
    st.session_state.manual_api_key=""
if "last_scan" not in st.session_state:
    st.session_state.last_scan=None

database.init_db()
utils.load_css(st.session_state.theme)

with st.sidebar:
    st.title("🛡️ Control Panel")
    page=st.radio("Navigation",["Scanner","History","About"])
    st.session_state.theme="light" if st.toggle("Light mode",value=st.session_state.theme=="light") else "dark"
    st.session_state.manual_api_key=st.text_input("VirusTotal API Key",type="password",value=st.session_state.manual_api_key)

def render_results(scan):
    st.success(f"Verdict: {scan.get('verdict')}")
    c1,c2,c3=st.columns(3)
    c1.metric("Risk Score",scan.get("risk_score"))
    c2.metric("Risk Level",scan.get("risk_level"))
    c3.metric("HTTPS","Yes" if scan.get("https") else "No")
    st.plotly_chart(utils.build_gauge(scan.get("risk_score",0)),use_container_width=True)
    st.subheader("Domain")
    st.json({
        "Registered Domain":scan.get("registered_domain"),
        "Domain":scan.get("domain"),
        "Suffix":scan.get("suffix"),
        "Subdomain":scan.get("subdomain")
    })
    st.subheader("WHOIS")
    st.json(scan.get("whois",{}))
    st.subheader("VirusTotal")
    st.json(scan.get("virustotal",{}))
    pdf=report.generate_pdf_report(scan)
    csv=report.generate_csv_report(scan)
    a,b=st.columns(2)
    with a:
        st.download_button("Download PDF",pdf,"report.pdf","application/pdf")
    with b:
        st.download_button("Download CSV",csv,"report.csv","text/csv")

def scanner_page():
    st.title("🛡️ Phishing URL Detection System")
    url=st.text_input("Enter URL")
    if st.button("Scan URL"):
        if not url.strip():
            st.warning("Enter a URL.")
        else:
            api=st.session_state.manual_api_key or utils.get_api_key()
            with st.spinner("Scanning..."):
                result=scanner.perform_full_scan(url.strip(),api)
            database.save_scan(result)
            st.session_state.last_scan=result
    if st.session_state.last_scan:
        render_results(st.session_state.last_scan)

def history_page():
    st.title("History")
    rows=database.get_history()
    if not rows:
        st.info("No history.")
        return
    st.dataframe(rows,use_container_width=True)
    if st.button("Clear History"):
        database.clear_history()
        st.success("History cleared")
        st.rerun()

def about_page():
    st.title("About")
    st.markdown("""
### Phishing URL Detection System

Features:
- URL Validation
- WHOIS
- VirusTotal
- Risk Score
- PDF & CSV Reports
- SQLite History

Created by Amit Anil.
""")

if page=="Scanner":
    scanner_page()
elif page=="History":
    history_page()
else:
    about_page()

st.markdown("---")
st.caption("🛡️ Phishing URL Detection System • Created by Amit Anil")
