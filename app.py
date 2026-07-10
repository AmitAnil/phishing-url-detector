"""
app.py
------
Main Streamlit entry-point for the Phishing URL Detection dashboard.
Run with:  streamlit run app.py
"""

import streamlit as st

import database
import report
import scanner
import utils

# --------------------------------------------------------------------------
# Page configuration (must be the first Streamlit call)
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="Phishing URL Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------------------------------
# Session state defaults
# --------------------------------------------------------------------------
defaults = {
    "theme": "dark",
    "manual_api_key": "",
    "last_scan": None,
    "page": "Scanner",
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

database.init_db()
utils.load_css(st.session_state["theme"])

# --------------------------------------------------------------------------
# Sidebar — navigation, API key, theme toggle
# --------------------------------------------------------------------------
with st.sidebar:
    from pathlib import Path
    logo_path = Path(__file__).parent / "assets" / "logo.png"
    if logo_path.exists():
        st.image(str(logo_path), use_container_width=True)
    else:
        st.markdown("<h1 style='text-align:center;'>🛡️</h1>", unsafe_allow_html=True)

    st.markdown("### Control Panel")
    st.session_state["page"] = st.radio(
        "Navigation", ["Scanner", "History", "About"], label_visibility="collapsed"
    )

    st.divider()
    st.markdown("**🌗 Theme**")
    light_mode = st.toggle("Light mode", value=(st.session_state["theme"] == "light"))
    st.session_state["theme"] = "light" if light_mode else "dark"

    st.divider()
    st.markdown("**🔑 VirusTotal API Key**")
    st.session_state["manual_api_key"] = st.text_input(
        "API Key",
        value=st.session_state["manual_api_key"],
        type="password",
        placeholder="Paste your VirusTotal API key",
        help="Kept only for this session. For production, use st.secrets or the VT_API_KEY env variable.",
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("Built with Streamlit • Secured by VirusTotal")


# --------------------------------------------------------------------------
# Reusable UI components
# --------------------------------------------------------------------------
def render_card(icon: str, title: str, value_html: str) -> str:
    return f"""
    <div class="glass-card">
        <div class="card-icon">{icon}</div>
        <div class="card-title">{title}</div>
        <div class="card-value">{value_html}</div>
    </div>
    """


def render_copy_button(text: str) -> None:
    safe_text = text.replace("\\", "\\\\").replace("'", "\\'")
    st.markdown(
        f"""
        <button class="copy-btn" onclick="navigator.clipboard.writeText('{safe_text}');
            this.innerText='✅ Copied!'; setTimeout(()=>{{this.innerText='📋 Copy URL'}}, 1500);">
            📋 Copy URL
        </button>
        """,
        unsafe_allow_html=True,
    )


def render_loading_animation(placeholder) -> None:
    placeholder.markdown(
        """
        <div class="scan-loader">
            Scanning target URL, please wait
            <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_footer() -> None:
    st.markdown(
        """
        <div class="app-footer">
            🛡️ Phishing URL Detection System &nbsp;|&nbsp; Created by: <span>Amit Anil</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# PAGE: Scanner (Home + Results)
# --------------------------------------------------------------------------
def scanner_page() -> None:
    st.markdown('<div class="hero-title">🛡️ Phishing URL Detection System</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="hero-subtitle">Detect malicious URLs using AI-assisted heuristics and VirusTotal.</div>',
        unsafe_allow_html=True,
    )

    _, mid, _ = st.columns([1, 3, 1])
    with mid:
        url_input = st.text_input(
            "url", placeholder="Enter Website URL", label_visibility="collapsed", key="url_box"
        )
        scan_clicked = st.button("🔍 Scan URL", use_container_width=True)

    if scan_clicked:
        if not url_input.strip():
            st.warning("Please enter a URL to scan.")
            return

        loader = st.empty()
        render_loading_animation(loader)

        api_key = st.session_state["manual_api_key"] or utils.get_api_key()
        scan_result = scanner.perform_full_scan(url_input.strip(), api_key)

        loader.empty()
        database.save_scan(scan_result)
        st.session_state["last_scan"] = scan_result

    if st.session_state["last_scan"]:
        render_results