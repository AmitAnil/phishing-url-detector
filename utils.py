"""
utils.py
--------
Shared helpers: CSS injection, secure API-key resolution, colour helpers,
and the animated Plotly risk gauge.
"""

import os
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

ASSETS_DIR = Path(__file__).parent / "assets"


def load_css(theme: str = "dark") -> None:
    """Injects the custom stylesheet and sets the active theme attribute."""
    css_path = ASSETS_DIR / "style.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    st.markdown(
        f"<script>document.documentElement.setAttribute('data-theme', '{theme}');</script>",
        unsafe_allow_html=True,
    )


def get_api_key() -> str:
    """
    Resolves the VirusTotal API key, in order of priority:
    1. Streamlit secrets (st.secrets["VT_API_KEY"])
    2. Environment variable VT_API_KEY
    3. Key typed into the sidebar (session state)
    Never hardcode a real key in source code.
    """
    try:
        if "VT_API_KEY" in st.secrets:
            return st.secrets["VT_API_KEY"]
    except Exception:
        pass

    env_key = os.getenv("VT_API_KEY")
    if env_key:
        return env_key

    return st.session_state.get("manual_api_key", "")


def risk_color(level: str) -> str:
    return {"Low Risk": "#00ff9d", "Medium Risk": "#ffd93d", "High Risk": "#ff4757"}.get(level, "#888")


def verdict_emoji(verdict: str) -> str:
    return {"SAFE": "🟢", "SUSPICIOUS": "🟡", "MALICIOUS": "🔴"}.get(verdict, "⚪")


def build_gauge(score: int, max_score: int = 10) -> go.Figure:
    """Builds the circular animated risk gauge (Plotly Indicator)."""
    if score >= 5:
        bar_color = "#ff4757"
    elif score >= 3:
        bar_color = "#ffd93d"
    else:
        bar_color = "#00ff9d"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 46, "color": "#e8f9ff"}},
            domain={"x": [0, 1], "y": [0, 1]},
            gauge={
                "axis": {"range": [0, max_score], "tickwidth": 1, "tickcolor": "#5ad1ff",
                          "tickfont": {"color": "#8fa5b6"}},
                "bar": {"color": bar_color, "thickness": 0.35},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 3], "color": "rgba(0,255,157,0.15)"},
                    {"range": [3, 5], "color": "rgba(255,217,61,0.15)"},
                    {"range": [5, max_score], "color": "rgba(255,71,87,0.15)"},
                ],
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=10, b=10, l=10, r=10),
        height=280,
        font={"color": "#e8f9ff", "family": "Poppins, sans-serif"},
    )
    return fig


def format_bool_badge(value: bool, true_text: str, false_text: str) -> str:
    """Returns HTML for a small pill-shaped status badge."""
    if value:
        return f'<span class="badge badge-danger">{true_text}</span>'
    return f'<span class="badge badge-success">{false_text}</span>'
