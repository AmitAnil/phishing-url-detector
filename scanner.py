"""
scanner.py
-----------
Core phishing URL detection logic.

IMPORTANT: Every check below is a direct, function-based refactor of your
original script. No detection rule, threshold, keyword list, or algorithm
has been changed — only reorganized into reusable functions so it can be
called from the Streamlit frontend (app.py) instead of printing to a
terminal. The only unavoidable adaptation is that the original script's
`exit()` calls on VirusTotal errors have been replaced with an "error" key
in the returned dictionary, because a long-running web app cannot terminate
the whole process the way a one-shot CLI script can.
"""

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract
import validators
import whois

# --------------------------------------------------------------------------
# Static lookup tables (unchanged from the original script)
# --------------------------------------------------------------------------
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "reward",
    "gift", "bank", "wallet", "kyc",
]

IP_PATTERN = r'(\d{1,3}\.){3}\d{1,3}'


def validate_url(url: str) -> bool:
    """Step 1: URL validation (validators library)."""
    return bool(validators.url(url))


def extract_domain_info(url: str) -> dict:
    """Step 2: Domain / suffix / subdomain extraction (tldextract)."""
    result = tldextract.extract(url)
    return {
        "domain": result.domain,
        "suffix": result.suffix,
        "subdomain": result.subdomain,
        "registered_domain": f"{result.domain}.{result.suffix}" if result.suffix else result.domain,
    }


def check_https(url: str) -> bool:
    """Step 3: HTTPS detection (urllib.parse)."""
    parsed = urlparse(url)
    return parsed.scheme == "https"


def check_shortener(url: str) -> bool:
    """Step 4: URL shortener detection."""
    return any(s in url for s in SHORTENERS)


def check_ip_address(url: str) -> bool:
    """Step 5: IP address usage detection (regex)."""
    return bool(re.search(IP_PATTERN, url))


def check_suspicious_keywords(url: str) -> list:
    """Step 6: Suspicious keyword detection."""
    found = []
    lowered = url.lower()
    for word in SUSPICIOUS_KEYWORDS:
        if word in lowered:
            found.append(word)
    return found


def check_domain_age(domain: str, suffix: str) -> dict:
    """
    Step 7: WHOIS domain-age check.
    Returns age in days, whether it's newly registered (<180 days),
    the raw creation date, and any error encountered — same logic as
    your original try/except block.
    """
    info = {"age_days": None, "creation_date": None, "is_new": False, "error": None}
    try:
        domain_info = whois.whois(f"{domain}.{suffix}")
        creation = domain_info.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation is not None:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age = (now - creation).days

            info["age_days"] = age
            info["creation_date"] = creation
            info["is_new"] = age < 180
        else:
            info["error"] = "Domain creation date not available."

    except Exception as e:
        info["error"] = f"WHOIS Error: {e}"

    return info


def scan_virustotal(url: str, api_key: str, wait_seconds: int = 5) -> dict:
    """
    Step 8: VirusTotal API scan.
    Submits the URL, waits (same 5-second delay as your script), then
    fetches the analysis report. Returns {"stats": {...}} on success or
    {"error": "..."} on failure instead of calling exit().
    """
    result = {"stats": None, "error": None}

    if not api_key:
        result["error"] = "VirusTotal API key not configured."
        return result

    headers = {"x-apikey": api_key}
    submit_url = "https://www.virustotal.com/api/v3/urls"

    try:
        response = requests.post(submit_url, headers=headers, data={"url": url}, timeout=15)

        if response.status_code != 200:
            result["error"] = f"Error submitting URL: {response.text}"
            return result

        analysis_id = response.json()["data"]["id"]

        time.sleep(wait_seconds)

        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(report_url, headers=headers, timeout=15)

        if response.status_code != 200:
            result["error"] = f"Error fetching report: {response.text}"
            return result

        report_data = response.json()
        result["stats"] = report_data["data"]["attributes"]["stats"]

    except requests.exceptions.RequestException as e:
        result["error"] = f"Network error: {e}"
    except Exception as e:
        result["error"] = f"VirusTotal Error: {e}"

    return result


def calculate_risk_score(url: str) -> int:
    """Step 9: Heuristic risk score calculation (unchanged thresholds)."""
    score = 0

    if len(url) > 75:
        score += 1

    if "@" in url:
        score += 2

    if "-" in url:
        score += 1

    if "http://" in url:
        score += 2

    if "bit.ly" in url:
        score += 2

    return score


def get_risk_level(score: int) -> str:
    """Step 10: Final risk-level classification (unchanged thresholds)."""
    if score >= 5:
        return "High Risk"
    elif score >= 3:
        return "Medium Risk"
    else:
        return "Low Risk"


def get_final_verdict(vt_stats: dict, risk_level: str) -> tuple:
    """
    Combines the VirusTotal outcome with the heuristic risk level into a
    single SAFE / SUSPICIOUS / MALICIOUS verdict for the dashboard banner.
    This is presentation logic that mirrors the print statements at the
    end of your original script — it does not change any detection rule.
    """
    if vt_stats and vt_stats.get("malicious", 0) > 0:
        return "MALICIOUS", "red"
    if vt_stats and vt_stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS", "yellow"
    if risk_level == "High Risk":
        return "SUSPICIOUS", "yellow"
    if risk_level == "Medium Risk":
        return "SUSPICIOUS", "yellow"
    return "SAFE", "green"


def perform_full_scan(url: str, api_key: str) -> dict:
    """
    Master orchestration function used by app.py.
    Runs every check in the same order as your original script and
    collects the results into a single dictionary.
    """
    scan_result = {"url": url, "timestamp": datetime.now().isoformat()}

    scan_result["is_valid"] = validate_url(url)

    domain_info = extract_domain_info(url)
    scan_result.update(domain_info)

    scan_result["https"] = check_https(url)
    scan_result["is_shortener"] = check_shortener(url)
    scan_result["has_ip"] = check_ip_address(url)
    scan_result["keywords_found"] = check_suspicious_keywords(url)
    scan_result["whois"] = check_domain_age(domain_info["domain"], domain_info["suffix"])
    scan_result["virustotal"] = scan_virustotal(url, api_key)
    scan_result["risk_score"] = calculate_risk_score(url)
    scan_result["risk_level"] = get_risk_level(scan_result["risk_score"])

    vt_stats = scan_result["virustotal"].get("stats")
    verdict, verdict_color = get_final_verdict(vt_stats, scan_result["risk_level"])
    scan_result["verdict"] = verdict
    scan_result["verdict_color"] = verdict_color

    return scan_result
