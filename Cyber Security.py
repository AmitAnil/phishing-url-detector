import validators
import tldextract
import time
from urllib.parse import urlparse
import whois
from datetime import datetime
import requests
url = input("Enter URL: ")
if(validators.url(url)):
    print("Valid URL")
else:
    print("Invalid URL")
result = tldextract.extract(url)
print("Domain: ",result.domain)
print("Suffix: ",result.suffix)
print("Subdomain: ",result.subdomain)
parsed = urlparse(url)

if parsed.scheme == "https":
    print("HTTPS Enabled")
else:
    print("HTTP (Unsafe)")
shorteners = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd"
]

for s in shorteners:
    if s in url:
        print("Shortened URL Detected")
import re

pattern = r'(\d{1,3}\.){3}\d{1,3}'

if re.search(pattern, url):
    print("Uses IP Address")
keywords = [
    "login",
    "verify",
    "update",
    "secure",
    "reward",
    "gift",
    "bank",
    "wallet",
    "kyc"
]

found = False

for word in keywords:
    if word in url.lower():
        print("Keyword Found:", word)
        found = True

if not found:
    print("No suspicious keywords found.")
from datetime import datetime, timezone

try:
    domain_info = whois.whois(result.domain + "." + result.suffix)

    creation = domain_info.creation_date

    if isinstance(creation, list):
        creation = creation[0]

    if creation is not None:

        # Make both dates timezone-aware
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        age = (now - creation).days

        print("Domain Age:", age, "days")

        if age < 180:
            print("⚠ Newly Registered Domain")

    else:
        print("Domain creation date not available.")

except Exception as e:
    print("WHOIS Error:", e)

API_KEY = "d45eca2ed2be497faff5ecb9df84a97875f07d7ab74c8931855cb146c8e7ef78"


headers = {
    "x-apikey": API_KEY
}


submit_url = "https://www.virustotal.com/api/v3/urls"

response = requests.post(
    submit_url,
    headers=headers,
    data={"url": url}
)

if response.status_code != 200:
    print("Error!")
    print(response.text)
    exit()

analysis_id = response.json()["data"]["id"]

print("\nURL submitted successfully.")
print("Scanning... Please wait.\n")

time.sleep(5)


report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

response = requests.get(
    report_url,
    headers=headers
)

if response.status_code != 200:
    print("Error fetching report!")
    print(response.text)
    exit()

report = response.json()

stats = report["data"]["attributes"]["stats"]

print("========== VIRUSTOTAL REPORT ==========")
print("Malicious   :", stats["malicious"])
print("Suspicious  :", stats["suspicious"])
print("Harmless    :", stats["harmless"])
print("Undetected  :", stats["undetected"])
print("Timeout     :", stats["timeout"])

print("---------------------------------------")

if stats["malicious"] > 0:
    print("⚠ WARNING: This URL is MALICIOUS!")
elif stats["suspicious"] > 0:
    print("⚠ CAUTION: This URL is SUSPICIOUS!")
else:
    print(" SAFE: No malicious detections found.")
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

print("Risk Score:", score)

if score >= 5:
    print("High Risk")

elif score >= 3:
    print("Medium Risk")

else:
    print("Low Risk")

