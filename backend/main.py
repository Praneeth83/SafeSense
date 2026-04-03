from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from urllib.parse import urlparse
import re

from models.emotional_model import detect_emotion
from models.phising_model import detect_phishing
from risk_engine import calculate_div_risk, get_div_weight, aggregate_risk

app = FastAPI()

# -----------------------------
# Request Models
# -----------------------------
class DivData(BaseModel):
    text: str
    hasPasswordField: bool = False
    hasSensitiveField: bool = False
    numInputs: int = 0
    hasFileUpload: bool = False
    hasOTPField: bool = False
    selector: str = ""
    hasCard: bool = False

class PageData(BaseModel):
    text: str = ""
    url: str
    divs: List[DivData] = []

# -----------------------------
# Brand List
# -----------------------------
BRAND_KEYWORDS = [
    "google","gmail","youtube","facebook","instagram","whatsapp","messenger",
    "twitter","x","linkedin","reddit","snapchat","tiktok",
    "apple","icloud","microsoft","windows","outlook","hotmail",
    "amazon","flipkart","myntra","snapdeal","meesho",
    "paypal","paytm","phonepe","gpay","upi","bhim",
    "sbi","hdfc","icici","axis","kotak","yesbank","pnb","canara",
    "irctc","makemytrip","goibibo","yatra","booking","airbnb","uber","ola",
    "netflix","spotify","disney",
    "github","dropbox","adobe","zoom"
]

OFFICIAL_ROOT_DOMAINS = [
    "google.com", "youtube.com", "youtu.be", "googleapis.com",  # ← add these
    "facebook.com", "instagram.com", "amazon.com", "flipkart.com",
    "paypal.com", "apple.com", "microsoft.com", "netflix.com", "twitter.com",
    "linkedin.com", "github.com", "dropbox.com", "adobe.com", "zoom.us",
    "paytm.com", "phonepe.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "irctc.co.in", "makemytrip.com"
]

# -----------------------------
# Brand Detection
# -----------------------------
def detect_brands(text: str):
    text = text.lower()
    return list(set([brand for brand in BRAND_KEYWORDS if brand in text]))

# -----------------------------
# Root Domain
# -----------------------------
def get_root_domain(domain: str):
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain

# -----------------------------
# URL Features
# -----------------------------
def extract_url_features(url: str, detected_brands: list):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain = re.sub(r'^www\.', '', domain)

        root_domain = get_root_domain(domain)

        domain_length = len(domain)
        special_char_count = len(re.findall(r'[-_0-9]', domain))

        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
        has_many_subdomains = domain.count('.') >= 3

        is_official =  any(
    domain == official or domain.endswith("." + official)
    for official in OFFICIAL_ROOT_DOMAINS
)
        brand_in_page = len(detected_brands) > 0

        domain_mismatch = 0

        if brand_in_page and not is_official:
            domain_mismatch = 1

        if is_ip:
            domain_mismatch = 1

        if has_many_subdomains:
            domain_mismatch = 1

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        trusted_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.in', '.co.in']

        domain_age_proxy = 800
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                domain_age_proxy = 50
                break
        for tld in trusted_tlds:
            if domain.endswith(tld):
                domain_age_proxy = 1200
                break
        if is_ip:
            domain_age_proxy = 20

        return {
            "domain_mismatch": domain_mismatch,
            "domain_length": domain_length,
            "domain_age": domain_age_proxy,
            "special_char_count": special_char_count,
            "root_domain": root_domain,
            "is_official": is_official
        }

    except Exception:
        return {
            "domain_mismatch": 0,
            "domain_length": 10,
            "domain_age": 500,
            "special_char_count": 0,
            "root_domain": "",
            "is_official": False
        }

# -----------------------------
# Div Filters
# -----------------------------
def is_actionable_div(div):
    return (
        div.hasPasswordField or
        div.hasOTPField or
        div.hasFileUpload or
        div.hasSensitiveField or
        div.numInputs >= 2
    )

def is_layout_div(selector: str):
    bad_keywords = [
        "body", "html", "#root",
        "container", "wrapper", "main", "content",
        "page", "layout", "section", "nav", "header", "footer"
    ]
    selector = selector.lower()
    return any(word in selector for word in bad_keywords)

# -----------------------------
# Health Check
# -----------------------------
@app.get("/")
def root():
    return {"status": "Backend running"}

# -----------------------------
# Main Analysis
# -----------------------------
@app.post("/analyze")
def analyze_page(data: PageData):

    div_results = []
    risky_selectors = []
    warning_selectors = []
    div_risks = []

    page_brands = detect_brands(data.text)
    url_features = extract_url_features(data.url, page_brands)

    for i, div in enumerate(data.divs):

        detected_brands = detect_brands(div.text)
        brand_present = 1 if detected_brands else 0

        emotion_score, triggers = detect_emotion(div.text)

        phishing_score = detect_phishing(
            has_password=int(div.hasPasswordField),
            brand_present=brand_present,
            domain_mismatch=url_features["domain_mismatch"],
            domain_length=url_features["domain_length"],
            domain_age=url_features["domain_age"],
            special_char_count=url_features["special_char_count"],
            has_sensitive=int(div.hasSensitiveField),
            num_inputs=div.numInputs,
            has_file_upload=int(div.hasFileUpload),
            has_otp=int(div.hasOTPField)
        )

        div_risk = calculate_div_risk(emotion_score, phishing_score)

        # Boost risk for important sections
        if div.numInputs > 0:
            div_risk += 0.1
        if div.hasFileUpload:
            div_risk += 0.15
        if div.hasSensitiveField:
            div_risk += 0.15

        # Reduce risk for official domains
        if url_features["is_official"]:
            div_risk *= 0.5

        div_risk = min(div_risk, 1.0)

        weight = get_div_weight(
            div.hasSensitiveField,
            bool(detected_brands),
            emotion_score
        )

        div_results.append((i, div_risk, weight))
        div_risks.append(div_risk)

        # -------------------------
        # Detection Rules
        # -------------------------
        is_sensitive = div.hasSensitiveField
        has_upload = div.hasFileUpload
        has_password = div.hasPasswordField
        has_otp = div.hasOTPField
        is_brand = brand_present
        is_mismatch = url_features["domain_mismatch"]
        is_official = url_features["is_official"]

        flag_phishing = False
        flag_warning = False

        # PHISHING
        if is_brand and has_password and not is_official:
            flag_phishing = True
        elif (has_password or has_otp) and is_mismatch:
            flag_phishing = True
        elif is_sensitive and has_upload and is_mismatch:
            flag_phishing = True
        elif page_brands and has_upload and is_mismatch:
            flag_phishing = True
        elif div_risk > 0.80 and not is_official:
            flag_phishing = True

        # WARNING (official sites)
        elif is_official and (has_password or has_otp or has_upload or is_sensitive):
            flag_warning = True

        if is_actionable_div(div) and not is_layout_div(div.selector):
            if flag_phishing:
                risky_selectors.append(div.selector)
            elif flag_warning:
                warning_selectors.append(div.selector)

    final_risk, risky_divs = aggregate_risk(div_results)

    # Reduce final risk for official domains
    if url_features["is_official"]:
        final_risk *= 0.6

    # Risk level
    if final_risk > 0.75:
        level = "high"
    elif final_risk > 0.30:
        level = "medium"
    else:
        level = "low"

    print(f"FINAL PAGE RISK: {final_risk}")
    print(f"RISKY SELECTORS: {risky_selectors}")
    print(f"WARNING SELECTORS: {warning_selectors}")

    return {
        "final_risk": final_risk,
        "risk_level": level,
        "risky_selectors": risky_selectors,
        "warning_selectors": warning_selectors,
        "div_risks": div_risks
    }