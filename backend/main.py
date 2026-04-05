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

# FIX 1: Massively expanded official domains list.
# The old list was too small — claude.ai, anthropic.com, accounts.google.com etc. were missing.
OFFICIAL_ROOT_DOMAINS = [
    # Google ecosystem
    "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr",
    "youtube.com", "youtu.be", "googleapis.com", "googleusercontent.com",
    "accounts.google.com", "mail.google.com", "drive.google.com",
    # Meta
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "meta.com",
    # Apple
    "apple.com", "icloud.com",
    # Microsoft
    "microsoft.com", "live.com", "outlook.com", "hotmail.com",
    "office.com", "microsoftonline.com", "azure.com", "bing.com",
    # Amazon / AWS
    "amazon.com", "amazon.in", "amazonaws.com", "aws.amazon.com",
    # Anthropic / Claude
    "anthropic.com", "claude.ai",
    # Social / Comms
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "snapchat.com", "tiktok.com", "telegram.org",
    "zoom.us", "slack.com", "discord.com",
    # Commerce
    "flipkart.com", "myntra.com", "snapdeal.com", "meesho.com",
    "shopify.com", "ebay.com",
    # Payments
    "paypal.com", "paytm.com", "phonepe.com", "razorpay.com", "stripe.com",
    # Indian Banks
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "yesbank.in", "pnbindia.in",
    "canarabank.com", "unionbankofindia.co.in",
    # Travel / Services
    "irctc.co.in", "makemytrip.com", "goibibo.com", "yatra.com",
    "booking.com", "airbnb.com", "uber.com", "ola.com",
    # Entertainment
    "netflix.com", "spotify.com", "disneyplus.com", "hotstar.com",
    # Dev / Tools
    "github.com", "gitlab.com", "dropbox.com", "adobe.com",
    "notion.so", "figma.com", "atlassian.com", "jira.com",
    # News / Productivity
    "wikipedia.org", "medium.com",
]

# FIX 2: Pre-build a set of root domains for fast O(1) lookups
OFFICIAL_ROOT_SET = set(OFFICIAL_ROOT_DOMAINS)

# -----------------------------
# Brand Detection
# -----------------------------
def detect_brands(text: str):
    text = text.lower()
    return list(set([brand for brand in BRAND_KEYWORDS if brand in text]))

# -----------------------------
# Root Domain
# -----------------------------
def get_root_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac"):
        # Handle co.in, co.uk, com.au etc.
        return parts[-3] + "." + parts[-2] + "." + parts[-1]
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain

# -----------------------------
# URL Features
# FIX 3: Completely rewritten — more accurate is_official, better domain_age_proxy
# -----------------------------
def extract_url_features(url: str, detected_brands: list):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        # Strip port number if present
        domain = domain.split(':')[0]

        root_domain = get_root_domain(domain)

        domain_length = len(domain)
        special_char_count = len(re.findall(r'[-_0-9]', domain))

        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))

        # FIX 3a: Count subdomains only beyond the root (e.g. a.b.google.com has 1 extra subdomain)
        # Only flag if there are 3+ dots AND it doesn't match an official root
        subdomain_parts = domain.split('.')
        has_many_subdomains = (
            len(subdomain_parts) >= 5 and  # raised from 3 to 5
            not any(domain == off or domain.endswith("." + off) for off in OFFICIAL_ROOT_SET)
        )

        # FIX 3b: Robust official check — exact match or subdomain of official root
        is_official = any(
            domain == official or domain.endswith("." + official)
            for official in OFFICIAL_ROOT_SET
        )

        brand_in_page = len(detected_brands) > 0

        domain_mismatch = 0

        # FIX 3c: Only flag domain mismatch when it's truly suspicious.
        # Official domains are NEVER a mismatch even if they have brand keywords.
        if not is_official:
            if is_ip:
                domain_mismatch = 1
            elif has_many_subdomains:
                domain_mismatch = 1
            elif brand_in_page:
                # Check: does any detected brand NOT match the actual domain?
                for brand in detected_brands:
                    if brand not in root_domain and brand not in domain:
                        domain_mismatch = 1
                        break

        # FIX 3d: domain_age_proxy — use values that align with training data ranges
        # Training legit: 200-5000 days. Training phishing: 5-200 days.
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.click']
        # Use 2000 for known good TLDs so the ML model firmly classifies them as legit
        domain_age_proxy = 1500  # neutral default (was 800 — too close to phishing range)

        if is_ip:
            domain_age_proxy = 20
        elif is_official:
            domain_age_proxy = 3000  # well-established site
        else:
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    domain_age_proxy = 50
                    break
            else:
                # For normal TLDs, use a healthy value
                domain_age_proxy = 1500

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
            "domain_age": 1500,
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
# FIX 4: Rewritten detection rules — official sites never get phishing flags
# -----------------------------
@app.post("/analyze")
def analyze_page(data: PageData):

    div_results = []
    risky_selectors = []
    warning_selectors = []
    div_risks = []

    page_brands = detect_brands(data.text)
    url_features = extract_url_features(data.url, page_brands)

    is_official = url_features["is_official"]
    is_mismatch = url_features["domain_mismatch"]

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

        # Boost risk for important sections (only on non-official sites)
        if not is_official:
            if div.numInputs > 0:
                div_risk += 0.1
            if div.hasFileUpload:
                div_risk += 0.15
            if div.hasSensitiveField:
                div_risk += 0.15

        # FIX 4a: Apply official discount BEFORE capping, not after detection rules.
        # Use a stronger discount — official sites should almost never exceed 0.40 risk.
        if is_official:
            div_risk *= 0.25  # was 0.5 — not strong enough

        div_risk = min(div_risk, 1.0)

        weight = get_div_weight(
            div.hasSensitiveField,
            bool(detected_brands),
            emotion_score
        )

        div_results.append((i, div_risk, weight))
        div_risks.append(div_risk)

        # -------------------------
        # FIX 4b: Detection Rules — completely rewritten with clear priority
        # Rule 1: Official sites NEVER get phishing flags — only warnings for
        #         genuinely risky fields (file upload asking for documents, OTP scams)
        # Rule 2: Phishing requires domain mismatch OR (brand impersonation + no official match)
        # -------------------------
        has_password = div.hasPasswordField
        has_otp = div.hasOTPField
        has_upload = div.hasFileUpload
        is_sensitive = div.hasSensitiveField

        flag_phishing = False
        flag_warning = False

        if is_official:
            # Official sites: only warn for file uploads with sensitive fields
            # (e.g. KYC document uploads on banking sites — legitimate but worth noting)
            # Do NOT warn for normal login forms on Google, banks, etc.
            if has_upload and is_sensitive and div.numInputs >= 3:
                flag_warning = True
            # Everything else on official sites: no flag at all

        else:
            # Non-official sites: apply phishing detection

            # Strong phishing signals — require domain mismatch
            if is_mismatch and (has_password or has_otp):
                flag_phishing = True

            elif is_mismatch and is_sensitive and has_upload:
                flag_phishing = True

            elif is_mismatch and page_brands and has_upload:
                flag_phishing = True

            # Brand impersonation: brand in content but domain doesn't match brand
            elif brand_present and has_password and is_mismatch:
                flag_phishing = True

            # FIX 4c: High ML risk threshold raised from 0.80 to 0.90 for non-mismatch sites.
            # Only flag if BOTH ML says risky AND there's mismatch — prevents false positives
            # on legitimate new/unknown sites.
            elif div_risk > 0.90 and is_mismatch:
                flag_phishing = True

            # Mild warning: suspicious but not confirmed phishing
            elif div_risk > 0.75 and (has_password or is_sensitive):
                flag_warning = True

        if is_actionable_div(div) and not is_layout_div(div.selector):
            if flag_phishing:
                risky_selectors.append(div.selector)
            elif flag_warning:
                warning_selectors.append(div.selector)

    final_risk, risky_divs = aggregate_risk(div_results)

    # FIX 4d: Stronger official discount on final risk
    if is_official:
        final_risk *= 0.25  # was 0.6

    # Risk level
    if final_risk > 0.75:
        level = "high"
    elif final_risk > 0.30:
        level = "medium"
    else:
        level = "low"

    print(f"URL: {data.url}")
    print(f"IS OFFICIAL: {is_official}")
    print(f"DOMAIN MISMATCH: {is_mismatch}")
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