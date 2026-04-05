from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from urllib.parse import urlparse
import re
import spacy
import whois
from datetime import datetime

from models.emotional_model import detect_emotion
from models.phising_model import detect_phishing
from risk_engine import calculate_div_risk, get_div_weight, aggregate_risk

app = FastAPI()

# Load spaCy — only NER pipeline needed, lemmatizer disabled to avoid warning
nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])

# -----------------------------
# WHOIS Cache
# -----------------------------
domain_age_cache = {}

def get_domain_age(domain: str) -> int:
    if domain in domain_age_cache:
        return domain_age_cache[domain]
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = max(0, (datetime.now() - creation_date).days)
            domain_age_cache[domain] = age
            return age
    except:
        pass
    domain_age_cache[domain] = 365
    return 365

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
# Text Cleaner
# -----------------------------
def clean_text(text: str) -> str:
    """Remove symbols, arrows, and UI noise before NER."""
    text = re.sub(r'[▾▴►◄→←▲▼●•◦–—|/\\]', ' ', text)
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)   # remove non-ASCII
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# -----------------------------
# NER Brand Detection
# No hardcoded brands — spaCy reads the page like a human
# -----------------------------
def detect_brands(text: str) -> list:
    if not text or not text.strip():
        return []

    text = clean_text(text)
    if len(text) < 3:
        return []

    doc = nlp(text)
    brands = set()

    for ent in doc.ents:
        if ent.label_ in ("ORG", "PRODUCT"):
            cleaned = ent.text.strip().lower()
            # Filter out noise: too short, contains menu-like chars, numbers only
            if (
                len(cleaned) > 2
                and "&" not in cleaned
                and "\n" not in cleaned
                and not cleaned.replace(" ", "").isdigit()
                and len(cleaned.split()) <= 4  # avoid long nav phrases
            ):
                brands.add(cleaned)

    return list(brands)

# -----------------------------
# Extract Brand Name FROM the Domain itself
# Core idea: what is this domain pretending to be?
# We extract the meaningful word from the domain and
# check if the page text mentions it — that's the brand claim
# No hardcoding needed.
# -----------------------------
def extract_domain_brand(domain: str) -> str:
    """
    Pull the most meaningful word from a domain.
    e.g. 'secure-paypal-login.tk' → 'paypal'
         'instagram-verify.com'  → 'instagram'
         'hdfc-netbanking.in'    → 'hdfc'
    We split on hyphens/dots and return the longest meaningful token
    that is not a generic word.
    """
    GENERIC_WORDS = {
        "secure", "login", "verify", "account", "update", "confirm",
        "bank", "net", "online", "pay", "free", "gift", "lucky",
        "winner", "support", "help", "service", "portal", "web",
        "app", "sign", "in", "out", "my", "your", "the", "new",
        "get", "now", "click", "here", "www", "com", "net", "org",
        "in", "co", "tk", "ml", "xyz", "info", "biz"
    }

    # Remove TLD
    parts = domain.split('.')
    # Rejoin everything except the last part (TLD)
    base = '.'.join(parts[:-1]) if len(parts) > 1 else domain

    # Split on hyphens and dots
    tokens = re.split(r'[-.]', base)

    # Filter generics, keep longest meaningful token
    candidates = [t for t in tokens if t and t not in GENERIC_WORDS and len(t) > 2]

    if not candidates:
        return ""

    # Return longest candidate — most likely to be the brand name
    return max(candidates, key=len)

# -----------------------------
# Root Domain
# -----------------------------
def get_root_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac"):
        return parts[-3] + "." + parts[-2] + "." + parts[-1]
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain

# -----------------------------
# URL Feature Extraction
# is_official is now determined by domain age + structure, not a hardcoded list
# domain_mismatch is determined by comparing domain brand vs page brand
# -----------------------------
def extract_url_features(url: str, page_brands: list):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split(':')[0]

        root_domain = get_root_domain(domain)
        domain_length = len(domain)
        special_char_count = len(re.findall(r'[-_0-9]', domain))
        is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))

        # Get real domain age via WHOIS
        domain_age = 10 if is_ip else get_domain_age(root_domain)

        # A domain is considered "established" if it's older than 1 year
        is_established = domain_age > 365

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
                           '.top', '.pw', '.click', '.gq', '.monster']
        has_suspicious_tld = any(root_domain.endswith(t) for t in suspicious_tlds)

        has_many_subdomains = len(domain.split('.')) >= 5

        # Structural suspicion flags (no hardcoded brand list)
        is_structurally_suspicious = (
            is_ip or
            has_suspicious_tld or
            has_many_subdomains or
            bool(re.search(r'(secure|login|verify|update|confirm|account|signin)', domain))
        )

        # ------------------------------------
        # Domain Mismatch — fully dynamic
        # ------------------------------------
        # Extract what brand THIS domain is pretending to be
        domain_brand = extract_domain_brand(domain)

        domain_mismatch = 0

        if domain_brand:
            # Case 1: domain brand word is NOT in the root domain properly
            # e.g. domain is 'paypal-secure.tk' → domain_brand = 'paypal'
            # root_domain is 'paypal-secure.tk' — paypal IS there but it's not paypal.com
            # So check: is root_domain EXACTLY just brand.tld or brand.co.tld?
            legitimate_pattern = bool(re.match(
                rf'^{re.escape(domain_brand)}\.(com|in|org|net|co\.in|co\.uk|io|app)$',
                root_domain
            ))
            if not legitimate_pattern:
                # Domain looks like it's impersonating its own brand word
                domain_mismatch = 1

        # Case 2: page mentions a brand that doesn't match domain at all
        if not domain_mismatch and page_brands:
            for brand in page_brands:
                brand_clean = brand.replace(" ", "").lower()
                if len(brand_clean) > 3:  # skip short noise like "co"
                    if brand_clean not in root_domain and brand_clean not in domain:
                        domain_mismatch = 1
                        break

        # Case 3: structural suspicion alone is enough to flag
        if is_structurally_suspicious and not is_established:
            domain_mismatch = 1

        return {
            "domain_mismatch": domain_mismatch,
            "domain_length": domain_length,
            "domain_age": domain_age,
            "special_char_count": special_char_count,
            "root_domain": root_domain,
            "domain_brand": domain_brand,
            "is_established": is_established,
            "is_structurally_suspicious": is_structurally_suspicious
        }

    except Exception as e:
        print(f"URL feature extraction error: {e}")
        return {
            "domain_mismatch": 0,
            "domain_length": 10,
            "domain_age": 365,
            "special_char_count": 0,
            "root_domain": "",
            "domain_brand": "",
            "is_established": True,
            "is_structurally_suspicious": False
        }

# -----------------------------
# Div Filters
# -----------------------------
def is_actionable_div(div: DivData) -> bool:
    return (
        div.hasPasswordField or
        div.hasOTPField or
        div.hasFileUpload or
        div.hasSensitiveField or
        div.numInputs >= 2
    )

def is_layout_div(selector: str) -> bool:
    layout_words = ["body", "html", "#root", "layout", "nav", "header", "footer"]
    return any(word in selector.lower() for word in layout_words)

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
async def analyze_page(data: PageData):

    div_results = []
    risky_selectors = []
    warning_selectors = []
    div_risks = []

    # --- Page-level brand detection via NER ---
    page_brands = detect_brands(data.text)

    # --- URL feature extraction (WHOIS + structural analysis) ---
    url_features = extract_url_features(data.url, page_brands)

    is_mismatch = url_features["domain_mismatch"]
    is_established = url_features["is_established"]
    is_suspicious = url_features["is_structurally_suspicious"]

    # Treat established + non-suspicious as "safe" (replaces hardcoded OFFICIAL list)
    is_safe_domain = is_established and not is_mismatch and not is_suspicious

    for i, div in enumerate(data.divs):

        # NER on each div
        div_brands = detect_brands(div.text)
        brand_present = 1 if (div_brands or page_brands) else 0

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

        # Boost risk for non-safe domains with sensitive inputs
        if not is_safe_domain:
            if div.numInputs > 0:
                div_risk += 0.08
            if div.hasFileUpload:
                div_risk += 0.12
            if div.hasSensitiveField:
                div_risk += 0.12

        # Dampen risk for clearly safe/established domains
        if is_safe_domain:
            div_risk *= 0.25

        div_risk = min(div_risk, 1.0)

        weight = get_div_weight(div.hasSensitiveField, bool(page_brands or div_brands), emotion_score)
        div_results.append((i, div_risk, weight))
        div_risks.append(div_risk)

        # --- Flagging Logic ---
        flag_phishing = False
        flag_warning = False

        has_password = div.hasPasswordField
        has_otp = div.hasOTPField
        has_upload = div.hasFileUpload
        is_sensitive = div.hasSensitiveField

        if is_safe_domain:
            # Even safe domains can have suspicious forms
            if has_upload and is_sensitive and div.numInputs >= 3:
                flag_warning = True

        else:
            # Definite phishing signals
            if is_mismatch and (has_password or has_otp):
                flag_phishing = True

            elif is_mismatch and is_sensitive and has_upload:
                flag_phishing = True

            elif is_mismatch and brand_present and (has_password or has_otp):
                flag_phishing = True

            elif div_risk > 0.88 and is_mismatch:
                flag_phishing = True

            # Warning signals — suspicious but not confirmed
            elif div_risk > 0.72 and (has_password or is_sensitive):
                flag_warning = True

            elif is_suspicious and (has_password or has_otp) and not is_established:
                flag_warning = True

            elif brand_present and (has_password or has_otp) and not is_established:
                flag_warning = True

        # Only flag actionable, non-layout divs
        if is_actionable_div(div) and not is_layout_div(div.selector):
            if flag_phishing:
                risky_selectors.append(div.selector)
            elif flag_warning:
                warning_selectors.append(div.selector)

    final_risk, risky_divs = aggregate_risk(div_results)

    # Safe domain dampening at page level
    if is_safe_domain:
        final_risk *= 0.25

    # Strong override: brand on page + mismatch + password/OTP = definitely phishing
    if page_brands and is_mismatch:
        for div in data.divs:
            if div.hasPasswordField or div.hasOTPField:
                final_risk = max(final_risk, 0.92)
                break

    # Structural suspicion override: new domain + suspicious structure + has inputs
    if is_suspicious and not is_established:
        for div in data.divs:
            if div.hasPasswordField or div.hasOTPField or div.hasSensitiveField:
                final_risk = max(final_risk, 0.75)
                break

    final_risk = min(final_risk, 1.0)

    level = "high" if final_risk > 0.75 else "medium" if final_risk > 0.30 else "low"

    # Debug output
    print(f"\n{'='*60}")
    print(f"URL          : {data.url}")
    print(f"ROOT DOMAIN  : {url_features['root_domain']}")
    print(f"DOMAIN BRAND : {url_features['domain_brand']}")
    print(f"DOMAIN AGE   : {url_features['domain_age']} days")
    print(f"MISMATCH     : {is_mismatch}")
    print(f"ESTABLISHED  : {is_established}")
    print(f"SUSPICIOUS   : {is_suspicious}")
    print(f"SAFE DOMAIN  : {is_safe_domain}")
    print(f"PAGE BRANDS  : {page_brands}")
    print(f"FINAL RISK   : {final_risk:.4f} → {level.upper()}")
    print(f"RISKY        : {risky_selectors}")
    print(f"WARNING      : {warning_selectors}")
    print(f"{'='*60}\n")

    return {
        "final_risk": final_risk,
        "risk_level": level,
        "risky_selectors": risky_selectors,
        "warning_selectors": warning_selectors,
        "div_risks": div_risks
    }