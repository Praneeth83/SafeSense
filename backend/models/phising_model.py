import pickle
import os
import re
import pandas as pd
from datetime import datetime
import whois
import concurrent.futures

# -----------------------------
# Load trained ML model
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Cache for domain age (persists for server lifetime)
domain_age_cache = {}

# Trusted brands for domain mismatch — only exact domain-level names
BRAND_DOMAINS = [
    "google", "facebook", "instagram", "youtube", "gmail",
    "outlook", "hotmail", "yahoo", "amazon", "flipkart",
    "myntra", "snapdeal", "paypal", "paytm", "phonepe",
    "gpay", "whatsapp", "telegram", "twitter", "linkedin",
    "netflix", "apple", "microsoft", "icloud", "adobe",
    "dropbox", "zoom", "uber", "airbnb", "irctc",
    "sbi", "hdfc", "icici", "axis", "kotak", "yesbank",
    "indusind", "pnb", "canara", "hsbc", "citibank",
    "razorpay", "stripe", "shopify", "github"
]

# -----------------------------
# URL Feature Helpers
# -----------------------------
def get_domain(url: str) -> str:
    try:
        domain = url.split("//")[-1].split("/")[0].lower()
        domain = re.sub(r'^www\.', '', domain)
        return domain
    except:
        return ""

def get_domain_length(url: str) -> int:
    return len(get_domain(url))

def count_special_chars(url: str) -> int:
    domain = get_domain(url)
    return len(re.findall(r'[-_0-9]', domain))

def get_domain_age(url: str) -> int:
    domain = get_domain(url)
    if not domain:
        return 365

    if domain in domain_age_cache:
        return domain_age_cache[domain]

    def _whois_lookup():
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return 365
        return max(0, (datetime.now() - creation_date).days)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_whois_lookup)
            age = future.result(timeout=5)
    except Exception:
        age = 365

    domain_age_cache[domain] = age
    return age

def check_domain_mismatch(domain: str, brands: list[str]) -> int:
    if not brands:
        return 0

    real_brands = [b for b in brands if b in BRAND_DOMAINS]

    if not real_brands:
        return 0

    for brand in real_brands:
        domain_root = domain.split('.')[0]
        if brand not in domain_root:
            return 1

    return 0

# -----------------------------
# MAIN ML PHISHING DETECTION
# -----------------------------
def detect_phishing(
    url: str = "",
    has_password: int = 0,
    has_sensitive: int = 0,
    num_inputs: int = 0,
    has_file_upload: int = 0,
    has_otp: int = 0,
    brands: list = None,
    brand_present: int = None,
    domain_mismatch: int = None,
    domain_length: int = None,
    domain_age: int = None,
    special_char_count: int = None
) -> float:

    # If FastAPI already computed features, use them
    if brand_present is not None:
        bp = brand_present
        dm = domain_mismatch
        dl = domain_length
        da = domain_age
        sc = special_char_count
    else:
        # Otherwise compute from URL (old behavior)
        domain = get_domain(url)
        bp = 1 if brands else 0
        dm = check_domain_mismatch(domain, brands)
        dl = get_domain_length(url)
        da = get_domain_age(url)
        sc = count_special_chars(url)

    # Feature vector — order MUST match training
    X = pd.DataFrame([[
        int(has_password),
        int(bp),
        int(dm),
        int(dl),
        int(da),
        int(sc),
        int(has_sensitive),
        int(num_inputs),
        int(has_file_upload),
        int(has_otp)
    ]], columns=[
        "hasPassword",
        "brandPresent",
        "domainMismatch",
        "domainLength",
        "domainAge",
        "specialCharCount",
        "hasSensitiveField",
        "numInputs",
        "hasFileUpload",
        "hasOTPField"
    ])

    probability = model.predict_proba(X)[0][1]
    return float(probability)