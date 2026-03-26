import pickle
import os
import pandas as pd
from datetime import datetime
import whois

# -----------------------------
# Load trained model
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)


# -----------------------------
# Cache (IMPORTANT for speed)
# -----------------------------

domain_age_cache = {}


# -----------------------------
# Feature helpers
# -----------------------------

def get_domain(url: str):
    try:
        return url.split("//")[-1].split("/")[0].lower()
    except:
        return ""


def get_domain_length(url: str):
    return len(get_domain(url))


def count_special_chars(url: str):
    return sum(c in url for c in ["@", "-", "_", "%", "=", "?", "."])


def get_domain_age(url: str):
    domain = get_domain(url)

    # ✅ cache hit (FAST)
    if domain in domain_age_cache:
        return domain_age_cache[domain]

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            age = 0
        else:
            age = (datetime.now() - creation_date).days

        # ✅ store in cache
        domain_age_cache[domain] = age
        return age

    except:
        return 0


# -----------------------------
# MAIN FUNCTION
# -----------------------------

def detect_phishing(url: str, has_password: bool, brands: list[str]) -> float:

    domain = get_domain(url)

    # -----------------------------
    # Core features
    # -----------------------------

    brand_present = 1 if brands else 0

    domain_mismatch = 0
    for brand in brands:
        if brand not in domain:
            domain_mismatch = 1

    domain_length = get_domain_length(url)
    domain_age = get_domain_age(url)
    special_chars = count_special_chars(url)

    # -----------------------------
    # Feature vector
    # -----------------------------

    X = pd.DataFrame([{
        "hasPassword": int(has_password),
        "brandPresent": brand_present,
        "domainMismatch": domain_mismatch,
        "domainLength": domain_length,
        "domainAge": domain_age,
        "specialCharCount": special_chars
    }])

    # -----------------------------
    # Prediction
    # -----------------------------

    probability = model.predict_proba(X)[0][1]

    return float(probability)