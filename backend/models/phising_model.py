import pickle
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# BRAND_DOMAINS removed — brand detection now handled by NER in main.py

def detect_phishing(
    has_password: int = 0,
    has_sensitive: int = 0,
    num_inputs: int = 0,
    has_file_upload: int = 0,
    has_otp: int = 0,
    brand_present: int = 0,
    domain_mismatch: int = 0,
    domain_length: int = 10,
    domain_age: int = 1500,
    special_char_count: int = 0
) -> float:

    X = pd.DataFrame([[
        int(has_password),
        int(brand_present),
        int(domain_mismatch),
        int(domain_length),
        int(domain_age),
        int(special_char_count),
        int(has_sensitive),
        int(num_inputs),
        int(has_file_upload),
        int(has_otp)
    ]], columns=[
        "hasPassword", "brandPresent", "domainMismatch",
        "domainLength", "domainAge", "specialCharCount",
        "hasSensitiveField", "numInputs", "hasFileUpload", "hasOTPField"
    ])

    return float(model.predict_proba(X)[0][1])