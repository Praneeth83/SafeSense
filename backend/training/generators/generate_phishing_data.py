import csv
import random
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(BASE_DIR)
OUTPUT_PATH = os.path.join(TRAINING_DIR, "data", "phishing_data.csv")

NUM_SAMPLES = 150000

rows = []

for _ in range(NUM_SAMPLES):

    scenario = random.choices(
        [
            "legit_normal",
            "legit_login",
            "legit_payment",
            "legit_bank",
            "legit_big_form",
            "fake_login",
            "fake_payment",
            "fake_otp",
            "fake_kyc",
            "phishing_no_brand",
            "phishing_form_only"
        ],
        weights=[12, 14, 10, 10, 12, 12, 10, 8, 6, 4, 2]
    )[0]

    # Default legit values
    has_password = 0
    brand_present = 0
    domain_mismatch = 0
    domain_length = random.randint(6, 18)
    domain_age = random.randint(365, 5000)
    special_chars = random.randint(0, 1)
    sensitive_fields = 0
    input_fields = random.randint(1, 3)
    file_upload = 0
    otp_field = 0
    label = 0

    # ================= LEGIT =================

    if scenario == "legit_normal":
        label = 0

    elif scenario == "legit_login":
        has_password = 1
        brand_present = 1
        input_fields = random.randint(2, 4)
        label = 0

    elif scenario == "legit_payment":
        brand_present = 1
        sensitive_fields = 1
        input_fields = random.randint(3, 5)
        label = 0

    elif scenario == "legit_bank":
        brand_present = 1
        sensitive_fields = 1
        otp_field = 1
        input_fields = random.randint(3, 6)
        label = 0

    elif scenario == "legit_big_form":
        brand_present = random.choice([0, 1])
        sensitive_fields = 1
        has_password = random.choice([0, 1])
        otp_field = random.choice([0, 1])
        input_fields = random.randint(6, 14)
        special_chars = random.randint(0, 2)
        domain_age = random.randint(200, 4000)
        label = 0

    # ================= PHISHING =================

    elif scenario == "fake_login":
        has_password = 1
        brand_present = random.choice([0, 1])
        domain_mismatch = 1
        domain_age = random.randint(5, 180)
        special_chars = random.randint(2, 6)
        input_fields = random.randint(3, 7)
        label = 1

    elif scenario == "fake_payment":
        brand_present = random.choice([0, 1])
        domain_mismatch = 1
        sensitive_fields = 1
        input_fields = random.randint(3, 8)
        special_chars = random.randint(2, 6)
        domain_age = random.randint(5, 150)
        label = 1

    elif scenario == "fake_otp":
        brand_present = random.choice([0, 1])
        domain_mismatch = 1
        otp_field = 1
        input_fields = random.randint(2, 5)
        domain_age = random.randint(5, 120)
        special_chars = random.randint(1, 5)
        label = 1

    elif scenario == "fake_kyc":
        brand_present = random.choice([0, 1])
        domain_mismatch = 1
        sensitive_fields = 1
        file_upload = 1
        input_fields = random.randint(4, 10)
        domain_age = random.randint(5, 120)
        special_chars = random.randint(2, 7)
        label = 1

    elif scenario == "phishing_no_brand":
        brand_present = 0
        domain_mismatch = 1
        domain_age = random.randint(5, 200)
        special_chars = random.randint(2, 7)
        input_fields = random.randint(3, 10)
        sensitive_fields = random.randint(0, 1)
        label = 1

    elif scenario == "phishing_form_only":
        brand_present = 0
        domain_mismatch = 0
        domain_age = random.randint(10, 200)
        input_fields = random.randint(5, 12)
        sensitive_fields = 1
        special_chars = random.randint(1, 4)
        label = 1

    # ================= REALISTIC NOISE =================

    # Some legit sites are new
    if label == 0 and random.random() < 0.15:
        domain_age = random.randint(10, 200)

    # Some phishing sites are old (compromised domains)
    if label == 1 and random.random() < 0.20:
        domain_age = random.randint(365, 3000)

    # Legit sites sometimes have many inputs
    if label == 0 and random.random() < 0.25:
        input_fields = random.randint(5, 12)

    # Phishing sometimes simple pages
    if label == 1 and random.random() < 0.20:
        input_fields = random.randint(1, 3)

    # Legit sites often ask sensitive info
    if label == 0 and random.random() < 0.30:
        sensitive_fields = 1

    # Phishing sometimes does not ask sensitive info
    if label == 1 and random.random() < 0.25:
        sensitive_fields = 0

    # Rare legit domain mismatch (SSO, auth domains)
    if label == 0 and random.random() < 0.03:
        domain_mismatch = 1

    # Some phishing pages avoid mismatch
    if label == 1 and random.random() < 0.15:
        domain_mismatch = 0

    # Legit sites sometimes have special chars
    if label == 0 and random.random() < 0.10:
        special_chars = random.randint(1, 3)

    # Phishing sometimes clean domain
    if label == 1 and random.random() < 0.20:
        special_chars = 0

    # Domain length noise
    domain_length += random.randint(-2, 2)
    domain_length = max(3, min(30, domain_length))

    rows.append([
        has_password,
        brand_present,
        domain_mismatch,
        domain_length,
        domain_age,
        special_chars,
        sensitive_fields,
        input_fields,
        file_upload,
        otp_field,
        label
    ])

random.shuffle(rows)

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "hasPassword",
        "brandPresent",
        "domainMismatch",
        "domainLength",
        "domainAge",
        "specialCharCount",
        "hasSensitiveField",
        "numInputs",
        "hasFileUpload",
        "hasOTPField",
        "label"
    ])
    writer.writerows(rows)

legit = sum(1 for r in rows if r[-1] == 0)
phishing = sum(1 for r in rows if r[-1] == 1)

print(f"✅ Generated {len(rows)} samples")
print(f"   Legit (0):    {legit} ({legit/len(rows)*100:.1f}%)")
print(f"   Phishing (1): {phishing} ({phishing/len(rows)*100:.1f}%)")
print(f"📁 Saved to: {OUTPUT_PATH}")