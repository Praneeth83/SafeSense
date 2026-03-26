import csv
import random
import os

# -----------------------------
# Paths
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(BASE_DIR)

OUTPUT_PATH = os.path.join(
    TRAINING_DIR,
    "data",
    "phishing_data.csv"
)

# -----------------------------
# Dataset size
# -----------------------------

NUM_SAMPLES = 60000

# -----------------------------
# Feature generators
# -----------------------------

def generate_domain_length(is_phishing):
    if is_phishing:
        return random.randint(20, 120)   # long messy domains
    return random.randint(5, 25)         # normal domains


def generate_domain_age(is_phishing):
    if is_phishing:
        return random.randint(1, 90)     # new domains
    return random.randint(180, 5000)    # old domains


def generate_special_chars(is_phishing):
    if is_phishing:
        return random.randint(2, 10)
    return random.randint(0, 2)


# -----------------------------
# Label logic (UPDATED)
# -----------------------------

def assign_label(has_password, brand_present, domain_mismatch,
                 domain_length, domain_age, special_chars):

    score = 0

    if has_password:
        score += 1

    if brand_present:
        score += 1

    if domain_mismatch:
        score += 2   # strong signal

    if domain_length > 30:
        score += 1

    if domain_age < 120:
        score += 2   # very strong signal

    if special_chars > 3:
        score += 1

    # probabilistic labeling
    if score >= 5:
        return 1
    elif score >= 3:
        return 1 if random.random() < 0.7 else 0
    else:
        return 0


# -----------------------------
# Generate dataset
# -----------------------------

rows = []

for _ in range(NUM_SAMPLES):

    # Base features
    has_password = int(random.random() < 0.55)
    brand_present = int(random.random() < 0.40)

    if brand_present:
        domain_mismatch = int(random.random() < 0.85)
    else:
        domain_mismatch = 0

    # First assume phishing randomly (to generate features realistically)
    temp_is_phishing = random.random() < 0.5

    domain_length = generate_domain_length(temp_is_phishing)
    domain_age = generate_domain_age(temp_is_phishing)
    special_chars = generate_special_chars(temp_is_phishing)

    # Final label based on all features
    label = assign_label(
        has_password,
        brand_present,
        domain_mismatch,
        domain_length,
        domain_age,
        special_chars
    )

    rows.append([
        has_password,
        brand_present,
        domain_mismatch,
        domain_length,
        domain_age,
        special_chars,
        label
    ])

# Shuffle
random.shuffle(rows)

# -----------------------------
# Write CSV
# -----------------------------

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
        "label"
    ])

    writer.writerows(rows)

print(f"✅ Generated {len(rows)} samples")
print(f"📁 Saved to: {OUTPUT_PATH}")