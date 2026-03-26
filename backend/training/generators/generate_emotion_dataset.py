import csv
import random

OUTPUT_FILE = "emotion_data.csv"

# ===== Vocabulary pools =====

urgency_words = [
    "urgent", "immediately", "now", "right now",
    "final warning", "last chance", "critical"
]

threats = [
    "your account will be closed",
    "your system is infected",
    "your access will be permanently blocked",
    "data will be permanently lost",
    "identity theft may occur",
    "financial loss is imminent"
]

actions = [
    "verify your account",
    "click the button below",
    "take action immediately",
    "secure your system",
    "confirm your identity"
]

time_pressure = [
    "within 1 minute",
    "before time runs out",
    "limited time",
    "expires today",
    "only a few seconds left"
]

authorities = [
    "security team",
    "system administrator",
    "official support",
    "IT department",
    "account protection service"
]

normal_sentences = [
    "this article explains basic concepts",
    "welcome to our official website",
    "thank you for visiting our page",
    "here is an overview of the product",
    "contact us for more information",
    "this blog discusses recent updates",
    "learn more about our services",
    "we value your privacy and trust"
]

# ===== Sentence builders =====

def generate_manipulative():
    return (
        f"{random.choice(urgency_words).upper()}! "
        f"{random.choice(threats)}. "
        f"Please {random.choice(actions)} "
        f"{random.choice(time_pressure)}. "
        f"This message is from the {random.choice(authorities)}."
    )

def generate_normal():
    return random.choice(normal_sentences)

# ===== Dataset generation =====

rows = []

NUM_POSITIVE = 50000
NUM_NEGATIVE = 50000

for _ in range(NUM_POSITIVE):
    rows.append([generate_manipulative(), 1])

for _ in range(NUM_NEGATIVE):
    rows.append([generate_normal(), 0])

random.shuffle(rows)

# ===== Write CSV =====

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["text", "label"])
    writer.writerows(rows)

print(f"✅ Generated {len(rows)} samples into {OUTPUT_FILE}")
