import os
import pandas as pd
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# -----------------------------
# Path handling
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(BASE_DIR)

DATA_PATH = os.path.join(
    TRAINING_DIR,
    "data",
    "phishing_data.csv"
)

MODEL_PATH = os.path.join(
    os.path.dirname(TRAINING_DIR),
    "models",
    "phishing_model.pkl"
)

# -----------------------------
# Load dataset
# -----------------------------

df = pd.read_csv(DATA_PATH)

# 🔥 UPDATED FEATURES
features = [
    "hasPassword",
    "brandPresent",
    "domainMismatch",
    "domainLength",
    "domainAge",
    "specialCharCount"
]

X = df[features]
y = df["label"]

# -----------------------------
# Train-test split (IMPORTANT)
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# Train model
# -----------------------------

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# -----------------------------
# Evaluate model
# -----------------------------

y_pred = model.predict(X_test)

print("\n📊 Model Evaluation:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# -----------------------------
# Save model
# -----------------------------

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)

print("\n✅ Phishing ML model trained successfully")
print(f"📦 Model saved to: {MODEL_PATH}")
print(f"📊 Samples used: {len(df)}")