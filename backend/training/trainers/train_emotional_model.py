import os
import pickle
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# -----------------------------
# Path handling (ROBUST)
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(BASE_DIR)

DATA_PATH = os.path.join(
    TRAINING_DIR,
    "data",
    "emotion_data.csv"
)

MODEL_PATH = os.path.join(
    os.path.dirname(TRAINING_DIR),
    "models",
    "emotional_model.pkl"
)


# -----------------------------
# Load dataset
# -----------------------------

df = pd.read_csv(DATA_PATH)

X_text = df["text"].astype(str)
y = df["label"].astype(int)


# -----------------------------
# Vectorization (NLP features)
# -----------------------------

vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=20000,
    stop_words="english"
)

X_vec = vectorizer.fit_transform(X_text)


# -----------------------------
# Train ML model
# -----------------------------

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    n_jobs=1
)

model.fit(X_vec, y)


# -----------------------------
# Save model
# -----------------------------

with open(MODEL_PATH, "wb") as f:
    pickle.dump((vectorizer, model), f)


print("✅ Emotional manipulation ML model trained successfully")
print(f"📦 Model saved to: {MODEL_PATH}")
print(f"📊 Samples used: {len(df)}")
