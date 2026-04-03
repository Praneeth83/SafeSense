import os
import pandas as pd
import pickle
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, ConfusionMatrixDisplay
from sklearn.ensemble import RandomForestClassifier

# -----------------------------
# Path handling
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAINING_DIR = os.path.dirname(BASE_DIR)

DATA_PATH = os.path.join(TRAINING_DIR, "data", "phishing_data.csv")

MODEL_PATH = os.path.join(
    os.path.dirname(TRAINING_DIR),
    "models",
    "phishing_model.pkl"
)

# -----------------------------
# Load dataset
# -----------------------------
df = pd.read_csv(DATA_PATH)
print(f"📂 Loaded {len(df)} samples")
print(f"   Legit (0):    {(df['label'] == 0).sum()}")
print(f"   Phishing (1): {(df['label'] == 1).sum()}")

# -----------------------------
# Features
# -----------------------------
features = [
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
]

X = df[features]
y = df["label"]

# -----------------------------
# Train-test split (stratified)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y          # preserves class ratio in both splits
)

# -----------------------------
# Train model
# -----------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,           # reduced from 15 to prevent overfitting
    min_samples_leaf=10,    # each leaf needs at least 10 samples
    min_samples_split=20,   # each split needs at least 20 samples
    random_state=42
    # removed class_weight="balanced" since classes are ~50/50
)

print("\n⏳ Training model...")
model.fit(X_train, y_train)

# -----------------------------
# Evaluate on test set
# -----------------------------
y_pred = model.predict(X_test)
y_pred_train = model.predict(X_train)

train_acc = accuracy_score(y_train, y_pred_train)
test_acc = accuracy_score(y_test, y_pred)

print("\n📊 Model Evaluation:")
print(f"   Train Accuracy: {train_acc:.4f}")
print(f"   Test  Accuracy: {test_acc:.4f}")

gap = train_acc - test_acc
if gap > 0.05:
    print(f"   ⚠️  Overfitting detected! Gap = {gap:.4f} — consider reducing max_depth further")
elif test_acc > 0.99:
    print(f"   ⚠️  Suspiciously high accuracy ({test_acc:.4f}) — check for data leakage or overly clean synthetic data")
else:
    print(f"   ✅ Model looks healthy (train-test gap = {gap:.4f})")

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

# -----------------------------
# Cross-validation (5-fold)
# -----------------------------
print("⏳ Running 5-fold cross-validation...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring="f1")
print(f"\n🔁 Cross-Validation F1 Scores: {[round(s, 4) for s in cv_scores]}")
print(f"   Mean F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

if cv_scores.std() > 0.02:
    print("   ⚠️  High variance across folds — model may be unstable")
else:
    print("   ✅ Low variance — model is stable across folds")

# -----------------------------
# Feature Importance Plot
# -----------------------------
importances = pd.Series(model.feature_importances_, index=features).sort_values()

plt.figure(figsize=(8, 5))
importances.plot(kind="barh", color="steelblue")
plt.title("Feature Importances")
plt.xlabel("Importance Score")
plt.tight_layout()
plt.savefig(os.path.join(os.path.dirname(MODEL_PATH), "feature_importance.png"))
print("\n📈 Feature importance plot saved to models/feature_importance.png")

# -----------------------------
# Confusion Matrix
# -----------------------------
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legit", "Phishing"])
disp.plot(cmap="Blues")
plt.title("Confusion Matrix")
plt.tight_layout()
plt.savefig(os.path.join(os.path.dirname(MODEL_PATH), "confusion_matrix.png"))
print("📊 Confusion matrix saved to models/confusion_matrix.png")

# Print raw confusion matrix numbers
tn, fp, fn, tp = cm.ravel()
print(f"\n   True Negatives  (Legit correctly identified):    {tn}")
print(f"   False Positives (Legit wrongly flagged):          {fp}")
print(f"   False Negatives (Phishing missed):                {fn}")
print(f"   True Positives  (Phishing correctly caught):      {tp}")

# -----------------------------
# Save model
# -----------------------------
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)

print(f"\n✅ Phishing ML model trained and saved")
print(f"📦 Model saved to: {MODEL_PATH}")
print(f"📊 Samples used:   {len(df)}")