import pickle

with open("models/emotional_model.pkl", "rb") as f:
    vectorizer, model = pickle.load(f)

def detect_emotion(text: str):
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]

    triggers = []
    emotional_words = [
        "urgent", "immediately", "verify", "suspended",
        "alert", "warning", "limited", "now",
        "action required", "expire", "blocked"
    ]

    for word in emotional_words:
        if word in text.lower():
            triggers.append(word)

    return float(prob), triggers