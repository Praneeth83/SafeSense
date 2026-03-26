import pickle

with open("models/emotional_model.pkl", "rb") as f:
    vectorizer, model = pickle.load(f)

def detect_emotion(text: str):
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]  # class=1 probability
    return float(prob), []
