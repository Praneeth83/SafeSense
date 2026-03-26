from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from models.emotional_model import detect_emotion
from models.phising_model import detect_phishing
from risk_engine import aggregate_risk

app = FastAPI()


# -----------------------------
# Request Model
# -----------------------------

class PageData(BaseModel):
    text: str
    url: str
    hasPasswordField: bool = False


# -----------------------------
# 🔥 Brand + Trust Detection
# -----------------------------

def detect_brands(text: str):
    text = text.lower()

    # 🔥 Top brands (global + India + services)
    brand_keywords = [
        "google","facebook","instagram","youtube","gmail","outlook","hotmail",
        "yahoo","amazon","flipkart","myntra","snapdeal","paypal","paytm",
        "phonepe","gpay","bhim","whatsapp","telegram","twitter","x",
        "linkedin","netflix","primevideo","disney","apple","microsoft",
        "windows","icloud","adobe","dropbox","zoom","skype","uber","ola",
        "airbnb","booking","makeMyTrip","irctc","sbi","hdfc","icici","axis",
        "kotak","yesbank","indusind","bankofbaroda","pnb","canara",
        "unionbank","idfc","rbl","hsbc","citibank","standardchartered",
        "visa","mastercard","rupay","stripe","razorpay","cashfree",
        "shopify","godaddy","hostinger","bluehost","aws","azure",
        "cloudflare","digitalocean","github","gitlab","bitbucket",
        "reddit","quora","tiktok","snapchat","pinterest","discord",
        "steam","epicgames","playstation","xbox","nvidia","intel",
        "samsung","oneplus","xiaomi","oppo","vivo","realme",
        "jio","airtel","vodafone","idea","bsnl"
    ]

    # 🔥 Generic trust / phishing keywords
    trust_keywords = [
        "login","account","verify","verification","secure","security",
        "update","password","otp","signin","signup","bank","payment",
        "wallet","reset","confirm","identity","access","unlock"
    ]

    detected = []

    for word in brand_keywords:
        if word in text:
            detected.append(word)

    for word in trust_keywords:
        if word in text:
            detected.append(word)

    return list(set(detected))  # remove duplicates


# -----------------------------
# Health Check
# -----------------------------

@app.get("/")
def root():
    return {"status": "Backend running"}


# -----------------------------
# Main Analysis Endpoint
# -----------------------------

@app.post("/analyze")
def analyze_page(data: PageData):

    # 🔹 Backend detection
    detected_brands = detect_brands(data.text)

    # 🔹 Emotional analysis
    emotion_score, triggers = detect_emotion(data.text)

    # 🔹 Phishing model
    phishing_score = detect_phishing(
        data.url,
        data.hasPasswordField,
        detected_brands
    )

    # 🔹 Final combined score
    final_score = aggregate_risk(
        emotion=emotion_score,
        phishing=phishing_score
    )

    # -----------------------------
    # Response
    # -----------------------------

    return {
        "final_score": final_score,
        "emotion_score": emotion_score,
        "phishing_score": phishing_score,
        "triggers": triggers,
        "brands": detected_brands
    }