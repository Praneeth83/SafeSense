def aggregate_risk(emotion: float, phishing: float) -> float:
    return max(emotion, phishing)
