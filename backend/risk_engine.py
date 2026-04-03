def calculate_div_risk(emotion_score, phishing_score):
    return (0.6 * phishing_score) + (0.4 * emotion_score)


def get_div_weight(has_sensitive, brand_detected, emotion_score):
    if has_sensitive:
        return 0.5
    elif brand_detected:
        return 0.2
    elif emotion_score > 0.6:
        return 0.2
    else:
        return 0.1


def aggregate_risk(div_results):
    total = 0
    weight_sum = 0
    risky_divs = []

    for i, risk, weight in div_results:
        total += risk * weight
        weight_sum += weight

        if risk > 0.45:
            risky_divs.append(i)

    final_risk = total / weight_sum if weight_sum > 0 else 0

    return final_risk, risky_divs