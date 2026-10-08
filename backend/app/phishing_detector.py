from urllib.parse import urlparse
import os
import pickle
import re

from app.threat_intelligence import check_url_threat_intelligence


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "example",
    "account", "free", "bonus", "password", "wallet",
    "win", "gift", "claim", "limited", "urgent",
    "confirm", "signin", "reset",
]


FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "has_http",
    "has_at_symbol",
    "has_hyphen",
    "dot_count",
    "digit_count",
    "keyword_count",
    "has_ip_address",
]


def load_model():
    if not os.path.exists(MODEL_PATH):
        return None

    try:
        with open(MODEL_PATH, "rb") as file:
            return pickle.load(file)
    except Exception:
        return None


MODEL = load_model()


def extract_url_features(url: str) -> dict:
    original_url = url.strip()
    url_lower = original_url.lower()

    parsed_url = urlparse(url_lower)
    domain = parsed_url.netloc

    return {
        "url_length": len(url_lower),
        "domain_length": len(domain),
        "has_http": 1 if url_lower.startswith("https://") else 0,
        "has_at_symbol": 1 if "@" in url_lower else 0,
        "has_hyphen": 1 if "-" in domain else 0,
        "dot_count": domain.count("."),
        "digit_count": sum(char.isdigit() for char in domain),
        "keyword_count": sum(
            1 for word in SUSPICIOUS_KEYWORDS if word in url_lower
        ),
        "has_ip_address": 1
        if bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", domain))
        else 0,
    }


def get_rule_based_result(url: str, features: dict) -> dict:
    url_lower = url.lower()
    score = 0
    reasons = []

    if features["url_length"] > 50:
        score += 1
        reasons.append("URL is very long")

    if features["keyword_count"] > 0:
        score += features["keyword_count"]
        for word in SUSPICIOUS_KEYWORDS:
            if word in url_lower:
                reasons.append(f"Contains suspicious keyword: {word}")

    if features["has_at_symbol"]:
        score += 2
        reasons.append("URL contains @ symbol")

    if not features["has_http"]:
        score += 1
        reasons.append("URL does not use HTTPS")

    if features["has_hyphen"]:
        score += 1
        reasons.append("Domain contains hyphen")

    if features["dot_count"] >= 3:
        score += 1
        reasons.append("URL has many subdomains")

    if features["digit_count"] > 0:
        score += 1
        reasons.append("Domain contains numbers")

    if features["has_ip_address"]:
        score += 2
        reasons.append("URL uses an IP address instead of a normal domain")

    if score >= 4:
        result = "Phishing"
        risk_level = "High"
        is_phishing = True
        advice = "Do not open this link. It may be trying to steal your information."
    elif score >= 2:
        result = "Suspicious"
        risk_level = "Medium"
        is_phishing = True
        advice = "Be careful. Verify the source before opening this link."
    else:
        result = "Safe"
        risk_level = "Low"
        is_phishing = False
        advice = "This link looks safe based on basic checks."

    return {
        "score": score,
        "result": result,
        "risk_level": risk_level,
        "is_phishing": is_phishing,
        "reasons": reasons,
        "advice": advice,
    }


def get_ml_prediction(features: dict):
    if MODEL is None:
        return None

    try:
        feature_row = [[features[column] for column in FEATURE_COLUMNS]]
        prediction = MODEL.predict(feature_row)[0]

        confidence = None
        if hasattr(MODEL, "predict_proba"):
            probabilities = MODEL.predict_proba(feature_row)[0]
            confidence = round(float(max(probabilities)) * 100, 2)

        return {
            "prediction": prediction,
            "confidence": confidence,
        }
    except Exception:
        return None


def combine_results(rule_result: dict, ml_result: dict | None) -> dict:
    rule_verdict = rule_result["result"]

    if ml_result is None:
        final_result = rule_verdict
        ml_prediction = "Model not available"
        ml_confidence = None
    else:
        ml_prediction = ml_result["prediction"]
        ml_confidence = ml_result["confidence"]

        if rule_verdict == "Phishing" or ml_prediction == "Phishing":
            final_result = "Phishing"
        elif rule_verdict == "Suspicious" or ml_prediction == "Suspicious":
            final_result = "Suspicious"
        else:
            final_result = "Safe"

    if final_result == "Phishing":
        risk_level = "High"
        is_phishing = True
        advice = "Do not open this link. It may be trying to steal your information."
    elif final_result == "Suspicious":
        risk_level = "Medium"
        is_phishing = True
        advice = "Be careful. Verify the source before opening this link."
    else:
        risk_level = "Low"
        is_phishing = False
        advice = "This link looks safe based on the current checks."

    return {
        "result": final_result,
        "verdict": final_result,
        "risk_level": risk_level,
        "is_phishing": is_phishing,
        "advice": advice,
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
    }


def analyze_url(url: str):
    original_url = url.strip()

    features = extract_url_features(original_url)
    rule_result = get_rule_based_result(original_url, features)
    ml_result = get_ml_prediction(features)
    final = combine_results(rule_result, ml_result)

    threat_intel = check_url_threat_intelligence(original_url)

    reasons = list(rule_result["reasons"])

    if ml_result is not None:
        reasons.append(f"AI model prediction: {ml_result['prediction']}")
        if ml_result["confidence"] is not None:
            reasons.append(f"AI confidence: {ml_result['confidence']}%")
    else:
        reasons.append("AI model not available, used rule-based detection only")

    if threat_intel.get("available"):
        reasons.append(f"VirusTotal verdict: {threat_intel.get('verdict')}")
        reasons.append(
            f"VirusTotal stats - malicious: {threat_intel.get('malicious', 0)}, "
            f"suspicious: {threat_intel.get('suspicious', 0)}"
        )

        vt_verdict = threat_intel.get("verdict")

        if vt_verdict == "Phishing":
            final["result"] = "Phishing"
            final["verdict"] = "Phishing"
            final["risk_level"] = "High"
            final["is_phishing"] = True
            final["advice"] = (
                "Do not open this link. VirusTotal has flagged it as dangerous."
            )

        elif vt_verdict == "Suspicious" and final["result"] == "Safe":
            final["result"] = "Suspicious"
            final["verdict"] = "Suspicious"
            final["risk_level"] = "Medium"
            final["is_phishing"] = True
            final["advice"] = "Be careful. VirusTotal found suspicious signals."
    else:
        reasons.append(
            f"VirusTotal unavailable: "
            f"{threat_intel.get('error') or threat_intel.get('message')}"
        )

    return {
        "url": original_url,
        "score": rule_result["score"],
        "risk_score": rule_result["score"],
        "risk_level": final["risk_level"],
        "result": final["result"],
        "verdict": final["verdict"],
        "is_phishing": final["is_phishing"],
        "reasons": reasons,
        "features": features,
        "ml_prediction": final["ml_prediction"],
        "ml_confidence": final["ml_confidence"],
        "advice": final["advice"],
        "threat_intelligence": threat_intel,
    }