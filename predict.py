from pathlib import Path
import joblib
import pandas as pd
from src.feature_extraction import extract_features, FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "model" / "phishing_model.pkl"

def ensure_model():
    if not MODEL_PATH.exists():
        import subprocess, sys
        subprocess.run([sys.executable, str(ROOT / "src" / "train_model.py")], check=True)

def predict_url(url: str):
    ensure_model()
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]

    features = extract_features(url)
    X = pd.DataFrame([features])[FEATURE_NAMES]
    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    phishing_probability = float(probabilities[1])

    indicators = []
    if features["has_ip"]:
        indicators.append("The hostname uses an IP address.")
    if features["uses_https"] == 0:
        indicators.append("The URL does not use HTTPS.")
    if features["num_subdomains"] >= 2:
        indicators.append("The URL contains multiple subdomains.")
    if features["url_length"] >= 75:
        indicators.append("The URL is unusually long.")
    if features["num_at"] > 0:
        indicators.append("The URL contains an '@' character.")
    if features["has_suspicious_word"]:
        indicators.append("A security/account-related keyword appears in the URL.")
    if features["num_hyphens"] >= 3:
        indicators.append("The URL contains several hyphens.")
    if not indicators:
        indicators.append("No major URL-level warning indicators were detected.")

    risk = (
        "HIGH" if phishing_probability >= 0.70
        else "MEDIUM" if phishing_probability >= 0.40
        else "LOW"
    )

    return {
        "prediction": "POTENTIALLY PHISHING" if prediction == 1 else "LIKELY LEGITIMATE",
        "probability": round(phishing_probability * 100, 1),
        "risk": risk,
        "indicators": indicators,
    }
