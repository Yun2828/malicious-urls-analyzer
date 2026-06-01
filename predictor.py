import joblib
import pandas as pd
from feature_extractor import extract_features
from rule_analyzer import analyze_with_rules

MODEL_PATH = "models/url_random_forest.pkl"


def load_model():
    return joblib.load(MODEL_PATH)


def classify_score(score: int) -> str:
    if score <= 30:
        return "Low Risk / Likely Safe"
    if score <= 69:
        return "Medium Risk / Suspicious"
    return "High Risk / Likely Malicious"


def predict_url(url: str) -> dict:
    package = load_model()
    model = package["model"]
    feature_columns = package["feature_columns"]

    features = extract_features(url)
    X = pd.DataFrame([features]).reindex(columns=feature_columns, fill_value=0)

    malicious_probability = model.predict_proba(X)[0][1]
    ml_score = round(malicious_probability * 100)

    rule_score, reasons = analyze_with_rules(url)
    final_score = round((0.5 * rule_score) + (0.5 * ml_score))

    return {
        "final_score": final_score,
        "category": classify_score(final_score),
        "rule_score": rule_score,
        "ml_score": ml_score,
        "reasons": reasons,
        "features": features,
    }
