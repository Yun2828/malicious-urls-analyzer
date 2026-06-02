from pathlib import Path

import joblib
import pandas as pd

from feature_extractor import extract_features, parse_url
from rule_analyzer import analyze_with_rules


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "weighted_ensemble.pkl"


TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "python.org",
}


def load_model_package() -> dict:
    return joblib.load(MODEL_PATH)


def classify_score(score: int) -> str:
    if score <= 30:
        return "Low Risk / Likely Safe"
    if score <= 69:
        return "Medium Risk / Suspicious"
    return "High Risk / Likely Malicious"


def get_malicious_probability(model, X: pd.DataFrame) -> float:
    probabilities = model.predict_proba(X)
    return float(probabilities[0][1])


def predict_url(url: str) -> dict:
    parts = parse_url(url)
    domain_name = parts.get("domain_name", "")

    features = extract_features(url)
    rule_score, reasons = analyze_with_rules(url)

    if domain_name in TRUSTED_DOMAINS:
        return {
            "final_score": 5,
            "category": classify_score(5),
            "rule_score": 0,
            "ml_score": 5,
            "reasons": ["Domain is trusted"],
            "features": features,
            "model_probabilities": {},
            "ensemble_strategy": "Trusted domain allowlist override",
            "classification_type": "binary",
        }

    package = load_model_package()

    models = package["models"]
    model_weights = package["model_weights"]
    feature_columns = package["feature_columns"]

    X = pd.DataFrame([features]).reindex(
        columns=feature_columns,
        fill_value=0,
    )

    model_probabilities = {}
    weighted_probability = 0.0

    for model_name, model in models.items():
        malicious_probability = get_malicious_probability(model, X)
        weight = model_weights[model_name]
        weighted_contribution = malicious_probability * weight

        model_probabilities[model_name] = {
            "malicious_probability": malicious_probability,
            "weight": weight,
            "weighted_contribution": weighted_contribution,
        }

        weighted_probability += weighted_contribution

    ml_score = round(weighted_probability * 100)
    final_score = round((0.5 * rule_score) + (0.5 * ml_score))

    return {
        "final_score": final_score,
        "category": classify_score(final_score),
        "rule_score": rule_score,
        "ml_score": ml_score,
        "reasons": reasons,
        "features": features,
        "model_probabilities": model_probabilities,
        "ensemble_strategy": "Weighted probability using malicious-class F1 score",
        "classification_type": package.get("classification_type", "binary"),
    }