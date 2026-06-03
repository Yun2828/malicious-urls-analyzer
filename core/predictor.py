from pathlib import Path

import joblib
import pandas as pd

from core.feature_extractor import extract_features, parse_url
from core.rule_analyzer import analyze_with_rules
from core.reputation import get_domain_reputation


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "models" / "weighted_ensemble.pkl"


def load_model_package() -> dict:
    return joblib.load(MODEL_PATH)

def load_model() -> dict:
    return load_model_package()

def classify_score(score: int) -> str:
    if score <= 30:
        return "Low Risk / Likely Safe"
    if score <= 69:
        return "Medium Risk / Suspicious"
    return "High Risk / Likely Malicious"


def get_malicious_probability(model, X: pd.DataFrame) -> float:
    probabilities = model.predict_proba(X)
    return float(probabilities[0][1])


def explain_ml_score(ml_score: int, model_probabilities: dict) -> list[str]:
    explanations = []

    if ml_score >= 70:
        explanations.append(
            "The machine learning ensemble found this URL pattern similar to malicious URLs in the training dataset."
        )
    elif ml_score >= 31:
        explanations.append(
            "The machine learning ensemble found some suspicious patterns, but confidence is moderate."
        )
    else:
        explanations.append(
            "The machine learning ensemble found the URL pattern closer to benign examples."
        )

    for model_name, details in model_probabilities.items():
        probability = round(details["malicious_probability"] * 100)
        weight = round(details["weight"] * 100)
        if model_name == "logistic_regression":
            model = "Logistic Regression Model"
        if model_name == "random_forest":
            model = "Random Forest Model"
        explanations.append(
            f"{model} predicted {probability}% malicious probability with {weight}% ensemble weight."
        )

    return explanations


def predict_url(url: str) -> dict:
    parts = parse_url(url)
    domain_name = parts.get("domain_name", "")

    features = extract_features(url)
    rule_score, reasons = analyze_with_rules(url)
    reputation = get_domain_reputation(domain_name)

    if reputation["is_tranco_domain"] and rule_score == 0:
        return {
            "final_score": 5,
            "category": classify_score(5),
            "rule_score": 0,
            "ml_score": 5,
            "reasons": [
                f"Domain appears in Tranco top domains with rank {reputation['tranco_rank']}",
            ],
            "ml_reasons": [
                f"ML scoring was bypassed because {domain_name} is ranked #{reputation['tranco_rank']} in Tranco."
            ],
            "features": features,
            "model_probabilities": {},
            "ensemble_strategy": "Tranco reputation low-risk override",
            "classification_type": "binary",
        }

    package = load_model()

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
    ml_reasons = explain_ml_score(ml_score, model_probabilities)
    final_score = round((0.5 * rule_score) + (0.5 * ml_score))

    return {
        "final_score": final_score,
        "category": classify_score(final_score),
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_reasons": ml_reasons,
        "reasons": reasons,
        "features": features,
        "model_probabilities": model_probabilities,
        "ensemble_strategy": "Weighted probability using malicious-class F1 score",
        "classification_type": package.get("classification_type", "binary"),
    }