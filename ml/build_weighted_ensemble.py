from pathlib import Path

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[1]

LOGISTIC_MODEL_PATH = BASE_DIR / "models" / "logistic_regression.pkl"
RANDOM_FOREST_MODEL_PATH = BASE_DIR / "models" / "random_forest.pkl"
ENSEMBLE_MODEL_PATH = BASE_DIR / "models" / "weighted_ensemble.pkl"
ENSEMBLE_REPORT_PATH = BASE_DIR / "models" / "weighted_ensemble_report.txt"
ENSEMBLE_RESULTS_PATH = BASE_DIR / "models" / "weighted_ensemble_results.json"


def load_model_package(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Missing model file: {path}")

    return joblib.load(path)


def calculate_weights(model_packages: dict) -> dict:
    f1_scores = {
        model_name: package["metrics"]["f1_malicious"]
        for model_name, package in model_packages.items()
    }

    total_f1 = sum(f1_scores.values())

    if total_f1 == 0:
        equal_weight = 1 / len(f1_scores)
        return {
            model_name: equal_weight
            for model_name in f1_scores
        }

    return {
        model_name: f1 / total_f1
        for model_name, f1 in f1_scores.items()
    }


def validate_feature_columns(model_packages: dict) -> list[str]:
    feature_columns_by_model = {
        model_name: package["feature_columns"]
        for model_name, package in model_packages.items()
    }

    first_model_name = next(iter(feature_columns_by_model))
    first_columns = feature_columns_by_model[first_model_name]

    for model_name, columns in feature_columns_by_model.items():
        if columns != first_columns:
            raise ValueError(
                f"Feature columns mismatch between {first_model_name} and {model_name}"
            )

    return first_columns


def write_ensemble_report(model_packages: dict, model_weights: dict):
    rows = []

    for model_name, package in model_packages.items():
        metrics = package["metrics"]

        rows.append(
            {
                "model": model_name,
                "accuracy": metrics["accuracy"],
                "precision_malicious": metrics["precision_malicious"],
                "recall_malicious": metrics["recall_malicious"],
                "f1_malicious": metrics["f1_malicious"],
                "ensemble_weight": model_weights[model_name],
                "best_params": package["best_params"],
                "best_cv_score": package["best_cv_score"],
                "confusion_matrix": metrics["confusion_matrix"],
            }
        )

    results_df = pd.DataFrame(rows)
    results_df = results_df.sort_values(by="f1_malicious", ascending=False)

    report_text = f"""
Weighted Ensemble Report
========================

Weighting Formula
-----------------
weight = model_f1 / sum(all_f1_scores)

Primary Score
-------------
F1 score for malicious class

Secondary Safety Metric
-----------------------
Recall for malicious class


Model Comparison
----------------
{results_df.to_string(index=False)}
""".strip()

    ENSEMBLE_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ENSEMBLE_REPORT_PATH.write_text(report_text, encoding="utf-8")

    results_df.to_json(
        ENSEMBLE_RESULTS_PATH,
        orient="records",
        indent=4,
    )


def main():
    model_packages = {
        "logistic_regression": load_model_package(LOGISTIC_MODEL_PATH),
        "random_forest": load_model_package(RANDOM_FOREST_MODEL_PATH),
    }

    feature_columns = validate_feature_columns(model_packages)
    model_weights = calculate_weights(model_packages)

    ensemble_package = {
        "classification_type": "binary",
        "future_multiclass_ready": True,
        "binary_label_meaning": {
            0: "benign",
            1: "malicious",
        },
        "multiclass_label_meaning": {
            0: "benign",
            1: "phishing",
            2: "malware",
            3: "defacement",
        },
        "models": {
            model_name: package["model"]
            for model_name, package in model_packages.items()
        },
        "model_weights": model_weights,
        "feature_columns": feature_columns,
        "individual_model_metrics": {
            model_name: package["metrics"]
            for model_name, package in model_packages.items()
        },
        "individual_best_params": {
            model_name: package["best_params"]
            for model_name, package in model_packages.items()
        },
        "weighting_strategy": "weight = model_f1 / sum(all_f1_scores)",
        "primary_score": "f1_malicious",
        "secondary_score": "recall_malicious",
    }

    ENSEMBLE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(ensemble_package, ENSEMBLE_MODEL_PATH)

    write_ensemble_report(model_packages, model_weights)

    print(f"Saved weighted ensemble to: {ENSEMBLE_MODEL_PATH}")
    print(f"Saved weighted ensemble report to: {ENSEMBLE_REPORT_PATH}")
    print(f"Saved weighted ensemble results to: {ENSEMBLE_RESULTS_PATH}")


if __name__ == "__main__":
    main()