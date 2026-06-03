from pathlib import Path
import sys

import joblib
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

from core.feature_extractor import extract_features


PROCESSED_DATA_PATH = BASE_DIR / "data" / "processed" / "processed_urls.csv"
MODEL_PATH = BASE_DIR / "models" / "logistic_regression.pkl"
RESULTS_PATH = BASE_DIR / "models" / "logistic_regression_results.txt"

RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 3
N_JOBS = 4
SAMPLE_SIZE = 50000


def load_data() -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(PROCESSED_DATA_PATH)

    if SAMPLE_SIZE and len(df) > SAMPLE_SIZE:
        df, _ = train_test_split(
            df,
            train_size=SAMPLE_SIZE,
            random_state=RANDOM_STATE,
            stratify=df["binary_label"],
        )

    feature_rows = [extract_features(url) for url in df["url"]]

    X = pd.DataFrame(feature_rows).fillna(0)
    y = df["binary_label"]

    return X, y


def evaluate_model(model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    y_pred = model.predict(X_test)

    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_malicious": precision_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        ),
        "recall_malicious": recall_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        ),
        "f1_malicious": f1_score(
            y_test,
            y_pred,
            pos_label=1,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(
            y_test,
            y_pred,
            target_names=["benign", "malicious"],
            zero_division=0,
        ),
    }


def write_results_report(metrics: dict, best_params: dict, best_cv_score: float):
    report_text = f"""
Logistic Regression Results
===========================

Best Parameters
---------------
{best_params}

Best Cross-Validation F1
------------------------
{best_cv_score}

Test Metrics
------------
Accuracy: {metrics["accuracy"]}
Precision malicious: {metrics["precision_malicious"]}
Recall malicious: {metrics["recall_malicious"]}
F1 malicious: {metrics["f1_malicious"]}

Confusion Matrix
----------------
{metrics["confusion_matrix"]}

Classification Report
---------------------
{metrics["classification_report"]}
""".strip()

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(report_text, encoding="utf-8")


def main():
    X, y = load_data()

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    param_grid = {
        "model__C": [0.1, 1.0, 10.0],
        "model__penalty": ["l1", "l2"],
    }

    grid_search = GridSearchCV(
        estimator=pipeline,
        param_grid=param_grid,
        scoring="f1",
        cv=CV_FOLDS,
        n_jobs=N_JOBS,
        verbose=1,
    )

    grid_search.fit(X_train, y_train)

    best_model = grid_search.best_estimator_
    best_params = grid_search.best_params_
    best_cv_score = grid_search.best_score_

    metrics = evaluate_model(best_model, X_test, y_test)

    package = {
        "model_name": "logistic_regression",
        "model": best_model,
        "feature_columns": feature_columns,
        "metrics": metrics,
        "best_params": best_params,
        "best_cv_score": best_cv_score,
        "classification_type": "binary",
        "binary_label_meaning": {
            0: "benign",
            1: "malicious",
        },
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(package, MODEL_PATH)

    write_results_report(metrics, best_params, best_cv_score)

    print(f"Saved Logistic Regression model to: {MODEL_PATH}")
    print(f"Saved Logistic Regression report to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()