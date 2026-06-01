import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import GaussianNB

from feature_extractor import extract_features


DATA_PATH = "../data/your_dataset_name.csv"
MODEL_PATH = "../models/best_model.pkl"


def load_dataset():
    df = pd.read_csv(DATA_PATH)

    # Change these if your dataset column names are different
    urls = df["url"]
    labels = df["label"]

    features = pd.DataFrame([extract_features(url) for url in urls])
    features = features.fillna(0)

    return features, labels


def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    return {
        "name": name,
        "model": model,
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, average="weighted", zero_division=0),
        "recall": recall_score(y_test, predictions, average="weighted", zero_division=0),
        "f1": f1_score(y_test, predictions, average="weighted", zero_division=0),
        "report": classification_report(y_test, predictions, zero_division=0),
    }


def main():
    X, y = load_dataset()

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "Naive Bayes": GaussianNB(),
    }

    results = []

    for name, model in models.items():
        print(f"\nTraining {name}...")
        result = evaluate_model(name, model, X_train, X_test, y_train, y_test)
        results.append(result)

        print(result["report"])

    results_table = pd.DataFrame([
        {
            "model": result["name"],
            "accuracy": result["accuracy"],
            "precision": result["precision"],
            "recall": result["recall"],
            "f1": result["f1"],
        }
        for result in results
    ]).sort_values(by="f1", ascending=False)

    print("\nModel comparison:")
    print(results_table)

    best_model_name = results_table.iloc[0]["model"]
    best_result = next(result for result in results if result["name"] == best_model_name)

    package = {
        "model": best_result["model"],
        "model_name": best_result["name"],
        "feature_columns": feature_columns,
        "metrics": {
            "accuracy": best_result["accuracy"],
            "precision": best_result["precision"],
            "recall": best_result["recall"],
            "f1": best_result["f1"],
        },
    }

    joblib.dump(package, MODEL_PATH)

    print(f"\nBest model: {best_result['name']}")
    print(f"Saved model package to: {MODEL_PATH}")


if __name__ == "__main__":
    main()