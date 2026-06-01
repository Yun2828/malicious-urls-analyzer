import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from feature_extractor import extract_features

DATA_PATH = "data/sample_urls.csv"
MODEL_PATH = "models/url_random_forest.pkl"


def main():
    df = pd.read_csv(DATA_PATH)
    features = pd.DataFrame([extract_features(url) for url in df["url"]])
    labels = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.3, random_state=42, stratify=labels
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, predictions))
    print(classification_report(y_test, predictions))

    package = {
        "model": model,
        "feature_columns": list(features.columns),
    }
    joblib.dump(package, MODEL_PATH)
    print(f"Saved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
