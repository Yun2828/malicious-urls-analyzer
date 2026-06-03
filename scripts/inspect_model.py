import joblib
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "models" / "weighted_ensemble.pkl"

package = joblib.load(MODEL_PATH)

print("Loaded successfully")
print("Object type:", type(package))

if isinstance(package, dict):
    print("Keys:", package.keys())

    if "model" in package:
        print("Model type:", type(package["model"]))

    if "feature_columns" in package:
        print("Feature columns:")
        for col in package["feature_columns"]:
            print("-", col)
else:
    print("Model:", package)