# URL Safety Checker V1

A beginner-friendly prototype that checks URLs using:

- URL input validation
- URL component parsing
- Feature extraction
- Rule-based security checks
- One machine learning model: RandomForestClassifier
- Streamlit web interface
- Risk score with explanations

## Project Structure

```text
url_safety_checker_v1/
├── app.py
├── feature_extractor.py
├── rule_analyzer.py
├── predictor.py
├── train_model.py
├── requirements.txt
├── data/
│   └── sample_urls.csv
└── models/
    └── url_random_forest.pkl   # created after training
```

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the model

```bash
python train_model.py
```

This creates:

```text
models/url_random_forest.pkl
```

The `.pkl` file stores the trained machine learning model so the Streamlit app can reuse it without retraining every time.

### 3. Start the Streamlit app

```bash
streamlit run app.py
```

## Labels in the dataset

- `0` = safe
- `1` = malicious/suspicious

## Important Note

The included dataset is tiny and only for learning. A real project needs a larger, verified dataset of safe and malicious URLs.
