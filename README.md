# URL Safety Analyzer

A cybersecurity and machine learning prototype that checks whether a URL looks safe, suspicious, or potentially malicious.

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

The current version uses Logistic Regression and Random Forest, so XGBoost is optional.

### 2. Build Tranco reputation data

```bash
python3 scripts/build_tranco_reputation.py
```

This creates:

```text
data/reputation/tranco_top_domains.csv
```

### 3. Prepare the dataset

```bash
python3 scripts/prepare_dataset.py
```

This creates:

```text
data/processed/processed_urls.csv
data/processed/processed_data_report.txt
```

### 4. Train Logistic Regression

```bash
python3 training/train_logistic_regression.py
```

This creates a local model file:

```text
models/logistic_regression.pkl
```

### 5. Train Random Forest

```bash
python3 training/train_random_forest.py
```

This creates a local model file:

```text
models/random_forest.pkl
```

### 6. Build weighted ensemble

```bash
python3 training/build_weighted_ensemble.py
```

This creates:

```text
models/weighted_ensemble.pkl
models/weighted_ensemble_report.txt
models/weighted_ensemble_results.json
```

### 7. Run tests

```bash
pytest tests/ -v
```

### 8. Start the Streamlit app

```bash
streamlit run app.py
```

## Important GitHub Note

Model `.pkl` files can be large and should not be committed to GitHub.

Keep this in `.gitignore`:

```gitignore
.venv/
__pycache__/
*.pyc
.DS_Store
.pytest_cache/
.tranco/
models/*.pkl
models/*.joblib
```

## Current Version

This project is currently in Iteration 3.

### Iteration 1

Basic working prototype:

- Streamlit interface
- URL validation
- URL parsing
- Basic feature extraction
- Rule-based scoring
- Random Forest model
- Risk score and explanations
- Unit tests

### Iteration 2

Improved machine learning pipeline:

- Larger dataset
- Binary classification: benign vs malicious
- Separate training scripts
- Logistic Regression model
- Random Forest model
- Model evaluation using accuracy, precision, recall, F1 score, and confusion matrix
- Weighted ensemble model
- Model weights based on malicious-class F1 score

### Iteration 3

Improved URL intelligence and feature engineering:

- Tranco top-domain reputation signal
- Brand domain list
- Brand impersonation detection
- Typo-similarity detection for lookalike domains
- Better URL-only features such as entropy, path depth, query indicators, encoded characters, risky extensions, and reputation features

## How the System Works

The app takes a user-entered URL and processes it through two main systems:

```text
User URL
   ↓
URL validation
   ↓
URL parsing and feature extraction
   ↓
Rule-based analyzer
   ↓
Machine learning ensemble
   ↓
Final risk score and explanation
```

## Rule-Based Analysis

The rule-based analyzer checks for suspicious URL signals such as:

- Unusual protocols like `ftp`, `smtp`, or `ldap`
- Missing HTTPS
- IP address used as hostname
- Risky TLDs such as `.xyz`, `.top`, `.click`, `.biz`, or `.info`
- Suspicious keywords such as `login`, `verify`, `account`, `password`, `token`, and `session`
- Brand impersonation
- Lookalike brand domains such as `g00gle.com`
- Deep paths combined with login/account wording
- Query strings containing `user=`, `token=`, `session=`, or `email=`
- URL encoded characters such as `%20` or `%40`
- Risky downloadable file extensions such as `.exe`, `.zip`, `.scr`, and `.dll`

The rule score ranges from `0` to `100`.

## Machine Learning Analysis

The machine learning system uses binary classification:

```text
0 = benign
1 = malicious
```

Currently, the project trains:

- Logistic Regression
- Random Forest

Each model is evaluated using:

- Accuracy
- Precision for malicious class
- Recall for malicious class
- F1 score for malicious class
- Confusion matrix

## Weighted Ensemble

The final ML score is created using a weighted ensemble.

Each model receives a weight based on its malicious-class F1 score:

```text
weight = model_f1 / sum(all_model_f1_scores)
```

Then the ensemble malicious probability is calculated as:

```text
weighted_probability =
(logistic_regression_probability × logistic_regression_weight)
+
(random_forest_probability × random_forest_weight)
```

The ML score is:

```text
ML Score = weighted_probability × 100
```

The final score combines the rule-based score and ML score:

```text
Final Score = 50% Rule Score + 50% ML Score
```

## Tranco Reputation Signal

This project uses a local Tranco top-domain list as a reputation feature.

Tranco does not prove that a URL is safe. It only shows that a domain is popular or commonly visited.

Example:

```text
google.com
```

may receive a positive reputation signal because it appears in the Tranco top domains.

However, suspicious paths and query strings can still increase the risk score, even on a popular domain.

Example:

```text
https://google.com/download/file.zip
```

may still receive warnings because it contains a download path and archive file extension.

## Brand Impersonation Detection

The project uses a local brand-domain list:

```text
data/reputation/brand_domains.csv
```

Example:

```csv
brand,official_domain
google,google.com
microsoft,microsoft.com
microsoft,office.com
apple,apple.com
paypal,paypal.com
github,github.com
```

This helps detect suspicious URLs such as:

```text
http://google-login-security.example.com
https://microsoft-login.com/verify
https://g00gle.com
```

The brand analyzer checks:

- Whether a URL mentions a known brand
- Whether the registered domain is an official brand domain
- Whether the domain looks similar to a known brand domain
- Whether the domain uses phishing modifiers like `login`, `secure`, `verify`, `account`, or `support`

## Current Limitations

This project does not yet perform:

- Live webpage content scanning
- JavaScript analysis
- Redirect-chain analysis
- WHOIS/domain-age lookup
- VirusTotal or urlscan.io API checks
- File download sandboxing
- Real-time blacklist checking

These are planned for later iterations.

## Disclaimer

This project is a learning prototype. It should not be used as a final security decision system. A real-world malicious URL detector would require verified threat intelligence, stronger model validation, continuous updates, and multiple external reputation sources.