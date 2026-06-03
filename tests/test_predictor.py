import core.predictor as predictor


class FakeLogisticRegression:
    def predict_proba(self, X):
        return [[0.20, 0.80]]


class FakeRandomForest:
    def predict_proba(self, X):
        return [[0.40, 0.60]]


def fake_load_model():
    return {
        "classification_type": "binary",
        "models": {
            "logistic_regression": FakeLogisticRegression(),
            "random_forest": FakeRandomForest(),
        },
        "model_weights": {
            "logistic_regression": 0.5,
            "random_forest": 0.5,
        },
        "feature_columns": [
            "url_length",
            "domain_length",
            "registered_domain_length",
            "path_length",
            "query_length",
            "num_dots",
            "num_hyphens",
            "num_slashes",
            "num_digits",
            "digit_ratio",
            "domain_digit_ratio",
            "domain_hyphen_count",
            "uses_https",
            "uses_http",
            "uses_ftp_smtp_ldap",
            "has_ip_address",
            "has_query",
            "num_query_params",
            "has_percent_encoding",
            "encoded_char_count",
            "has_fragment",
            "suspicious_keyword_count",
            "brand_keyword_count",
            "brand_impersonation",
            "typo_similarity_risk",
            "brand_similarity_score",
            "risky_tld",
            "domain_entropy",
            "url_entropy",
            "subdomain_depth",
            "path_depth",
            "deep_path",
            "redirect_keyword_count",
            "executable_in_path",
            "is_tranco_domain",
            "tranco_rank",
            "domain_reputation_score",
        ],
    }


def test_classify_score_low_risk():
    assert predictor.classify_score(0) == "Low Risk / Likely Safe"
    assert predictor.classify_score(30) == "Low Risk / Likely Safe"


def test_classify_score_medium_risk():
    assert predictor.classify_score(31) == "Medium Risk / Suspicious"
    assert predictor.classify_score(69) == "Medium Risk / Suspicious"


def test_classify_score_high_risk():
    assert predictor.classify_score(70) == "High Risk / Likely Malicious"
    assert predictor.classify_score(100) == "High Risk / Likely Malicious"


def test_predict_url_returns_expected_fields(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    result = predictor.predict_url(
        "http://192.168.1.25/login?user=admin&session=abc123"
    )

    assert "final_score" in result
    assert "category" in result
    assert "rule_score" in result
    assert "ml_score" in result
    assert "ml_reasons" in result
    assert "reasons" in result
    assert "features" in result
    assert "model_probabilities" in result
    assert "ensemble_strategy" in result
    assert "classification_type" in result


def test_predict_url_ml_score_uses_weighted_average(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    result = predictor.predict_url("https://not-in-tranco-test-domain-12345.com")

    expected_probability = (0.80 * 0.5) + (0.60 * 0.5)
    expected_ml_score = round(expected_probability * 100)

    assert result["ml_score"] == expected_ml_score


def test_predict_url_final_score_is_average_of_rule_and_ml(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    result = predictor.predict_url("https://not-in-tranco-test-domain-12345.com")

    expected_score = round((0.5 * result["rule_score"]) + (0.5 * result["ml_score"]))

    assert result["final_score"] == expected_score


def test_predict_url_bad_url_scores_higher_than_clean_url(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    clean_result = predictor.predict_url("https://not-in-tranco-test-domain-12345.com")

    bad_result = predictor.predict_url(
        "http://192.168.1.25/login/verify/account?user=admin&session=abc123"
    )

    assert bad_result["rule_score"] > clean_result["rule_score"]
    assert bad_result["final_score"] > clean_result["final_score"]


def test_predict_url_tranco_clean_domain_bypasses_ml():
    result = predictor.predict_url("https://google.com")

    assert result["final_score"] == 5
    assert result["category"] == "Low Risk / Likely Safe"
    assert result["rule_score"] == 0
    assert result["ml_score"] == 5
    assert result["model_probabilities"] == {}
    assert result["ensemble_strategy"] == "Tranco reputation low-risk override"
    assert "ml_reasons" in result