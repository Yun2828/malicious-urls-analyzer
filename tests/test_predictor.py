import predictor


class FakeModel:
    def predict_proba(self, X):
        return [[0.20, 0.80]]


def fake_load_model():
    return {
        "model": FakeModel(),
        "feature_columns": [
            "url_length",
            "domain_length",
            "path_length",
            "query_length",
            "num_dots",
            "num_hyphens",
            "num_slashes",
            "num_digits",
            "uses_https",
            "uses_http",
            "uses_ftp_smtp_ldap",
            "has_ip_address",
            "has_query",
            "num_query_params",
            "has_percent_encoding",
            "has_fragment",
            "suspicious_keyword_count",
            "brand_keyword_count",
            "risky_tld",
            "domain_entropy",
            "deep_path",
            "executable_in_path",
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
    assert "reasons" in result
    assert "features" in result


def test_predict_url_ml_score_is_probability_times_100(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    result = predictor.predict_url("https://www.google.com")

    assert result["ml_score"] == 80


def test_predict_url_final_score_is_average_of_rule_and_ml(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    result = predictor.predict_url("https://www.google.com")

    expected_score = round((0.5 * result["rule_score"]) + (0.5 * result["ml_score"]))

    assert result["final_score"] == expected_score


def test_predict_url_bad_url_scores_higher_than_clean_url(monkeypatch):
    monkeypatch.setattr(predictor, "load_model", fake_load_model)

    clean_result = predictor.predict_url("https://www.google.com")
    bad_result = predictor.predict_url(
        "http://192.168.1.25/login/verify/account?user=admin&session=abc123"
    )

    assert bad_result["rule_score"] > clean_result["rule_score"]
    assert bad_result["final_score"] > clean_result["final_score"]