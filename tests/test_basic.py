# tests/test_basic.py

from app import is_valid_url
from feature_extractor import extract_features
from rule_analyzer import analyze_rules
from predictor import analyze_url


def test_empty_url_is_invalid():
    is_valid, message = is_valid_url("")
    assert is_valid is False
    assert message == "Please enter a URL."


def test_url_missing_protocol_is_invalid():
    is_valid, message = is_valid_url("google.com")
    assert is_valid is False
    assert "Missing protocol" in message


def test_url_missing_hostname_is_invalid():
    is_valid, message = is_valid_url("https://")
    assert is_valid is False
    assert "hostname" in message.lower() or "domain" in message.lower()


def test_valid_https_url_is_valid():
    is_valid, message = is_valid_url("https://www.google.com")
    assert is_valid is True
    assert message == "Valid URL"


def test_extract_features_returns_expected_keys():
    features = extract_features(
        "https://www.example.com/login/reset?user=abc&token=123#top"
    )

    expected_keys = [
        "url_length",
        "domain_length",
        "num_dots",
        "uses_https",
        "has_ip_address",
        "num_suspicious_words",
        "path_length",
        "query_length",
    ]

    for key in expected_keys:
        assert key in features


def test_https_feature_is_detected():
    features = extract_features("https://www.example.com")
    assert features["uses_https"] == 1


def test_http_feature_is_detected():
    features = extract_features("http://www.example.com")
    assert features["uses_https"] == 0


def test_ip_address_feature_is_detected():
    features = extract_features("http://192.168.1.25/login")
    assert features["has_ip_address"] == 1


def test_rule_analyzer_flags_http():
    result = analyze_rules("http://www.example.com")

    assert result["rule_score"] > 0
    assert any(
        "HTTPS" in warning or "http" in warning.lower()
        for warning in result["warnings"]
    )


def test_rule_analyzer_flags_ip_address():
    result = analyze_rules("http://192.168.1.25/login")

    assert result["rule_score"] > 0
    assert any("IP" in warning for warning in result["warnings"])


def test_predictor_returns_expected_fields():
    result = analyze_url("https://www.google.com")

    assert "final_score" in result
    assert "category" in result
    assert "warnings" in result
    assert "rule_score" in result
    assert "ml_score" in result


def test_bad_url_gets_higher_score_than_good_url():
    good_result = analyze_url("https://www.google.com")
    bad_result = analyze_url(
        "http://192.168.1.25/login/reset?user=admin&session=abc123"
    )

    assert bad_result["final_score"] > good_result["final_score"]
