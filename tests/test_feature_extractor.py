from core.feature_extractor import (
    parse_url,
    extract_features,
    has_ip_address,
    shannon_entropy,
)


def test_parse_url_basic_https_domain():
    result = parse_url("https://www.google.com")

    assert result["protocol"] == "https"
    assert result["hostname"] == "www.google.com"
    assert result["subdomain"] == "www"
    assert result["domain_name"] == "google.com"
    assert result["path"] == ""
    assert result["query"] == ""
    assert result["query_params"] == {}
    assert result["fragment"] == ""


def test_parse_url_with_path_query_and_fragment():
    result = parse_url(
        "https://login.example.com/account/reset?user=abc&token=123#top"
    )

    assert result["protocol"] == "https"
    assert result["hostname"] == "login.example.com"
    assert result["subdomain"] == "login"
    assert result["domain_name"] == "example.com"
    assert result["path"] == "/account/reset"
    assert result["query"] == "user=abc&token=123"
    assert result["query_params"] == {
        "user": ["abc"],
        "token": ["123"],
    }
    assert result["fragment"] == "top"


def test_has_ip_address_detects_valid_ip():
    assert has_ip_address("192.168.1.25") == 1


def test_has_ip_address_rejects_domain():
    assert has_ip_address("www.google.com") == 0


def test_has_ip_address_rejects_invalid_ip():
    assert has_ip_address("999.999.999.999") == 0


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_extract_features_returns_expected_keys():
    features = extract_features(
        "https://www.example.com/login/reset?user=abc&token=123#top"
    )

    expected_keys = [
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
    ]

    for key in expected_keys:
        assert key in features


def test_extract_features_detects_https():
    features = extract_features("https://www.example.com")

    assert features["uses_https"] == 1
    assert features["uses_http"] == 0


def test_extract_features_detects_http():
    features = extract_features("http://www.example.com")

    assert features["uses_https"] == 0
    assert features["uses_http"] == 1


def test_extract_features_detects_ip_address():
    features = extract_features("http://192.168.1.25/login")

    assert features["has_ip_address"] == 1


def test_extract_features_detects_query_params():
    features = extract_features("https://example.com/login?user=abc&token=123")

    assert features["has_query"] == 1
    assert features["num_query_params"] == 2


def test_extract_features_detects_percent_encoding():
    features = extract_features("https://example.com/search?q=hello%20world")

    assert features["has_percent_encoding"] == 1


def test_extract_features_detects_fragment():
    features = extract_features("https://example.com/page#section1")

    assert features["has_fragment"] == 1


def test_extract_features_detects_suspicious_keywords():
    features = extract_features("http://example.com/login/verify/account")

    assert features["suspicious_keyword_count"] >= 3


def test_extract_features_detects_brand_words():
    features = extract_features("http://microsoft-login.example.com")

    assert features["brand_keyword_count"] >= 1


def test_extract_features_detects_risky_tld():
    features = extract_features("http://example.xyz/login")

    assert features["risky_tld"] == 1


def test_extract_features_detects_deep_path():
    features = extract_features(
        "http://example.com/a/b/c/login"
    )

    assert features["deep_path"] == 1


def test_extract_features_detects_executable_in_path():
    features = extract_features("http://example.com/download/update.exe")

    assert features["executable_in_path"] == 1