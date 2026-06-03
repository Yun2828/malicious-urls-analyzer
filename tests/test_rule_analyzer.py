from core.rule_analyzer import analyze_with_rules


SAFE_UNKNOWN_DOMAIN = "unknown-test-domain-12345.com"


def test_rules_low_score_for_clean_https_url():
    score, reasons = analyze_with_rules("https://www.google.com")

    assert score >= 0
    assert score <= 30
    assert isinstance(reasons, list)


def test_rules_flags_http():
    score, reasons = analyze_with_rules(f"http://{SAFE_UNKNOWN_DOMAIN}")

    assert score >= 15
    assert any("https" in reason.lower() for reason in reasons)


def test_rules_flags_unusual_protocol():
    score, reasons = analyze_with_rules(
        f"ftp://{SAFE_UNKNOWN_DOMAIN}/download/file.zip"
    )

    assert score >= 20
    assert any("protocol" in reason.lower() for reason in reasons)


def test_rules_flags_ip_hostname():
    score, reasons = analyze_with_rules("http://192.168.1.25/login")

    assert score >= 20
    assert any("ip address" in reason.lower() for reason in reasons)


def test_rules_flags_risky_tld():
    score, reasons = analyze_with_rules("http://unknown-test-domain-12345.xyz/login")

    assert score >= 10
    assert any("risky" in reason.lower() or "tld" in reason.lower() for reason in reasons)


def test_rules_flags_suspicious_keywords():
    score, reasons = analyze_with_rules(
        f"http://{SAFE_UNKNOWN_DOMAIN}/login/verify/account"
    )

    assert score > 0
    assert any("suspicious words" in reason.lower() for reason in reasons)


def test_rules_flags_brand_impersonation():
    score, reasons = analyze_with_rules(
        "http://microsoft-login-security.unknown-test-domain-12345.com/verify"
    )

    assert score > 0
    assert any("brand" in reason.lower() for reason in reasons)


def test_rules_does_not_flag_official_brand_domain_as_impersonation():
    score, reasons = analyze_with_rules("https://microsoft.com/account")

    assert not any("not on an official brand domain" in reason.lower() for reason in reasons)


def test_rules_flags_deep_login_path():
    score, reasons = analyze_with_rules(
        f"http://{SAFE_UNKNOWN_DOMAIN}/about/reports/december/login/account"
    )

    assert score > 0
    assert any("deep path" in reason.lower() for reason in reasons)


def test_rules_flags_query_parameters():
    score, reasons = analyze_with_rules(
        f"https://{SAFE_UNKNOWN_DOMAIN}/search?q=test"
    )

    assert score >= 5
    assert any("query" in reason.lower() for reason in reasons)


def test_rules_flags_token_or_session_data():
    score, reasons = analyze_with_rules(
        f"https://{SAFE_UNKNOWN_DOMAIN}/login?user=abc&session=123"
    )

    assert score >= 10
    assert any("token" in reason.lower() or "session" in reason.lower() for reason in reasons)


def test_rules_flags_url_encoded_characters():
    score, reasons = analyze_with_rules(
        f"https://{SAFE_UNKNOWN_DOMAIN}/search?q=hello%20world"
    )

    assert score >= 5
    assert any("encoded" in reason.lower() for reason in reasons)


def test_rules_flags_downloadable_file():
    score, reasons = analyze_with_rules(
        f"http://{SAFE_UNKNOWN_DOMAIN}/download/update.exe"
    )

    assert score >= 20
    assert any("downloadable" in reason.lower() or "executable" in reason.lower() for reason in reasons)


def test_rules_flags_typo_similarity():
    score, reasons = analyze_with_rules("https://g00gle.com")

    assert score > 0
    assert any("similar to the known brand" in reason.lower() for reason in reasons)


def test_rules_score_never_exceeds_100():
    score, reasons = analyze_with_rules(
        "ftp://192.168.1.25/free/microsoft/login/verify/account/password/update.exe?user=abc&token=123%20abc"
    )

    assert score <= 100