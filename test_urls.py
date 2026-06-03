from core.rule_analyzer import analyze_with_rules


TEST_URLS = [
    "https://www.google.com",
    "http://example.com",
    "ftp://example.com/download/file.zip",
    "http://192.168.1.25/login",
    "http://example.xyz/login",
    "https://example.com/password/reset",
    "http://google-login-security.example.com",
    "https://google.com/login",
    "https://micros0ft.com/login",
    "https://microsoft-login.com/verify",
    "https://example.com/about/reports/december/login",
    "https://example.com/login?user=admin&session=abc123",
    "https://example.com/search?q=hello%20world",
    "http://example.com/download/update.exe",
    "ftp://free-microsoft-download.xyz/update.exe?token=abc123",
]


for url in TEST_URLS:
    score, reasons = analyze_with_rules(url)

    print("=" * 80)
    print("URL:", url)
    print("Score:", score)
    print("Reasons:")

    for reason in reasons:
        print("-", reason)