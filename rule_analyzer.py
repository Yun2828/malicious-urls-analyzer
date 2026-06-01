from feature_extractor import parse_url, RISKY_TLDS, SUSPICIOUS_KEYWORDS, BRAND_WORDS


def analyze_with_rules(url: str) -> tuple[int, list[str]]:
    """Return a rule-based risk score from 0 to 100 and human-readable reasons."""
    parts = parse_url(url)
    protocol = parts["protocol"]
    hostname = parts["hostname"]
    path = parts["path"]
    query = parts["query"]
    lower_url = url.lower()
    score = 0
    reasons = []

    if protocol not in ["http", "https"]:
        score += 20
        reasons.append(f"Uses unusual protocol: {protocol}")

    if protocol == "http":
        score += 15
        reasons.append("Does not use HTTPS")

    if protocol in ["ftp", "smtp", "ldap"]:
        score += 15
        reasons.append("Protocol is not normally used for regular web browsing")

    if hostname and hostname.replace(".", "").isdigit():
        score += 20
        reasons.append("Hostname is an IP address instead of a normal domain")

    for tld in RISKY_TLDS:
        if hostname.endswith(tld):
            score += 10
            reasons.append(f"Uses a risky or commonly abused TLD: {tld}")
            break

    keyword_hits = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]
    if keyword_hits:
        added = min(len(keyword_hits) * 5, 25)
        score += added
        reasons.append("Contains suspicious words: " + ", ".join(keyword_hits))

    brand_hits = [word for word in BRAND_WORDS if word in lower_url]
    if brand_hits and not any(hostname.endswith(f"{brand}.com") for brand in brand_hits):
        score += 15
        reasons.append("Mentions a known brand but is not clearly on that brand's official domain")

    if path.count("/") >= 3 and any(word in lower_url for word in ["login", "account", "verify"]):
        score += 15
        reasons.append("Deep path combined with login/account wording can indicate a hidden phishing page")

    if query:
        score += 5
        reasons.append("Contains query parameters after ?")

    if any(token in lower_url for token in ["token=", "session=", "user=", "email="]):
        score += 10
        reasons.append("Query string appears to include user, token, session, or email data")

    if "%20" in lower_url or "%40" in lower_url:
        score += 5
        reasons.append("Contains URL encoded characters such as %20 or %40")

    if any(path.lower().endswith(ext) for ext in [".exe", ".zip", ".scr", ".dll"]):
        score += 20
        reasons.append("Path points to a downloadable executable or archive")

    return min(score, 100), reasons
