from core.feature_extractor import parse_url, RISKY_TLDS, SUSPICIOUS_KEYWORDS, has_ip_address
from core.reputation import get_domain_reputation
from core.brand_analyzer import analyze_brand_impersonation


def analyze_with_rules(url: str) -> tuple[int, list[str]]:
    parts = parse_url(url)

    protocol = parts.get("protocol", "")
    hostname = parts.get("hostname", "")
    domain_name = parts.get("domain_name", "")
    path = parts.get("path", "")
    query = parts.get("query", "")

    lower_url = url.lower()

    reputation = get_domain_reputation(domain_name)
    brand = analyze_brand_impersonation(url, domain_name)

    score = 0
    reasons = []

    if reputation["is_tranco_domain"]:
        reasons.append(
        f"Positive reputation signal: domain appears in Tranco top domains with rank {reputation['tranco_rank']}"
        )

    if protocol not in ["http", "https"]:
        score += 20
        reasons.append(f"Uses unusual protocol: {protocol}")

    if protocol == "http" and not reputation["is_tranco_domain"]:
        score += 15
        reasons.append("Does not use HTTPS")

    if protocol in ["ftp", "smtp", "ldap"]:
        score += 15
        reasons.append("Protocol is not normally used for regular web browsing")

    if has_ip_address(hostname):
        score += 20
        reasons.append("Hostname is an IP address instead of a normal domain")
    
    suffix = parts.get("suffix", "")
    if suffix and f".{suffix}" in RISKY_TLDS:
        score += 10
        reasons.append(f"Uses a risky or commonly abused TLD: .{suffix}")

    keyword_hits = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]

    if keyword_hits:
        added = min(len(keyword_hits) * 5, 25)
        score += added
        reasons.append("Contains suspicious words: " + ", ".join(keyword_hits))

    if brand["brand_impersonation"]:
        score += 20
        reasons.append("Mentions a known brand but is not on an official brand domain")

    if brand["typo_similarity_risk"]:
        score += 20
        closest_brand = brand["closest_brand"]
        reasons.append(f"Domain is similar to the known brand: {closest_brand}")
        
    if path.count("/") >= 3 and any(
        word in lower_url for word in ["login", "account", "verify"]
    ):
        score += 15
        reasons.append(
            "Deep path combined with login/account wording can indicate a hidden phishing page"
        )

    if query:
        score += 5
        reasons.append("Contains query parameters after ?")

    if any(token in lower_url for token in ["token=", "session=", "user=", "email="]):
        score += 10
        reasons.append(
            "Query string appears to include user, token, session, or email data"
        )

    if "%20" in lower_url or "%40" in lower_url:
        score += 5
        reasons.append("Contains URL encoded characters such as %20 or %40")

    if any(path.lower().endswith(ext) for ext in [".exe", ".zip", ".scr", ".dll"]):
        score += 20
        reasons.append("Path points to a downloadable executable or archive")

    if reputation["is_tranco_domain"] and score <= 20:
        score = 0

    if not reasons:
        reasons.append("No major rule-based warning signs found")

    return min(score, 100), reasons


def analyze_rules(url: str) -> tuple[int, list[str]]:
    return analyze_with_rules(url)