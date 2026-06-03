from core.feature_extractor import parse_url, RISKY_TLDS, SUSPICIOUS_KEYWORDS, has_ip_address
from core.reputation import get_domain_reputation
from core.brand_analyzer import analyze_brand_impersonation
from core.rule_explanations import (
    SUSPICIOUS_WORD_EXPLANATIONS,
    QUERY_TOKEN_EXPLANATIONS,
    ENCODING_EXPLANATIONS,
    FILE_EXTENSION_EXPLANATIONS,
)


def analyze_with_rules(url: str) -> tuple[int, list[str]]:
    parts = parse_url(url)

    protocol = parts.get("protocol", "")
    hostname = parts.get("hostname", "")
    domain_name = parts.get("domain_name", "")
    path = parts.get("path", "")
    query = parts.get("query", "")
    suffix = parts.get("suffix", "")

    lower_url = url.lower()
    lower_path = path.lower()

    reputation = get_domain_reputation(domain_name)
    brand = analyze_brand_impersonation(url, domain_name)

    score = 0
    reasons = []

    if reputation["is_tranco_domain"]:
        reasons.append(
            f"Positive reputation signal: domain appears in Tranco top domains with rank {reputation['tranco_rank']}. Popular domains are usually less suspicious, but risky paths or query strings can still increase risk."
        )

    if protocol not in ["http", "https"]:
        score += 20
        reasons.append(
            f"Uses unusual protocol: {protocol}. Normal websites usually use HTTP or HTTPS, so unusual protocols can be a warning sign."
        )

    if protocol == "http" and not reputation["is_tranco_domain"]:
        score += 15
        reasons.append(
            "Does not use HTTPS. Without HTTPS, the connection is not encrypted, which can make the URL less trustworthy."
        )

    if protocol in ["ftp", "smtp", "ldap"]:
        score += 15
        reasons.append(
            "Protocol is not normally used for regular web browsing. This can indicate a file transfer, mail, or directory-service link instead of a normal website."
        )

    if has_ip_address(hostname):
        score += 20
        reasons.append(
            "Hostname is an IP address instead of a normal domain. Malicious links sometimes use raw IP addresses to avoid recognizable domain names."
        )

    if suffix and f".{suffix}" in RISKY_TLDS:
        score += 10
        reasons.append(
            f"Uses a risky or commonly abused TLD: .{suffix}. Some low-cost or commonly abused TLDs appear more often in suspicious campaigns."
        )

    # Pull suspicious keyword explanations from dictionary
    keyword_hits = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in lower_url
    ]

    if keyword_hits:
        added = min(len(keyword_hits) * 5, 25)
        score += added

        for word in keyword_hits:
            explanation = SUSPICIOUS_WORD_EXPLANATIONS.get(
                word,
                f"The URL contains '{word}', which may be suspicious in phishing or scam URLs."
            )
            reasons.append(explanation)

    if brand["brand_impersonation"]:
        score += 20
        reasons.append(
            "Mentions a known brand but is not on an official brand domain. This can indicate brand impersonation or phishing."
        )

    if brand["typo_similarity_risk"]:
        score += 20
        closest_brand = brand["closest_brand"]
        reasons.append(
            f"Domain is similar to the known brand: {closest_brand}. Lookalike domains are commonly used for typosquatting and phishing."
        )

    if path.count("/") >= 3 and any(
        word in lower_url for word in ["login", "account", "verify"]
    ):
        score += 15
        reasons.append(
            "Deep path combined with login/account wording can indicate a hidden phishing page. Attackers often bury fake login pages inside long paths."
        )

    if query:
        score += 5
        reasons.append(
            "Contains query parameters. Query strings can pass tracking data, redirects, or user-specific values."
        )

    # Pull query token explanations from dictionary
    query_token_hits = [
        token for token in QUERY_TOKEN_EXPLANATIONS
        if token in lower_url
    ]

    if query_token_hits:
        score += 10

        for token in query_token_hits:
            reasons.append(QUERY_TOKEN_EXPLANATIONS[token])

    # Pull encoding explanations from dictionary
    encoding_hits = [
        encoded_value for encoded_value in ENCODING_EXPLANATIONS
        if encoded_value in lower_url
    ]

    if encoding_hits:
        score += 5

        for encoded_value in encoding_hits:
            reasons.append(ENCODING_EXPLANATIONS[encoded_value])

    # Pull file extension explanations from dictionary
    extension_hits = [
        ext for ext in FILE_EXTENSION_EXPLANATIONS
        if lower_path.endswith(ext)
    ]

    if extension_hits:
        score += 20

        for ext in extension_hits:
            reasons.append(FILE_EXTENSION_EXPLANATIONS[ext])

    if not reasons:
        reasons.append("No major rule-based warning signs found.")

    return min(score, 100), reasons


def analyze_rules(url: str) -> tuple[int, list[str]]:
    return analyze_with_rules(url)