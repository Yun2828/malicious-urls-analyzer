from pathlib import Path
from difflib import SequenceMatcher

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
BRAND_DOMAINS_PATH = BASE_DIR / "data" / "reputation" / "brand_domains.csv"

PHISHING_MODIFIERS = {
    "login",
    "secure",
    "security",
    "verify",
    "account",
    "update",
    "support",
    "password",
    "auth",
    "signin",
    "wallet",
    "billing",
}

def load_brand_domains() -> dict:
    if not BRAND_DOMAINS_PATH.exists():
        return {}

    df = pd.read_csv(BRAND_DOMAINS_PATH)

    brand_domains = {}

    for _, row in df.iterrows():
        brand = str(row["brand"]).lower().strip()
        official_domain = str(row["official_domain"]).lower().strip()

        if brand not in brand_domains:
            brand_domains[brand] = set()

        brand_domains[brand].add(official_domain)

    return brand_domains


BRAND_DOMAINS = load_brand_domains()


def similarity_score(value_a: str, value_b: str) -> float:
    return SequenceMatcher(None, value_a, value_b).ratio()


def get_domain_stem(domain_name: str) -> str:
    return str(domain_name).lower().strip().split(".")[0]


def get_official_stem(official_domain: str) -> str:
    return str(official_domain).lower().strip().split(".")[0]


def has_phishing_modifier(domain_stem: str) -> bool:
    tokens = domain_stem.replace("-", ".").split(".")
    return any(token in PHISHING_MODIFIERS for token in tokens)

def normalize_lookalike_text(text: str) -> str:
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "@": "a",
        "$": "s",
    }

    normalized = str(text).lower().strip()

    for original, replacement in replacements.items():
        normalized = normalized.replace(original, replacement)

    return normalized

def analyze_brand_impersonation(url: str, domain_name: str) -> dict:
    url_lower = str(url).lower()
    domain_name = str(domain_name).lower().strip()
    domain_stem = get_domain_stem(domain_name)

    brand_hits = [
        brand
        for brand in BRAND_DOMAINS
        if brand in url_lower
    ]

    is_official_domain = any(
        domain_name in official_domains
        for official_domains in BRAND_DOMAINS.values()
    )

    best_similarity = 0.0
    closest_brand = ""
    closest_official_domain = ""
    closest_official_stem = ""

    for brand, official_domains in BRAND_DOMAINS.items():
        for official_domain in official_domains:
            official_stem = get_official_stem(official_domain)

            normal_domain_stem = normalize_lookalike_text(domain_stem)
            normal_official_stem = normalize_lookalike_text(official_stem)

            score = similarity_score(normal_domain_stem, normal_official_stem)

            if score > best_similarity:
                best_similarity = score
                closest_brand = brand
                closest_official_domain = official_domain
                closest_official_stem = official_stem

    brand_impersonation = 0
    typo_similarity_risk = 0

    if brand_hits and not is_official_domain:
        brand_impersonation = 1

    if not is_official_domain and best_similarity >= 0.85:
        typo_similarity_risk = 1

    if not is_official_domain and closest_official_stem:
        starts_with_brand = domain_stem.startswith(closest_official_stem + "-")
        contains_brand_modifier = (
            closest_official_stem in domain_stem
            and has_phishing_modifier(domain_stem)
        )

        if starts_with_brand or contains_brand_modifier:
            typo_similarity_risk = 1

    return {
        "brand_keyword_count": len(brand_hits),
        "brand_impersonation": brand_impersonation,
        "typo_similarity_risk": typo_similarity_risk,
        "closest_brand": closest_brand,
        "closest_official_domain": closest_official_domain,
        "brand_similarity_score": best_similarity,
        "brand_hits": brand_hits,
    }