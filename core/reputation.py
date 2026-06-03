from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[1]

TRANCO_PATH = BASE_DIR / "data" / "reputation" / "tranco_top_domains.csv"


def load_tranco_domains() -> dict:
    if not TRANCO_PATH.exists():
        return {}

    df = pd.read_csv(TRANCO_PATH)

    required_columns = {"domain", "tranco_rank", "reputation_score"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        return {}

    reputation = {}

    for _, row in df.iterrows():
        domain = str(row["domain"]).lower().strip()

        reputation[domain] = {
            "tranco_rank": int(row["tranco_rank"]),
            "reputation_score": int(row["reputation_score"]),
        }

    return reputation


TRANCO_REPUTATION = load_tranco_domains()


def get_domain_reputation(domain_name: str) -> dict:
    domain_name = str(domain_name).lower().strip()

    default_result = {
        "is_tranco_domain": 0,
        "tranco_rank": 0,
        "domain_reputation_score": 0,
    }

    if not domain_name:
        return default_result

    data = TRANCO_REPUTATION.get(domain_name)

    if not data:
        return default_result

    return {
        "is_tranco_domain": 1,
        "tranco_rank": data["tranco_rank"],
        "domain_reputation_score": data["reputation_score"],
    }