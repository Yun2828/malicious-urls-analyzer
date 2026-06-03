from pathlib import Path

import pandas as pd
from tranco import Tranco


BASE_DIR = Path(__file__).resolve().parents[0]

CACHE_DIR = BASE_DIR / ".tranco"
OUTPUT_PATH = BASE_DIR / "data" / "reputation" / "tranco_top_domains.csv"

TOP_N = 10000


def main():
    tranco = Tranco(cache=True, cache_dir=str(CACHE_DIR))
    latest_list = tranco.list()

    top_domains = latest_list.top(TOP_N)

    rows = []

    for rank, domain in enumerate(top_domains, start=1):
        rows.append(
            {
                "domain": domain.lower().strip(),
                "tranco_rank": rank,
                "reputation_score": max(1, round(100 - ((rank - 1) / TOP_N) * 100)),
            }
        )

    output_df = pd.DataFrame(rows)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(OUTPUT_PATH, index=False)

    print(f"Saved top {TOP_N} Tranco domains to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()