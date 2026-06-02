from pathlib import Path
import pandas as pd
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]

RAW_DATA_PATH = BASE_DIR / "data" / "raw" / "malicious_urls.csv"
PROCESSED_DATA_PATH = BASE_DIR / "data" / "processed" / "processed_urls.csv"
REPORT_PATH = BASE_DIR / "data" / "processed" / "processed_data_report.txt"

BINARY_LABEL_MAPPING = {
    "benign": 0,
    "phishing": 1,
    "malware": 1,
    "defacement": 1,
}

MULTICLASS_LABEL_MAPPING = {
    "benign": 0,
    "phishing": 1,
    "malware": 2,
    "defacement": 3,
}

def is_parseable_url(url: str) -> bool:
    try:
        urlparse(url)
        return True
    except ValueError:
        return False
    
def normalize_url(url: str) -> str:
    url = str(url).strip()

    if not url:
        return ""

    allowed_protocols = (
        "http://",
        "https://",
        "ftp://",
        "smtp://",
        "ldap://",
    )

    if url.lower().startswith(allowed_protocols):
        return url

    return "http://" + url


def clean_label(label: str) -> str:
    return str(label).strip().lower()


def write_report(
    original_shape,
    final_shape,
    before_drop_nulls,
    after_drop_nulls,
    before_empty_url,
    after_empty_url,
    before_duplicates,
    after_duplicates,
    before_invalid_urls,
    after_invalid_urls,
    original_type_counts,
    binary_label_counts,
    multiclass_label_counts,
):
    report_text = f"""
Processed Data Report
=====================

Raw dataset path:
{RAW_DATA_PATH}

Processed dataset path:
{PROCESSED_DATA_PATH}

Original shape:
{original_shape}

Final processed shape:
{final_shape}


Cleaning Summary
----------------
Rows before null removal: {before_drop_nulls}
Rows after null removal: {after_drop_nulls}
Rows removed because of null url/type: {before_drop_nulls - after_drop_nulls}

Rows before empty URL removal: {before_empty_url}
Rows after empty URL removal: {after_empty_url}
Rows removed because of empty URL: {before_empty_url - after_empty_url}

Rows before duplicate removal: {before_duplicates}
Rows after duplicate removal: {after_duplicates}
Rows removed because of duplicate URL: {before_duplicates - after_duplicates}

Rows before invalid urls removal: {before_invalid_urls}
Rows after invalid urls removal: {after_invalid_urls}
Rows removed because of invalid urls: {before_invalid_urls - after_invalid_urls}


Original Type Counts
--------------------
{original_type_counts.to_string()}


Binary Label Counts
-------------------
0 = benign
1 = malicious

{binary_label_counts.to_string()}


Multiclass Label Counts
-----------------------
0 = benign
1 = phishing
2 = malware
3 = defacement

{multiclass_label_counts.to_string()}
""".strip()

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")


def main():
    df = pd.read_csv(RAW_DATA_PATH)

    original_shape = df.shape

    df.columns = [column.strip().lower() for column in df.columns]

    if "url" not in df.columns:
        raise ValueError("Dataset must contain a column named 'url'.")

    if "type" not in df.columns:
        raise ValueError("Dataset must contain a column named 'type'.")

    df = df[["url", "type"]]

    before_drop_nulls = len(df)
    df = df.dropna(subset=["url", "type"])
    after_drop_nulls = len(df)

    df["url"] = df["url"].astype(str).str.strip()
    df["original_type"] = df["type"].apply(clean_label)

    before_empty_url = len(df)
    df = df[df["url"] != ""]
    after_empty_url = len(df)

    df["url"] = df["url"].apply(normalize_url)

    before_duplicates = len(df)
    df = df.drop_duplicates(subset=["url"])
    after_duplicates = len(df)

    allowed_labels = set(BINARY_LABEL_MAPPING.keys())
    found_labels = set(df["original_type"].unique())
    unknown_labels = found_labels - allowed_labels
    
    before_invalid_urls = len(df)
    df = df[df["url"].apply(is_parseable_url)]
    after_invalid_urls = len(df)

    if unknown_labels:
        raise ValueError(f"Unknown labels found in dataset: {unknown_labels}")

    df["binary_label"] = df["original_type"].map(BINARY_LABEL_MAPPING)
    df["multiclass_label"] = df["original_type"].map(MULTICLASS_LABEL_MAPPING)

    processed_df = df[
        [
            "url",
            "original_type",
            "binary_label",
            "multiclass_label",
        ]
    ].reset_index(drop=True)

    PROCESSED_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    processed_df.to_csv(PROCESSED_DATA_PATH, index=False)

    write_report(
        original_shape=original_shape,
        final_shape=processed_df.shape,
        before_drop_nulls=before_drop_nulls,
        after_drop_nulls=after_drop_nulls,
        before_empty_url=before_empty_url,
        after_empty_url=after_empty_url,
        before_duplicates=before_duplicates,
        after_duplicates=after_duplicates,
        before_invalid_urls=before_invalid_urls,
        after_invalid_urls=after_invalid_urls,
        original_type_counts=processed_df["original_type"].value_counts(),
        binary_label_counts=processed_df["binary_label"].value_counts(),
        multiclass_label_counts=processed_df["multiclass_label"].value_counts(),
    )

    print(f"Processed dataset saved to: {PROCESSED_DATA_PATH}")
    print(f"Processing report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()