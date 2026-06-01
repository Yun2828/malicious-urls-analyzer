import streamlit as st
from urllib.parse import urlparse
from feature_extractor import parse_url
from predictor import predict_url
import validators

st.set_page_config(page_title="URL Safety Checker")

st.title("URL Safety Checker")
st.write("This prototype checks whether a URL looks safe, suspicious, or malicious using rules + one machine learning model.")

url = st.text_input("Enter a URL", placeholder="https://example.com/login?user=test")

def is_valid_url(input_url: str) -> tuple[bool, str]:
    stripped_url = input_url.strip()
    if not stripped_url:
        return False, "Please enter a URL."
    if not validators.url(stripped_url):
        return False, "Invalid URL format."
    return True, "Valid URL"

def is_valid_url(input_url: str) -> tuple[bool, str]:
    stripped_url = input_url.strip()

    if not stripped_url:
        return False, "Please enter a URL."

    if not validators.url(stripped_url):
        return False, "Invalid URL format."

    return True, "Valid URL"


if st.button("Check URL"):
    valid, message = is_valid_url(url)
    if not valid:
        st.error(message)
    else:
        result = predict_url(url)
        components = parse_url(url)

        st.subheader("Result")
        st.metric("Final Risk Score", f"{result['final_score']}/100")
        st.write(f"**Category:** {result['category']}")

        st.progress(result["final_score"] / 100)

        st.subheader("URL Components")
        st.json(components)

        st.subheader("Score Breakdown")
        st.write(f"Rule-based score: **{result['rule_score']}/100**")
        st.write(f"Machine learning score: **{result['ml_score']}/100**")
        st.write("Final score = 50% rule-based score + 50% ML score")

        st.subheader("Warning Signs")
        if result["reasons"]:
            for reason in result["reasons"]:
                st.warning(reason)
        else:
            st.success("No major rule-based warning signs detected.")

        with st.expander("Extracted ML Features"):
            st.json(result["features"])
