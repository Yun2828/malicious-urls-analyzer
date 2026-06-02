import streamlit as st
import validators

from predictor import predict_url


st.set_page_config(page_title="URL Safety Checker")

st.title("URL Safety Checker")
st.write(
    "This prototype checks whether a URL looks safe, suspicious, or malicious "
    "using rule-based analysis and a weighted machine learning ensemble."
)

url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com/login?user=test",
)


def is_valid_url(input_url: str) -> tuple[bool, str]:
    stripped_url = input_url.strip()

    if not stripped_url:
        return False, "Please enter a URL."

    if not validators.url(stripped_url):
        return False, "Invalid URL format. Include http:// or https://"

    return True, "Valid URL"


if st.button("Check URL"):
    valid, message = is_valid_url(url)

    if not valid:
        st.error(message)
    else:
        result = predict_url(url)

        st.subheader("Final Decision")
        st.write("Category:", result["category"])
        st.write("Final Score:", result["final_score"])
        st.write("Rule Score:", result["rule_score"])
        st.write("ML Ensemble Score:", result["ml_score"])

        st.subheader("Rule-Based Reasons")

        if result["reasons"]:
            for reason in result["reasons"]:
                st.write("-", reason)
        else:
            st.write("No major rule-based warning signs found.")