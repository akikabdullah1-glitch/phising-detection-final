import streamlit as st

from features.email_features import clean_text
from frontend.templates import risk_banner
from utils.prediction import get_phishing_prob, risk_label


def _result_box(pred, prob):
    """Render metric cards and email threat analysis banner."""
    confidence = prob if pred == 1 else 1 - prob
    risk = risk_label(prob)

    c1, c2, c3 = st.columns(3)
    c1.metric("Prediction", "Phishing Email" if pred == 1 else "Safe Email")
    c2.metric("Confidence", f"{confidence * 100:.2f}%")
    c3.metric("Risk Level", risk)

    if pred == 1:
        st.markdown(
            risk_banner(
                "danger",
                "Phishing Email Detected",
                "The NLP classifier detected high TF-IDF feature weights associated with social engineering and phishing emails.",
            ),
            unsafe_allow_html=True,
        )
        st.error("⚠️ Security Warning: Do not click embedded links, open attachments, or reply with confidential credentials.")
    else:
        st.markdown(
            risk_banner(
                "safe",
                "Safe Email Detected",
                "The NLP classifier did not find significant phishing language signals in the processed text matrix.",
            ),
            unsafe_allow_html=True,
        )
        st.info("💡 Security Reminder: Inspect sender headers and verify out-of-band contacts before trusting unexpected requests.")


def render(model, vectorizer):
    """Render the Email Content Analyzer view."""
    st.subheader("📧 Email Content NLP Analysis")
    st.caption("Submissions are tokenized into 10,000 TF-IDF features and classified locally in session memory.")

    email_input = st.text_area(
        "Raw Email Body Text",
        height=260,
        placeholder=(
            "Paste full email body text here...\n"
            "e.g. Dear customer, your account requires immediate verification. "
            "Please click the secure link below within 24 hours to prevent suspension."
        ),
    )

    if not st.button("Analyse Email", type="primary", width="stretch"):
        return

    if not email_input.strip():
        st.warning("Please paste email body text before executing analysis.")
        return

    try:
        cleaned = clean_text(email_input)

        if not cleaned:
            raise ValueError("No readable words remained after text pre-cleaning.")

        X = vectorizer.transform([cleaned])
        pred = int(model.predict(X)[0])
        prob = get_phishing_prob(model, X)

        _result_box(pred, prob)

        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader("Security Verification Checklist")
        if pred == 1:
            st.markdown(
                """
                - 🛑 Verify sender address domains against official communications.
                - 🛑 Do not open attached files (.zip, .exe, .html, .docm).
                - 🛑 Do not click urgent verification or password reset links.
                - 🛑 Report the message to your security operations team.
                """
            )
        else:
            st.markdown(
                """
                - 🛡️ Confirm sender address matches expected organization domain.
                - 🛡️ Hover over embedded links to inspect actual destination URLs.
                - 🛡️ Exercise standard caution with unverified attachments.
                """
            )

        with st.expander("🔍 View Pre-Processed NLP Text Vector"):
            st.code(cleaned)

    except Exception as err:
        st.error("Analysis execution encountered an error.")
        st.code(str(err))
