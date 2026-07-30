import streamlit as st

from features.url_features import get_url_features, is_known_url_tld
from frontend.templates import risk_banner
from utils.prediction import get_phishing_prob, risk_label


def _result_box(pred, prob):
    """Render metric cards and threat assessment banner."""
    confidence = prob if pred == 1 else 1 - prob
    risk = risk_label(prob)

    c1, c2, c3 = st.columns(3)
    c1.metric("Prediction", "Phishing URL" if pred == 1 else "Legitimate URL")
    c2.metric("Confidence", f"{confidence * 100:.2f}%")
    c3.metric("Risk Level", risk)

    if pred == 1:
        st.markdown(
            risk_banner(
                "danger",
                "Phishing URL Detected",
                "The machine-learning model identified structural characteristics associated with phishing links.",
            ),
            unsafe_allow_html=True,
        )
        st.error("⚠️ Security Warning: Do not visit this URL, enter credentials, or download linked assets.")
    else:
        st.markdown(
            risk_banner(
                "safe",
                "Legitimate URL Detected",
                "The machine-learning model did not find anomalous lexical patterns associated with phishing in this URL.",
            ),
            unsafe_allow_html=True,
        )
        st.info("💡 Security Reminder: Lexical screening provides structural guidance. Always verify domain identity and context.")


def _url_warnings(feat_df):
    """Extract structural risk flags from computed feature vector."""
    row = feat_df.iloc[0]
    warnings = []

    if int(row["IsDomainIP"]) == 1:
        warnings.append("Raw IP address used as hostname instead of a domain name.")
    if int(row["IsHTTPS"]) == 0:
        warnings.append("Insecure connection (URL does not specify HTTPS).")
    if int(row["HasObfuscation"]) == 1:
        warnings.append("Percent-encoded character obfuscation detected.")
    if float(row["URLLength"]) > 75:
        warnings.append("Unusually high total URL string length (>75 characters).")
    if int(row["NoOfSubDomain"]) >= 3:
        warnings.append("High subdomain depth (3 or more subdomains).")
    if float(row["SpacialCharRatioInURL"]) > 0.20:
        warnings.append("Elevated density of special characters in URL path/query.")
    if int(row["NoOfQMarkInURL"]) > 1:
        warnings.append("Multiple query parameter delimiters ('?') found.")
    if int(row["NoOfEqualsInURL"]) >= 3:
        warnings.append("High count of assignment operators ('=') in query string.")

    return warnings


def render(model, feat_cols):
    """Render the URL Threat Analyzer view."""
    st.subheader("🌐 URL Structural Threat Inspection")
    st.caption("Non-invasive lexical extraction — operates offline without initiating HTTP connections.")

    url_input = st.text_input(
        "Target URL String",
        placeholder="e.g. https://secure-login.example.com/verify?token=abc123",
    )

    if not st.button("Analyse URL", type="primary", width="stretch"):
        return

    if not url_input.strip():
        st.warning("Please enter a valid URL string before launching analysis.")
        return

    try:
        feats = get_url_features(url_input)
        feats = feats.reindex(columns=feat_cols)

        if feats.isnull().any().any():
            raise ValueError("Feature extraction failed for the input string.")

        pred = int(model.predict(feats)[0])
        prob = get_phishing_prob(model, feats)

        _result_box(pred, prob)

        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader("Contextual Risk Indicators")
        
        warnings = _url_warnings(feats)
        trusted = is_known_url_tld(url_input)

        if trusted:
            st.success(
                "✅ **Trusted Domain TLD Identified:** "
                "The target belongs to a recognized domain registry family (e.g. .ac.uk, .gov.uk, .edu, .de)."
            )

        if warnings:
            for w in warnings:
                st.warning(f"🔸 {w}")
        else:
            st.success("No suspicious structural anomalies detected in the URL feature vector.")

        with st.expander("🔍 Inspect 18-Feature Vector Matrix"):
            st.dataframe(feats.T.rename(columns={0: "Feature Value"}), width="stretch")

    except Exception as err:
        st.error("Analysis execution encountered an error.")
        st.code(str(err))
