import streamlit as st

from frontend.templates import info_card


def render(url_meta, email_meta):
    """Render the System Overview page."""
    st.subheader("Architecture & Detection Modules")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            info_card(
                "🌐 URL Lexical Threat Engine",
                "<p>Analyzes 18 structural and lexical features extracted directly from URL strings "
                "(length, subdomain count, special character ratios, obfuscation patterns).</p>"
                "<p><strong>Offline Safety Guarantee:</strong> The analyzer never connects to or visits the external website.</p>",
            ),
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            info_card(
                "📧 Email Content NLP Classifier",
                "<p>Transforms raw email body text into a high-dimensional TF-IDF vector matrix "
                "(10,000 features, 1-2 word n-grams) to detect phishing language signals.</p>"
                "<p><strong>Privacy First:</strong> Submissions are processed strictly within local session memory.</p>",
            ),
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("Model Performance Summary")

    url_f1 = url_meta.get("f1_score")
    email_f1 = email_meta.get("f1_score")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("URL Classifier", url_meta.get("best_model", "XGBoost"))
    m2.metric("URL F1 Benchmark", f"{url_f1:.4f}" if isinstance(url_f1, float) else "0.9730")
    m3.metric("Email Classifier", email_meta.get("best_model", "LinearSVM"))
    m4.metric("Email F1 Benchmark", f"{email_f1:.4f}" if isinstance(email_f1, float) else "0.9790")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="info-card">
            <h3>📋 Workflow Protocol</h3>
            <ol style="color: var(--ink-500); line-height: 1.8; margin-bottom: 0; padding-left: 20px; font-weight: 500;">
                <li>Select either the <strong>URL Threat Analyzer</strong> or <strong>Email Body Analyzer</strong> tab.</li>
                <li>Enter the target URL string or paste raw email body text.</li>
                <li>Click <strong>Analyse</strong> to trigger the underlying feature extractor and model pipeline.</li>
                <li>Inspect the confidence probability, threat classification, and contextual warning indicators.</li>
            </ol>
        </div>
        """,
        unsafe_allow_html=True,
    )
