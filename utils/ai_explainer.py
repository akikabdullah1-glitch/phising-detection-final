"""
AI Explainer Utility — uses OpenAI GPT-4o to generate clear, professional
explanations for URL and email phishing detection results.

The ML model (XGBoost / LinearSVM) always makes the classification decision.
OpenAI is used ONLY to generate human-readable explanation text.
"""

import streamlit as st


try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


def _get_client():
    """Initialise OpenAI client using Streamlit secrets."""
    try:
        api_key = st.secrets.get("OPENAI_API_KEY", "")
        if not api_key or api_key == "your-openai-api-key-here":
            return None
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def explain_url(url: str, prediction: int, confidence: float, indicators: list[str]) -> str | None:
    """
    Generate an AI explanation for a URL phishing prediction.

    Parameters
    ----------
    url         : The URL that was analysed
    prediction  : 1 = Phishing, 0 = Legitimate
    confidence  : Model confidence as a float (e.g. 0.9452 = 94.52%)
    indicators  : List of suspicious indicator labels detected by the rule engine

    Returns
    -------
    AI-generated explanation string, or None if API call fails.
    """
    if not OPENAI_AVAILABLE:
        return None

    client = _get_client()
    if client is None:
        return None

    label = "Phishing" if prediction == 1 else "Legitimate"
    indicator_text = (
        "\n".join(f"- {i}" for i in indicators)
        if indicators
        else "- No single dominant indicator; overall structural pattern matches phishing."
    )

    prompt = f"""You are a cybersecurity expert assistant for a phishing detection research system.

A URL has been classified by a machine learning model trained on 18 lexical URL features.

URL: {url}
Classification: {label}
Model Confidence: {confidence * 100:.1f}%
Structural Risk Indicators Detected:
{indicator_text}

Write a concise, professional explanation (2–3 short paragraphs) for a non-technical user that:
1. Clearly explains why this URL was classified as {label} based on the structural indicators above.
2. If Phishing: Explains what the user should do immediately and how to protect themselves.
   If Legitimate: Reminds the user to still stay cautious and verify the URL themselves.
3. Ends with one key cybersecurity tip relevant to this specific case.

Important rules:
- Do NOT use bullet points — write in clear, flowing paragraphs.
- Do NOT claim the URL is definitely safe or dangerous — acknowledge it is a structural analysis.
- Keep the tone professional, calm, and educational — not alarmist.
- Keep total response under 200 words.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.4,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return None


def explain_email(email_text: str, prediction: int, confidence: float, found_signals: list[str]) -> str | None:
    """
    Generate an AI explanation for an email phishing prediction.

    Parameters
    ----------
    email_text    : The raw email body text
    prediction    : 1 = Phishing, 0 = Legitimate
    confidence    : Model confidence as a float
    found_signals : List of phishing signal labels matched in the text

    Returns
    -------
    AI-generated explanation string, or None if API call fails.
    """
    if not OPENAI_AVAILABLE:
        return None

    client = _get_client()
    if client is None:
        return None

    label = "Phishing" if prediction == 1 else "Legitimate (Safe)"
    signal_text = (
        "\n".join(f"- {s}" for s in found_signals)
        if found_signals
        else "- No dominant trigger phrase found; overall vocabulary pattern matches phishing."
    )

   
    truncated_email = email_text[:600] + ("..." if len(email_text) > 600 else "")

    prompt = f"""You are a cybersecurity expert assistant for a phishing email detection research system.

An email has been classified by a machine learning NLP model trained on TF-IDF vocabulary features.

Classification: {label}
Model Confidence: {confidence * 100:.1f}%
Phishing Language Signals Detected:
{signal_text}

Email Text (first 600 characters):
\"\"\"{truncated_email}\"\"\"

Write a concise, professional explanation (2–3 short paragraphs) for a non-technical user that:
1. Clearly explains why this email was classified as {label} based on the language signals above.
2. If Phishing: Explains what the user should do immediately.
   If Legitimate: Reminds the user to still verify the sender and stay cautious.
3. Ends with one key email safety tip relevant to this specific case.

Important rules:
- Do NOT use bullet points — write in clear, flowing paragraphs.
- Do NOT claim the email is definitely malicious or safe — it is a statistical prediction.
- Keep the tone professional, calm, and educational.
- Keep total response under 200 words.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.4,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return None
