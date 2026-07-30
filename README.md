# Phishing Detection System

A machine learning project that detects phishing attacks in URLs and emails.

## Project Structure

```
├── app.py                  # Streamlit application entry point
├── layout.py               # Theme layout and control center sidebar
├── README.md               # Documentation
├── requirements.txt        # Python package dependencies
├── .gitignore              # Git ignore rules
│
├── config/
│   └── paths.py            # Centralized system file paths
│
├── features/
│   ├── url_features.py     # 18 lexical URL feature extraction
│   └── email_features.py   # Raw email text pre-cleaning
│
├── frontend/
│   ├── styles.css          # App stylesheet and theme tokens
│   └── templates.py        # Reusable HTML component templates
│
├── utils/
│   └── prediction.py       # Probability scoring and risk level helpers
│
├── views/
│   ├── home.py             # System Overview view
│   ├── url_checker.py      # URL Threat Analyzer view
│   ├── email_checker.py    # Email Body Analyzer view
│   └── results_viewer.py   # Model Analytics & Benchmark view
│
├── training/
│   ├── clean_emails.py     # Email dataset preprocessing script
│   ├── build_url_data.py   # URL dataset feature builder script
│   ├── train_email_model.py # Email NLP model training pipeline
│   └── train_url_model.py  # URL XGBoost model training pipeline
│
├── data/                   # Datasets
├── models/                 # Model binaries (.pkl) & metadata (.json)
└── results/                # Evaluation benchmark charts and reports
```

## Running the Application

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Retraining Models (Optional)

```bash
python training/clean_emails.py
python training/build_url_data.py
python training/train_email_model.py
python training/train_url_model.py
```

## Detection Architecture

- **URL Threat Analysis**: Extracts 18 lexical features directly from URL strings (length, HTTPS flag, subdomain count, special character ratios, obfuscation patterns) and classifies them using XGBoost. Operates completely offline without making network connections.
- **Email Content Analysis**: Pre-cleans raw email body text, converts it into a 10,000-dimensional TF-IDF feature matrix (1–2 word n-grams), and classifies it using a Linear Support Vector Machine (LinearSVM).

## Model Performance

| Module | Model | F1 Score | ROC-AUC |
|--------|-------|----------|---------|
| URL Classification | XGBoost | 97.3% | 98.9% |
| Email Classification | LinearSVM | 97.9% | 99.8% |
