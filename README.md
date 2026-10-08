# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

Production-quality Security Operations Center (SOC) intelligence platform that combines **deterministic RFC 5322 header parsing**, **cryptographic authentication audits (SPF / DKIM / DMARC)**, **real supervised Machine Learning NLP classification**, **explainable 0–100 risk scoring**, **approximate IP geolocation**, and **MTA relay timeline reconstruction**.

---

## 1. System Architecture Overview

```
                          ┌──────────────────────────┐
                          │   Raw Email (.eml / MUA) │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │    Email Analysis Engine │
                          │ (Python RFC 5322 Policy) │
                          └──────┬────────────┬──────┘
                                 │            │
            ┌────────────────────┘            └────────────────────┐
            ▼                                                      ▼
┌───────────────────────────┐                            ┌───────────────────────────┐
│     Forensic Engine       │                            │   Multi-Signal Threat     │
│  - SHA-256 Fingerprinting │                            │         Engine            │
│  - MTA Hop Reconstruction │                            │  - SPF/DKIM/DMARC Audit   │
│  - Chronological Timeline │                            │  - Display Spoofing Check │
│  - IOC JSON Extraction    │                            │  - Dangerous Extensions   │
└───────────┬───────────────┘                            │  - Lookalike URLs         │
            │                                            └─────────────┬─────────────┘
            ▼                                                          ▼
┌───────────────────────────┐                            ┌───────────────────────────┐
│ Geolocation Intelligence  │                            │ Supervised ML Classifier  │
│  - RFC 1918 Classification│                            │  - TF-IDF N-Grams (1, 2)  │
│  - Approximate ASN / ISP  │                            │  - Logistic Regression    │
└───────────┬───────────────┘                            └─────────────┬─────────────┘
            │                                                          │
            └────────────────────┐            ┌────────────────────────┘
                                 ▼            ▼
                          ┌──────────────────────────┐
                          │   Explainable 0–100      │
                          │   Normalized Risk Score  │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │ FastAPI REST Backend &   │
                          │  SQLAlchemy Database     │
                          └─────────────┬────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │  Cybersecurity React SOC │
                          │     Web Dashboard        │
                          └──────────────────────────┘
```

---

## 2. Core Capabilities

1. **Deterministic Email Parsing**: Parses RFC 5322 / RFC 822 emails safely using standard Python `email.parser` with default modern policy. Extracts headers, bodies (plain & HTML), URLs, IP addresses, domains, and MIME attachments.
2. **Cryptographic Authentication Audit**: Inspects `Authentication-Results` and `Received-SPF` to determine verifiable SPF, DKIM, and DMARC alignments without inventing or guessing results.
3. **Supervised Machine Learning NLP**: Trained TF-IDF + Logistic Regression pipeline on realistic security text samples. Evaluated using scikit-learn hold-out test set (real Accuracy, F1-macro, and confusion matrix).
4. **Explainable Risk Scoring**: Weighted signal aggregator producing a normalized 0–100 score (`LOW`: 0–29, `MEDIUM`: 30–59, `HIGH`: 60–79, `CRITICAL`: 80–100) with line-item justifications.
5. **Forensic MTA Relay Chain**: Reconstructs the exact sequence of mail transfers from the originating host to the final recipient mail gateway using Received headers.
6. **Approximate IP Geolocation**: Differentiates private RFC 1918 / loopback IPs from public endpoints. Resolves approximate coordinates, country, region, city, ISP, and ASN.
7. **IOC Extraction**: Instant export of IPs, domains, URLs, email addresses, and SHA-256 evidence hashes in SIEM-ready JSON format.
8. **Executive SOC Reports**: Generates formal executive forensic reports exportable as JSON or printable to PDF.

---

## 3. Technology Stack

- **Frontend**: React 19, Vite, Tailwind CSS, React Router, Recharts, Lucide Icons, Axios.
- **Backend**: Python 3.14 / 3.11+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy.
- **Database**: SQLite (local development fallback) / PostgreSQL (production via `DATABASE_URL`).
- **Machine Learning**: Scikit-Learn (TF-IDF Vectorizer + Logistic Regression with sublinear TF and n-grams), Joblib.
- **Testing**: Pytest, HTTPX, FastAPI TestClient.

---

## 4. Quick Start & Execution

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Backend Setup
```bash
cd backend

# Initialize database and run tests
python -m pytest tests/test_platform.py -v

# Start the FastAPI server
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at: `http://127.0.0.1:8000/docs`

### Frontend Setup
```bash
cd frontend

# Install dependencies (if not done)
npm install

# Start development server
npm run dev
```
Dashboard will be live at: `http://127.0.0.1:5173`

---

## 5. Machine Learning Training

To re-train the ML classification pipeline and re-evaluate performance metrics:
```bash
# Generate training dataset
python ml/datasets/generate_dataset.py

# Train pipeline and generate evaluation metrics
python ml/training/train.py
```
Model artifacts will be written to `ml/models/phishing_classifier.joblib` and evaluation metrics to `ml/evaluation/metrics.json`.

---

## 6. Synthetic Test Emails

A collection of synthetic test emails covering realistic security scenarios is provided in `sample_emails/`:
1. `phishing_demo.eml` — Office 365 credential harvesting with SPF/DKIM/DMARC failures and malicious URL.
2. `legitimate_demo.eml` — GitHub PR notification with passing SPF, DKIM, and DMARC alignments.
3. `suspicious_auth_demo.eml` — Banking alert spoofing with private IP URL and authentication failures.
4. `suspicious_attachment_demo.eml` — Invoicing email containing a dangerous executable with double extension (`.pdf.exe`).
5. `header_anomaly_demo.eml` — CEO fraud BEC campaign with mismatched Reply-To and From headers.
6. `spam_demo.eml` — Promotional weight loss spam email.

---

## 7. Important Accuracy & Legal Notice

> **Forensic Limitation Notice**: IP geolocation is approximate and reflects the data center, ISP, or hosting provider of the intermediate relay. It does not identify the sender's physical home or office address. Private RFC 1918 addresses are excluded from public geolocation mappings. All intelligence outputs clearly distinguish verified facts from probabilistic inferences.
