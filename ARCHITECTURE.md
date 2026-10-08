# System Architecture & Technical Specification

## 1. Architectural Philosophy
The platform is designed around **zero-trust, verifiable evidence processing**. It couples deterministic RFC 5322 parsing with explainable heuristics and supervised machine learning:
1. **Never fabricate missing data**: If SPF or DKIM headers are missing or inconclusive, status is set to `unknown` or `not_available`.
2. **Layered defense-in-depth**: Static regex indicators, domain lookalike matching, cryptographic envelope checks, and NLP semantic inference are aggregated transparently.
3. **Safe Sandbox Execution**: Uploaded attachments are fingerprinted cryptographically (SHA-256) and inspected for dangerous extension patterns without ever executing payloads or invoking shell binaries.

---

## 2. Component Architecture

### A. Data Ingestion & Normalization (`app/services/email_analyzer.py`)
- Standard library Python `email.parser.BytesParser` with `policy.default` (RFC 5322 modern standard).
- Graceful fallback to `policy.compat32` for non-standard legacy or malformed emails.
- Extraction of:
  - Envelope: `From`, `To`, `Subject`, `Message-ID`, `Return-Path`, `Reply-To`, `Date`.
  - Body: Plaintext and decoded HTML body elements with safe charset decoding.
  - Entities: Hyperlinks, IPv4 addresses, domains, and MIME attachments.

### B. Forensic Engine (`app/forensic/forensic_engine.py`)
- **Integrity Fingerprinting**: Generates SHA-256 hash over raw email bytes.
- **MTA Chain Parser**: Inverts chronological order of `Received` headers (earliest origin MTA at bottom, final gateway at top) to reconstruct relay path, hops, and delay timestamps.
- **IOC Aggregator**: Produces SIEM-ready structured JSON categorizing IPs, domains, URLs, email addresses, and file hashes.

### C. Threat Scoring Engine (`app/services/threat_engine.py`)
- Implements an explainable 0–100 scoring framework:
  - **SPF Failure**: +12 to +20 points
  - **DKIM Failure**: +15 points
  - **DMARC Alignment Failure**: +15 points
  - **Display Name Spoofing**: +25 points
  - **Reply-To Mismatch**: +20 points
  - **Return-Path Mismatch**: +10 points
  - **Suspicious Lookalike URL**: +15 to +35 points
  - **Dangerous / Double-Extension Attachment**: +25 points
  - **High Urgency / Phishing Vocabulary**: +15 points
  - **ML Model Phishing Signal**: +0 to +25 points (proportional to confidence)
- Normalized strictly between `0` and `100`:
  - `0 - 29`: **LOW**
  - `30 - 59`: **MEDIUM**
  - `60 - 79`: **HIGH**
  - `80 - 100`: **CRITICAL**

### D. Supervised Machine Learning Pipeline (`ml/`)
- **Feature Extraction**: Scikit-Learn `TfidfVectorizer(ngram_range=(1, 2), max_features=2500, sublinear_tf=True)`.
- **Classification**: `LogisticRegression(C=1.5, class_weight='balanced')`.
- **Classes**: `legitimate`, `phishing`, `spam`.
- **Metrics**: Holds evaluated accuracy, precision, recall, F1-macro, and confusion matrix generated during training.

### E. Geolocation Intelligence (`app/services/geolocation_service.py`)
- Validates IPv4 structure and verifies RFC 1918 private / loopback address space via `ipaddress.ip_address(ip).is_global`.
- Enforces explicit caveat that IP geolocation indicates intermediate relay data centers, not physical sender residence.
