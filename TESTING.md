# Verification & Automated Testing Guide

## 1. Running the Automated Test Suite
From the `backend` directory, run:
```bash
python -m pytest tests/test_platform.py -v
```

## 2. Test Cases Covered
1. `test_health_endpoints` — Verifies `/api/health`, `/api/system/status`, and `/api/ml/status`.
2. `test_empty_email` — Verifies rejection of whitespace/empty payload with HTTP 400.
3. `test_corrupted_email_bytes` — Asserts robust parsing and cryptographic fingerprinting on malformed byte sequences.
4. `test_email_without_headers` — Asserts default behavior (`unknown`, `not_available`) when RFC headers are absent.
5. `test_private_vs_public_ip_filtering` — Validates accurate distinction of RFC 1918 / loopback IPs (127.0.0.1, 192.168.1.1, 10.0.0.5) from routable public endpoints.
6. `test_url_analyzer` — Validates detection of plaintext HTTP, suspicious TLDs, and brand lookalike URLs.
7. `test_dangerous_attachment_analyzer` — Detects executable extensions and double-extension tricks (`.pdf.exe`).
8. `test_ml_inference` — Verifies real supervised inference and probability generation from scikit-learn model.
9. `test_threat_engine_risk_score_normalization` — Confirms score bounding within [0, 100] and threat classification.
10. `test_end_to_end_phishing_demo` — Ingests `sample_emails/phishing_demo.eml`, tests API pipeline, reporting, and IOC extraction.
11. `test_end_to_end_legitimate_demo` — Ingests `sample_emails/legitimate_demo.eml` and verifies low threat score.

## 3. End-to-End Acceptance Verification
Both backend (port 8000) and frontend (port 5173) are actively tested and verified:
- Backend: `http://127.0.0.1:8000/api/health` returns status `healthy`.
- Frontend: `http://127.0.0.1:5173/` serves the SOC Dashboard with full React routing.
