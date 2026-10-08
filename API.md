# REST API Specification

Base URL: `http://127.0.0.1:8000/api`

## Endpoints

### 1. Ingest & Analyze Email File
- **Endpoint**: `POST /api/analyze`
- **Content-Type**: `multipart/form-data`
- **Body**: `file: Binary .eml file`
- **Response**: `200 OK` (Full Analysis Object with risk score, findings, hops, IOCs, ML results)

### 2. Ingest & Analyze Raw Text
- **Endpoint**: `POST /api/analyze/text`
- **Content-Type**: `application/json`
- **Body**:
  ```json
  {
    "raw_text": "From: sender@domain.com\nTo: victim@domain.com\nSubject: ...",
    "filename": "pasted_email.eml"
  }
  ```
- **Response**: `200 OK` (Full Analysis Object)

### 3. List Past Investigations
- **Endpoint**: `GET /api/analyses`
- **Response**: `200 OK` (Array of investigation summary items)

### 4. Get Investigation Details
- **Endpoint**: `GET /api/analysis/{id}`
- **Response**: `200 OK` (Complete investigation records, hops, findings)

### 5. Generate Executive Report
- **Endpoint**: `GET /api/analysis/{id}/report`
- **Response**: `200 OK` (Executive SOC intelligence report with legal disclaimers)

### 6. Export IOC Package
- **Endpoint**: `GET /api/analysis/{id}/iocs`
- **Response**: `200 OK` (Grouped IPs, domains, URLs, hashes, emails)

### 7. Service Health & Status
- **Endpoint**: `GET /api/health`
- **Response**: `200 OK` (`{"status": "healthy", ...}`)

### 8. Machine Learning Status
- **Endpoint**: `GET /api/ml/status`
- **Response**: `200 OK` (Model architecture, test accuracy, F1 score, confusion matrix)

### 9. System & Database Status
- **Endpoint**: `GET /api/system/status`
- **Response**: `200 OK` (Database connectivity and subsystem status)
