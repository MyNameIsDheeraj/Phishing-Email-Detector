# API Documentation - Phishing Email Detector Backend

The Phishing Email Detector backend is built using FastAPI and runs on `http://localhost:8000`. This document covers the available REST endpoints.

---

## 1. Health and Status Endpoints

### GET /
API base check.
- **Response (200 OK)**:
  ```json
  {
    "message": "Email Threat Intelligence Platform API",
    "status": "running",
    "version": "2.0.0",
    "docs": "/api/docs"
  }
  ```

### GET /health
Detailed application health status, testing the SQLite connection and checking external API key presence.
- **Response (200 OK)**:
  ```json
  {
    "status": "healthy",
    "database": "connected",
    "services": {
      "virustotal": "configured",
      "abuseipdb": "not configured"
    },
    "timestamp": "2026-06-21T18:05:14.000000"
  }
  ```

---

## 2. Forensic Analysis Endpoints

### POST /upload-email
Upload an email file (`.eml` or `.txt`) for parsing and threat scoring.
- **Request Content-Type**: `multipart/form-data`
- **Request Body**:
  - `file`: Binary file upload
- **Response (200 OK)**:
  ```json
  {
    "id": 1,
    "verdict": "MALICIOUS",
    "threat_score": 100,
    "confidence": "HIGH",
    "details": ["Urgent call to action", "Link to suspicious domain"],
    "authentication": {
      "spf": "PASS",
      "dkim": "FAIL",
      "dmarc": "FAIL"
    },
    "iocs": {
      "urls": ["http://phishingbank-verify-account.com/login"],
      "ips": ["192.168.1.1"],
      "domains": ["trustedbank.com"],
      "attachments": []
    },
    "stats": {
      "total_urls": 1,
      "total_ips": 1,
      "total_domains": 1,
      "total_attachments": 0
    },
    "filename": "suspicious.eml",
    "analyzed_at": "2026-06-21T18:05:14.000000",
    "enrichment": "Started in background"
  }
  ```

### POST /analyze-email
Submit raw email headers and text content directly.
- **Request Content-Type**: `application/json`
- **Request Body**:
  ```json
  {
    "email_text": "From: test@example.com\nTo: victim@example.com\n..."
  }
  ```
- **Response (200 OK)**: Same payload structure as `/upload-email`.

---

## 3. Database Queries & Management

### GET /emails
List scanned emails with pagination and optional verdict filters.
- **Query Parameters**:
  - `skip` (Integer, default: `0`)
  - `limit` (Integer, default: `50`)
  - `verdict` (String, optional: `MALICIOUS` | `SUSPICIOUS` | `SAFE`)
- **Response (200 OK)**:
  ```json
  {
    "total": 24,
    "skip": 0,
    "limit": 50,
    "emails": [
      {
        "id": 1,
        "sender": "attacker@scam.com",
        "subject": "Account update",
        "verdict": "MALICIOUS",
        "threat_score": 85,
        "confidence": "HIGH",
        "received_at": "2026-06-21T18:05:14",
        "analyzed_at": "2026-06-21T18:06:20"
      }
    ]
  }
  ```

### GET /emails/recent
Retrieve the 10 most recently scanned emails.
- **Response (200 OK)**:
  ```json
  {
    "count": 1,
    "emails": [
      {
        "id": 1,
        "sender": "attacker@scam.com",
        "subject": "Account update",
        "verdict": "MALICIOUS",
        "threat_score": 85,
        "confidence": "HIGH",
        "received_at": "2026-06-21T18:05:14",
        "has_iocs": true
      }
    ]
  }
  ```

### GET /email/{email_id}
Get full details of a specific analyzed email.
- **Path Parameters**:
  - `email_id` (Integer)
- **Query Parameters**:
  - `include_iocs` (Boolean, default: `true`)
  - `include_timeline` (Boolean, default: `true`)
- **Response (200 OK)**: Full detail object containing extracted URL reputation scores, IP abuse ratings, file hashes, and forensic timeline.

### GET /timeline/{email_id}
Retrieve the forensic analysis timeline for a specific scan.
- **Path Parameters**:
  - `email_id` (Integer)
- **Response (200 OK)**: List of events (e.g. `RECEIVED`, `PARSED`, `SPF_CHECK`, `RULE_ANALYSIS`).

### DELETE /email/{email_id}
Delete a specific forensic record.
- **Path Parameters**:
  - `email_id` (Integer)
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "message": "Email forensic record 1 deleted successfully"
  }
  ```

---

## 4. Threat Intelligence & Enrichment

### POST /email/{email_id}/enrich
Force immediate, synchronous lookup of parsed indicators against VirusTotal and AbuseIPDB API services.
- **Path Parameters**:
  - `email_id` (Integer)
- **Response (200 OK)**: Updated email summary with recalculated threat score.

---

## 5. Reporting

### GET /report/{email_id}
Generates and downloads a PDF threat report.
- **Path Parameters**:
  - `email_id` (Integer)
- **Response (200 OK)**: PDF byte stream (`Content-Type: application/pdf`).
