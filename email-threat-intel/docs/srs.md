# Software Requirements Specification (SRS) - Phishing Email Detector

## 1. Introduction
This document outlines the detailed Software Requirements Specification for the Phishing Email Detector platform. The application provides local email forensic analysis, protocol verification (SPF/DKIM/DMARC), and threat scoring.

## 2. System Architecture & Features

### 2.1 Web Interface (React + Vite)
- **Dashboard**: Renders real-time statistics (total scans, average threat score, malicious volume, and safe count) along with lists of recent email forensics.
- **Email Parser Inputs**: Contains a file upload drag-and-drop zone and a raw email text area for direct parsing.
- **Forensic Logs**: Renders a paginated history list of all analyzed emails with filtering by threat verdict (All, Malicious, Suspicious, Safe) and live search functionality.
- **Forensic Report View**: Detailed breakdown of threat factors, extracted IOC lists (URLs, IPs, attachments), timeline events, raw headers, and email body inspector.

### 2.2 Forensic Analysis Backend (FastAPI)
- **Email Parser Module**: Parses standard RFC 822 email files (`.eml` or `.txt`), extracting raw headers, body text, URLs, IP addresses, domains, and attachment filenames.
- **Authentication Checkers**: Performs DNS SPF lookups, verifies DKIM cryptographic signatures, and validates DMARC alignment.
- **Spamhaus Lookup**: Validates whether the sender IP is flagged in Spamhaus lists.
- **Rule Engine**: Evaluates email fields against heuristics (e.g., suspicious keywords, urgent tones, spoofed domains, or dangerous link shorteners) to calculate a base threat score.
- **Enrichment Service**: Executes asynchronous background tasks querying VirusTotal (for URL/hash reputation) and AbuseIPDB (for IP risk score).
- **Report Generator**: Combines analysis findings into a professional PDF threat report.

### 2.3 Database Management (SQLite)
- Relies on SQLAlchemy ORM to manage local relational schemas.
- Saves: `Email` metadata, `URL` records, `IP` records, forensic `Event` timelines, threat `IOC` indicators, `Attachment` metadata, and `Report` file path logs.
- Automatically initializes all tables on application startup.

## 3. Database Schema Specification

- **emails Table**:
  - `id` (Integer, Primary Key)
  - `sender` (String), `sender_domain` (String), `subject` (Text), `body` (Text), `headers` (JSON)
  - `spf_status`, `dkim_status`, `dmarc_status` (Strings)
  - `rule_score` (Integer), `threat_score` (Integer), `verdict` (String), `confidence` (String)
  - `received_at` (DateTime), `analyzed_at` (DateTime)

- **urls Table**:
  - `id` (Integer, Primary Key), `email_id` (Integer, FK)
  - `url` (Text), `domain` (String), `vt_malicious` (Integer), `vt_suspicious` (Integer), `vt_score` (Integer), `is_phishing` (Boolean), `checked_at` (DateTime)

- **ips Table**:
  - `id` (Integer, Primary Key), `email_id` (Integer, FK)
  - `ip_address` (String), `abuse_score` (Integer), `spamhaus_flagged` (Boolean), `is_malicious` (Boolean), `country` (String), `isp` (String), `reports_count` (Integer), `checked_at` (DateTime)

- **events Table**:
  - `id` (Integer, Primary Key), `email_id` (Integer, FK)
  - `event_type` (String), `description` (Text), `severity` (String), `timestamp` (DateTime)

- **attachments Table**:
  - `id` (Integer, Primary Key), `email_id` (Integer, FK)
  - `file_name` (String), `sha256` (String), `vt_malicious` (Integer), `vt_suspicious` (Integer), `vt_score` (Integer), `checked_at` (DateTime)

## 4. Non-Functional Requirements
- **Performance**: Backend must complete raw parsing and local rule evaluations in < 500ms.
- **Portability**: Database must require zero engine installations (accomplished via SQLite).
- **Scalability**: Asynchronous database session queries to prevent connection blockages.
- **Security**: The backend must bind to local addresses only (`localhost` / `127.0.0.1`) by default, keeping threat files within a sandbox environment.
