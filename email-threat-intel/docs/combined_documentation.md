# Combined Comprehensive Documentation - Phishing Email Detector

This document is a combined reference containing the complete Product Requirements Document (PRD), Software Requirements Specification (SRS), Software Design Document (SDD), and API reference manual for the Phishing Email Detector platform.

---

# PART 1: Product Requirements Document (PRD)

## 1. Product Overview
The **Phishing Email Detector** is a local Security Operations Center (SOC) console for parsing and analyzing email files (`.eml` or `.txt`) and raw text, evaluating indicators against reputation lists and security standards (SPF, DKIM, DMARC), and outputting threat scores (0-100%).

## 2. Target Audience
- Security analysts investigating potential spear-phishing campaigns.
- Mail administrators checking deliverability or authentication parameters.
- Tech-savvy users validating incoming messages.

## 3. Core Capabilities
- Automated parsing of headers, text/HTML content, attachments, links, and IP addresses.
- Checking senders against DNS records (SPF), checking header keys (DKIM), and confirming alignment rules (DMARC).
- Asynchronous threat lookup via external services (VirusTotal, AbuseIPDB).
- Interactive, responsive dashboard showing logs database and aggregate statistics.
- Exporting details as a PDF threat report.
- Maintaining logs inside a local file-based SQLite database.

---

# PART 2: Software Requirements Specification (SRS)

## 1. Functional Scope

### 1.1 Frontend Console UI
- **Dashboard**: High-level visual widgets showing total scans, average threat score, malicious count, and safe count.
- **Upload Forms**: Drag-and-drop area for EML/TXT files and a large text area for pasting email data.
- **Logs Database**: Tabular view of records with search and verdict filtering.
- **Forensic Inspector**: Contains tab views showing security authentication checks, extracted indicator reputations (URLs, IPs, attachments), timeline logs, and raw content.

### 1.2 Analysis Backend
- **Header Decoders**: Extracts RFC 822 parameters.
- **Authentication Handlers**: Runs DNS lookup checks for SPF alignment, verifies DKIM cryptographic signatures, and checks DMARC compliance.
- **Rule Engine**: Evaluates content keywords, urgency language, domain spoofing, and url shorteners to calculate base hazard ratings.
- **PDF Report Compiler**: Assembles forensic timelines, IOC tables, and security check grids into downloadable PDF reports.

## 2. Database Model Schemas
- **emails**: Stores email metadata, body text, header JSON, validation results (SPF/DKIM/DMARC), threat scores, and verdicts.
- **urls**: Stores extracted domains, URL strings, VirusTotal findings, phishing status, and check timestamps.
- **ips**: Stores IP addresses, AbuseIPDB rankings, countries, ISPs, and check timestamps.
- **events**: Stores timestamped timeline events detailing validation sequences.
- **attachments**: Stores file names, SHA-256 hashes, and VirusTotal reputation scores.

---

# PART 3: Software Design Document (SDD)

## 1. Technical Stack
- **Backend Core**: FastAPI, Uvicorn, Python-dotenv.
- **Database Access**: SQLite + SQLAlchemy ORM.
- **Email Validation**: `dnspython`, `dkimpy`, `pyspf`.
- **Reporting**: `reportlab` (PDF compilation).
- **Frontend Core**: React + Vite.
- **Icons**: Lucide React.
- **Styles**: Vanilla CSS Custom Properties (neon accents, glassmorphic UI).

## 2. System Flow Sequence
1. **User Action**: Drops an EML file or pastes text, submitting to `/upload-email` or `/analyze-email`.
2. **Parsing**: Backend processes raw email headers, SPF validation, DKIM checks, and DMARC alignment.
3. **Local Rules Heuristics**: Rules engine scores standard text strings.
4. **Database persistence**: Core tables are initialized, saving the initial record.
5. **Asynchronous Enrichment**: Async workers issue lookup requests to VirusTotal and AbuseIPDB in the background.
6. **Result compilation**: Recalculates final threat score & verdict, updating database rows.
7. **UI Render**: Frontend updates state, rendering verdict dials and forensic indicator tables.

---

# PART 4: API Reference Manual

- **GET /health**: Verifies system status and database connections.
- **POST /upload-email**: Parses an uploaded `.eml` or `.txt` file, returning initial parsed threat summaries.
- **POST /analyze-email**: Parses raw request body text, returning initial parsed threat summaries.
- **GET /email/{email_id}**: Returns full forensic details for a scan, including extracted URLs, IPs, and attachment reputations.
- **GET /timeline/{email_id}**: Fetches detailed timestamped events.
- **GET /emails**: Returns paginated log summaries with support for verdict filters and search strings.
- **POST /email/{email_id}/enrich**: Forces immediate lookups on VirusTotal/AbuseIPDB.
- **GET /report/{email_id}**: Generates and downloads a PDF threat report.
