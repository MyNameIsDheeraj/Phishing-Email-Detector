# Phishing Email Detector - Threat Intelligence Platform

An advanced, interactive local email forensics platform that detects phishing attempts using rule-based analysis, cryptographic verification (SPF/DKIM/DMARC), and threat reputation API integrations.

---

## Key Features
- **Sleek UI console**: Responsive dark-themed dashboard built with glassmorphic cards and intuitive visual dials for malicious scores.
- **Protocol validation**: Verifies SPF records, DKIM public-key signatures, and DMARC alignments using active DNS resolution.
- **Comprehensive IOC parser**: Extracts URLs, IPv4/IPv6 addresses, domain records, and attachment lists.
- **Threat intelligence lookups**: Asynchronously queries VirusTotal and AbuseIPDB to retrieve reputational risk scores for extracted indicators.
- **Local SQLite Storage**: Saves forensic scan data locally. Databases resolve paths automatically relative to the backend directory.
- **Professional PDF export**: Exports scanned metrics, timeline events, and IOCs as clean, SOC-grade PDF reports.

---

## Directory Overview
- **`email-threat-intel/backend/`**: FastAPI python server, local SQLite database, heuristic rule engines, DNS verification packages, and unit tests.
- **`email-threat-intel/frontend/`**: React SPA dev server powered by Vite.

---

## Installation & Setup

### Prerequisites
- Python 3.8+ (with pip)
- Node.js v18.0.0+ (and npm)
- *Optional*: Active internet connection (for external DNS checking and reputation API queries)

### 1. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd email-threat-intel/backend
   ```
2. Create and activate a python virtual environment:
   ```bash
   python -m venv env
   source env/bin/activate
   ```
3. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` configuration file in `email-threat-intel/backend/`:
   ```ini
   # Database (SQLite - file-based)
   DATABASE_URL=sqlite:///./email_threat_db.sqlite3

   # Redis (Optional)
   REDIS_URL=redis://localhost:6379/0

   # API Keys (VirusTotal & AbuseIPDB)
   VIRUSTOTAL_API_KEY=your_key_here
   ABUSEIPDB_API_KEY=your_key_here
   MESA_SECURITY_API_KEY=your_key_here

   # Settings
   SECRET_KEY=your_secret_key_here
   DEBUG=True
   ```

### 2. Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd email-threat-intel/frontend
   ```
2. Install frontend dependencies:
   ```bash
   npm install
   ```

---

## Execution Guide

### 1. Launch the Backend Server
From the `email-threat-intel/backend` directory (with virtual environment active):
```bash
python run.py
```
*Note*: The API will start on [http://localhost:8000](http://localhost:8000). Interactive OpenAPI docs are available at [http://localhost:8000/docs](http://localhost:8000/api/docs).

### 2. Launch the Frontend Server
From the `email-threat-intel/frontend` directory:
```bash
npm run dev
```
*Note*: The web app will launch on [http://localhost:5173](http://localhost:5173).

---

