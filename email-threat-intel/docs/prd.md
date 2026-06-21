# Product Requirements Document (PRD) - Phishing Email Detector

## 1. Product Overview
The **Phishing Email Detector** is a security-focused web application designed to act as a lightweight, local Security Operations Center (SOC) console. It allows users to analyze suspicious email files (`.eml` or `.txt`) or raw email headers/body text, extracting key security indicators (URLs, IP addresses, domains, and attachments) and calculating a comprehensive threat score.

## 2. Problem Statement
Phishing remains one of the primary vectors for security breaches. Standard email clients do not provide deep forensic analysis (e.g., verifying DKIM, DMARC, SPF protocols, checking blacklists, or looking up URLs and files on reputation services like VirusTotal and AbuseIPDB). Security practitioners and users need an interactive tool to quickly inspect raw email contents safely without opening malicious links or running attachments.

## 3. Target Audience & Personas
- **SOC Analysts / Security Practitioners**: Need to inspect raw emails, view cryptographic authentication statuses, and fetch automated threat reports.
- **System Administrators**: Need to troubleshoot mail delivery SPF/DKIM validation failures.
- **Regular Tech-Savvy Users**: Need to check if a suspicious bank alert or service notice they received is a phishing attempt.

## 4. Key Product Features
- **Forensic Threat Assessment Engine**: A rule-based engine combined with external reputation APIs (VirusTotal, AbuseIPDB) to score emails on a scale of 0-100%.
- **Email Protocol Verification**: Automatic parsing and checking of SPF records, DKIM cryptographic signatures, and DMARC alignment.
- **Interactive Security Dashboard**: Visualization of overall threat stats (Scanned count, average threat score, malicious count, and verdict breakdown) alongside a recent logs table.
- **Security IOC Extraction & List**: Automatic extraction of Indicators of Compromise (IOCs) including URLs, IPs, domains, and attachment hashes (SHA-256).
- **PDF Threat Report Export**: Ability to download a clean, professionally formatted PDF report summarizing the forensic timeline and security verdicts.
- **Local Database Management (SQLite)**: File-based SQLite storage residing in the backend directory to track scanned logs and maintain history offline.

## 5. Non-Functional Requirements
- **Privacy & Security**: Email text parsing must occur locally. Database must be fully local and file-based.
- **Usability**: Sleek, modern dark-themed dashboard with glassmorphic aesthetics and immediate visual markers for MALICIOUS, SUSPICIOUS, or SAFE verdicts.
- **Performance**: Email parsing must occur instantly (< 500ms). External api checks should run asynchronously in the background.
