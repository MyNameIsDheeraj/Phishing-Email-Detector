# Product Requirements Document (PRD)

## Project Title

**Advanced Email Threat Intelligence Platform**

---

# 1. Product Overview

The Advanced Email Threat Intelligence Platform is a cybersecurity-focused web application designed to analyze suspicious emails and detect spam, phishing attempts, malicious URLs, compromised sender IPs, and suspicious attachments using rule-based analysis and real-world threat intelligence integrations.

Unlike traditional phishing detectors that rely only on static keyword matching, this system integrates external intelligence sources such as VirusTotal, AbuseIPDB, and Spamhaus to perform deeper email forensic analysis.

The platform helps security analysts, SOC teams, and general users investigate email threats in real time.

---

# 2. Problem Statement

Phishing attacks remain one of the most effective cyberattack vectors used to steal credentials, financial information, and sensitive personal data.

Traditional spam filters often fail to:

* Detect zero-day phishing campaigns
* Verify sender IP reputation
* Analyze embedded URLs
* Detect malicious attachments
* Validate SPF, DKIM, and DMARC records

This creates major security gaps.

The system aims to provide a centralized solution for analyzing emails and generating actionable threat intelligence.

---

# 3. Objectives

### Primary Objectives

* Detect phishing emails using rule-based analysis
* Identify suspicious keywords and urgency phrases
* Extract URLs and validate their reputation
* Analyze sender IP reputation
* Detect domain blacklisting
* Validate email authentication protocols
* Perform attachment hash reputation checks
* Generate threat scores
* Create forensic timelines
* Provide downloadable reports

### Secondary Objectives

* Improve cybersecurity awareness
* Reduce phishing-related risks
* Assist SOC analysts in email investigations

---

# 4. Target Users

* Security Analysts
* SOC Teams
* Cybersecurity Students
* Enterprises
* Email Administrators
* Security Researchers

---

# 5. Scope

## In Scope

* Email parsing (.eml files)
* Rule-based phishing detection
* VirusTotal integration
* AbuseIPDB integration
* Spamhaus DNSBL checks
* SPF/DKIM/DMARC validation
* Attachment hash scanning
* Threat scoring engine
* Timeline generation
* Dashboard reporting

## Out of Scope (Initial Version)

* AI-based detection
* Sandbox attachment execution
* Live email gateway integration
* SIEM integration

---

# 6. Functional Requirements

## 6.1 Email Upload Module

Users must be able to upload email files.

Supported formats:

* .eml
* raw email text

---

## 6.2 Email Parsing Module

The system must extract:

* Sender email
* Subject
* Body content
* Received headers
* URLs
* Attachments
* Authentication headers

---

## 6.3 Rule-Based Analysis

Detect:

* Urgent keywords
* Suspicious phrases
* Excessive links
* Password reset traps
* Fake banking requests

---

## 6.4 URL Analysis

Extract URLs and send them to VirusTotal.

Output:

* Malicious
* Suspicious
* Clean

---

## 6.5 IP Reputation Analysis

Extract sender IP and analyze using AbuseIPDB.

Return:

* Confidence score
* Abuse reports
* ISP
* Country

---

## 6.6 Spamhaus Blacklist Check

Check whether sender IP exists in Spamhaus DNSBL.

---

## 6.7 SPF Validation

Validate sender domain SPF.

Result:

* Pass
* Fail
* SoftFail

---

## 6.8 DKIM Validation

Verify cryptographic signature integrity.

---

## 6.9 DMARC Validation

Check domain policy alignment.

---

## 6.10 Attachment Hash Analysis

Generate SHA256 hashes.

Check with VirusTotal.

---

## 6.11 Threat Scoring Engine

Calculate cumulative score based on:

* Keyword hits
* URL risk
* IP abuse
* Blacklist status
* SPF/DKIM/DMARC failures
* Attachment reputation

---

## 6.12 Report Generation

Generate PDF reports containing:

* Threat indicators
* Risk score
* Timeline
* IOC summary

---

# 7. Non-Functional Requirements

* Fast processing (<10 seconds average)
* High availability
* Secure API storage
* Scalable architecture
* Async background processing
* Encrypted API keys
* Role-based access control

---

# 8. System Architecture

User Upload
↓
FastAPI Backend
↓
Email Parser
↓
Threat Analysis Engine
├── Rule Engine
├── VirusTotal
├── AbuseIPDB
├── Spamhaus
├── SPF/DKIM/DMARC
↓
Scoring Engine
↓
SQL Database
↓
React Dashboard
↓
PDF Report Generator

---

# 9. Tech Stack

Backend:
FastAPI

Frontend:
React.js

Database:
SQL

Queue:
Celery

Broker:
Redis

Threat Intelligence APIs:
VirusTotal
AbuseIPDB
Spamhaus

Libraries:
SQLAlchemy
Requests
dnspython
dkimpy
pyspf
hashlib
reportlab

Deployment:
Render / Railway / Vercel

---

# 10. Database Design

Tables:

### emails

* id
* sender
* subject
* body
* risk_score
* verdict
* created_at

### urls

* id
* email_id
* url
* vt_result

### ips

* id
* email_id
* ip_address
* abuse_score
* blacklist_status

### attachments

* id
* email_id
* file_name
* sha256
* vt_result

### reports

* id
* email_id
* generated_at

---

# 11. API Endpoints

POST /upload-email

POST /analyze-email

GET /email/{id}

GET /report/{id}

GET /timeline/{id}

GET /dashboard/stats

---

# 12. Security Requirements

* Store API keys in environment variables
* Rate limiting
* Input validation
* File type restrictions
* SQL injection prevention
* Secure JWT authentication
* Role-based authorization

---

# 13. Risk Analysis

Risks:

* API rate limits
* False positives
* False negatives
* Large file uploads
* Slow third-party responses

Mitigation:

* Celery async processing
* Caching
* Retry mechanism
* Fallback scoring

---

# 14. Milestones

Phase 1:
Backend setup

Phase 2:
Email parser

Phase 3:
Threat integrations

Phase 4:
Database implementation

Phase 5:
Scoring engine

Phase 6:
Frontend dashboard

Phase 7:
Report generation

Phase 8:
Deployment

---

# 15. Future Enhancements

* Machine learning phishing detection
* OCR for image-based phishing
* Live Gmail integration
* Outlook integration
* Real-time threat feeds
* YARA scanning
* Sandbox execution
* SIEM integration
* Threat hunting dashboard

---

# 16. Success Metrics

* Detection accuracy
* Average scan time
* False positive rate
* User adoption
* Threat intelligence enrichment rate
* Report generation speed

---

# 17. Conclusion

The Advanced Email Threat Intelligence Platform extends beyond traditional rule-based phishing detection by integrating real-world threat intelligence and forensic analysis capabilities.

This system provides practical SOC-level email threat analysis while maintaining scalability and modularity for future enterprise expansion.
