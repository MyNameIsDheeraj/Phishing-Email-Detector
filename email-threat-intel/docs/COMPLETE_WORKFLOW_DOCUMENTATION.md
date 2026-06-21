# Email Threat Intelligence Platform - Complete Workflow Documentation

**Version**: 2.0.0  
**Last Updated**: June 21, 2026  
**Project Type**: SOC-Level Email Phishing Detection System  

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Complete Code Workflow](#complete-code-workflow)
4. [Database Schema](#database-schema)
5. [Backend Structure](#backend-structure)
6. [Frontend Structure](#frontend-structure)
7. [API Reference](#api-reference)
8. [Detection Rules Engine](#detection-rules-engine)
9. [External Integrations](#external-integrations)
10. [Threat Scoring Algorithm](#threat-scoring-algorithm)

---

## Project Overview

### Purpose
The **Email Threat Intelligence Platform** is a comprehensive SOC (Security Operations Center) console designed for:
- Parsing and analyzing email files (.eml, .txt formats)
- Extracting indicators of compromise (URLs, IPs, domains, file hashes)
- Validating email authentication protocols (SPF, DKIM, DMARC)
- Performing threat intelligence lookups via VirusTotal and AbuseIPDB
- Conducting advanced phishing detection using Mesa Security API
- Generating forensic reports and maintaining audit trails

### Technology Stack

**Backend:**
- Framework: FastAPI 0.104.1 (async/await Python web framework)
- Server: Uvicorn 0.24.0 (ASGI server)
- ORM: SQLAlchemy 2.0.23 (object-relational mapping)
- Database: SQLite (file-based, no external dependencies)
- Validation: Pydantic 2.5.0 (data validation)
- HTTP Client: httpx 0.25.2 (async HTTP requests)

**Frontend:**
- Framework: React (18.x)
- Bundler: Vite 5.4.21 (next-gen build tool)
- UI Icons: Lucide React (2000+ SVG icons)
- HTTP: Native Fetch API
- Styling: Vanilla CSS with custom properties (dark cybersecurity theme)

**Database:**
- SQLite with SQLAlchemy ORM
- Tables: emails, urls, ips, events, attachments, iocs, reports

**Email Processing:**
- Email Parsing: Python standard library `email` module
- HTML Conversion: BeautifulSoup 4.12.2
- SPF Validation: dnspython + pyspf
- DKIM Verification: dkimpy library
- DMARC Alignment: Custom implementation
- Blacklist Checking: Spamhaus DNSBL lookup

---

## System Architecture

### High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ USER INTERACTION LAYER                                          │
│ ┌─────────────────┐  ┌────────────────────────┐                 │
│ │ React Frontend  │  │ Upload Form / Text Area│                 │
│ │ (Dashboard)     │  │ (Drag & Drop / Paste)  │                 │
│ └────────┬────────┘  └────────────┬───────────┘                 │
│          │                         │                             │
│          └─────────────────────────┘                             │
│                     ↓                                             │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ FASTAPI BACKEND (Main Analysis Engine)                           │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ POST /upload-email | POST /analyze-email                   │ │
│ │ ↓                                                           │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ 1. EMAIL PARSING (EmailParser)                         │ │ │
│ │ │    - Extract sender, subject, body, headers            │ │ │
│ │ │    - Extract URLs, IPs, domains, attachments           │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ │ ↓                                                           │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ 2. AUTHENTICATION CHECKS                               │ │ │
│ │ │    - SPF validation (DNS lookup)                       │ │ │
│ │ │    - DKIM signature verification (cryptographic)       │ │ │
│ │ │    - DMARC alignment check                             │ │ │
│ │ │    - Spamhaus DNSBL lookup                             │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ │ ↓                                                           │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ 3. RULE-BASED DETECTION (RuleBasedDetector)            │ │ │
│ │ │    - Check for spam keywords (36 keywords)             │ │ │
│ │ │    - Detect urgency phrases (14 phrases)               │ │ │
│ │ │    - Analyze link patterns (count, shorteners, IPs)    │ │ │
│ │ │    - Detect sender spoofing attacks                    │ │ │
│ │ │    - Check for suspicious TLDs (14 TLDs)              │ │ │
│ │ │    - Analyze uppercase/exclamation usage               │ │ │
│ │ │    - Detect IDN/homograph attacks                      │ │ │
│ │ │    → Score: 0-100 (Direct points, strict thresholds)   │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ │ ↓                                                           │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ 4. DATABASE PERSISTENCE                                │ │ │
│ │ │    - Create email record in SQLite                     │ │ │
│ │ │    - Store URLs, IPs, attachments, domains             │ │ │
│ │ │    - Create event timeline (forensic log)              │ │ │
│ │ │    - Store IOCs (indicators of compromise)             │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ │ ↓                                                           │ │
│ │ ┌─────────────────────────────────────────────────────────┐ │ │
│ │ │ 5. INITIAL VERDICT (SYNCHRONOUS)                       │ │ │
│ │ │    - Score >= 40: MALICIOUS (HIGH confidence)          │ │ │
│ │ │    - Score 20-39: SUSPICIOUS (MEDIUM confidence)       │ │ │
│ │ │    - Score < 20: SAFE (LOW confidence)                 │ │ │
│ │ │    → Return to frontend immediately                    │ │ │
│ │ └─────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ BACKGROUND ENRICHMENT (Asynchronous Tasks)                  │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ VT Service                 AbuseIPDB Service            │ │ │
│ │ │ - Check URL reputation     - Check IP reputation        │ │ │
│ │ │ - Check file hashes        - Get abuse score            │ │ │
│ │ │ - Get malicious count      - Get country & ISP          │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ │                  ↓                                            │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ Mesa Security Service                                   │ │ │
│ │ │ - Submit email for full content analysis               │ │ │
│ │ │ - Poll job status (max 30 attempts × 2 sec)           │ │ │
│ │ │ - Get detailed threat verdict & score                  │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ │                  ↓                                            │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ Recalculate Threat Score                               │ │ │
│ │ │ (Combines rule + auth + VT + AbuseIPDB + Mesa)         │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ FRONTEND DASHBOARD (React Components)                            │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ Tab 1: Dashboard                                            │ │
│ │ - Statistics cards (total emails, avg score, verdicts)     │ │
│ │ - Recent analysis history (table view)                     │ │
│ │ - Verdict breakdown (progress bars)                        │ │
│ │ - IOC extraction totals (URLs, IPs, hashes, events)        │ │
│ │                                                              │ │
│ │ Tab 2: Analyze Email                                        │ │
│ │ - Drag & drop upload area (.eml/.txt)                      │ │
│ │ - Raw email text paste area                                │ │
│ │ - "Run Forensic Scan" buttons                              │ │
│ │                                                              │ │
│ │ Tab 3: Forensic Logs                                        │ │
│ │ - Paginated email history table                            │ │
│ │ - Verdict filtering (ALL, MALICIOUS, SUSPICIOUS, SAFE)     │ │
│ │ - Search by sender/subject                                 │ │
│ │                                                              │ │
│ │ Tab 4: Forensic Report                                      │ │
│ │ - Email metadata display                                    │ │
│ │ - Authentication status (SPF/DKIM/DMARC)                   │ │
│ │ - Extracted IOCs (URLs, IPs, domains, attachments)         │ │
│ │ - Forensic timeline (events with timestamps)               │ │
│ │ - Threat indicators & rule triggers                        │ │
│ │ - Manual enrichment button (VT/AbuseIPDB/Mesa)             │ │
│ │ - PDF report download                                       │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Complete Code Workflow

### Step-by-Step Execution Flow

#### **STEP 1: User Uploads Email**

```javascript
// Frontend: src/App.jsx - handleFileUploadSubmit()
const handleFileUploadSubmit = async (e) => {
  e.preventDefault();
  if (!uploadFile) return;
  
  setIsAnalyzing(true);
  try {
    const result = await api.uploadEmailFile(uploadFile);
    // result: { id, verdict, threat_score, details, ... }
    showToast('Email parsed and analyzed successfully');
    await loadEmailDetails(result.id);
    checkHealthAndLoadStats();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setIsAnalyzing(false);
  }
};
```

```javascript
// Frontend: src/api.js - uploadEmailFile()
uploadEmailFile: async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE_URL}/upload-email`, {
    method: 'POST',
    body: formData
  });
  return handleResponse(res);
}
```

#### **STEP 2: Backend Receives and Parses Email**

```python
# Backend: app/main.py - POST /upload-email

@app.post("/upload-email")
async def upload_email(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    # 2.1: Validate file type (.eml or .txt)
    allowed_extensions = ['.eml', '.txt']
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    
    # 2.2: Read and decode email content
    content = await file.read()
    try:
        raw_email = content.decode('utf-8')
    except UnicodeDecodeError:
        raw_email = content.decode('latin-1')
    
    # 2.3: Initialize email parser
    parser = EmailParser(raw_email)
    raw_bytes = parser.get_raw_bytes()
    
    # 2.4: Extract structured data
    sender = parser.get_sender()           # "attacker@phishing.com"
    subject = parser.get_subject()         # "URGENT: Verify Your Account!"
    body = parser.get_body()               # Full email body text
    headers = parser.get_headers()         # Dict of all SMTP headers
    urls = parser.extract_urls()           # ["http://phishing.com/login"]
    ips = parser.extract_ips()             # ["192.168.1.1"] (sender IP first)
    domains = parser.extract_domains()     # ["phishing.com"]
    attachments = parser.extract_attachments()  # [{"filename": "...", "sha256": "..."}]
```

#### **STEP 3: Parse Email Headers (EmailParser)**

```python
# Backend: app/core/parser.py - EmailParser class

class EmailParser:
    def __init__(self, raw_email: str):
        self.raw_email = raw_email
        self.parsed_email = email.message_from_string(
            raw_email, 
            policy=default
        )
    
    def get_sender(self) -> str:
        """Extract sender email from 'From' header"""
        from_header = self.parsed_email.get('From', '')
        match = re.search(r'<(.+?)>', from_header)
        if match:
            return match.group(1)
        return from_header.strip()
    
    def get_subject(self) -> str:
        """Extract subject from 'Subject' header"""
        return self.parsed_email.get('Subject', '').strip()
    
    def get_body(self) -> str:
        """Extract email body (handle both text/plain and text/html)"""
        body = ""
        if self.parsed_email.is_multipart():
            for part in self.parsed_email.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_content()
                        break
                    except:
                        continue
                elif part.get_content_type() == "text/html":
                    try:
                        html_content = part.get_content()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        body = soup.get_text(separator='\n')
                        break
                    except:
                        continue
        else:
            # Single part email
            content_type = self.parsed_email.get_content_type()
            try:
                content = self.parsed_email.get_content()
                if content_type == "text/html":
                    soup = BeautifulSoup(content, 'html.parser')
                    body = soup.get_text(separator='\n')
                else:
                    body = content
            except:
                body = str(self.parsed_email)
        
        return body.strip()
    
    def extract_urls(self) -> List[str]:
        """Extract all URLs from email body"""
        body = self.get_body()
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)
        return list(set(urls))  # Remove duplicates
    
    def extract_ips(self) -> List[str]:
        """Extract IPs with sender IP prioritized"""
        sender_ip = self.get_sender_ip()  # From Received headers
        ips = []
        if sender_ip:
            ips.append(sender_ip)  # Index 0: sender IP
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        headers = self.get_headers()
        
        # Check headers (Received, X-Originating-IP, X-Forwarded-For)
        for header in ['received', 'x-originating-ip', 'x-forwarded-for']:
            if header in headers:
                found = re.findall(ip_pattern, headers[header])
                for ip in found:
                    if not self._is_private_ip(ip) and ip not in ips:
                        ips.append(ip)
        
        # Check body
        body = self.get_body()
        found = re.findall(ip_pattern, body)
        for ip in found:
            if not self._is_private_ip(ip) and ip not in ips:
                ips.append(ip)
        
        return ips
    
    def extract_domains(self) -> List[str]:
        """Extract domains from extracted URLs"""
        urls = self.extract_urls()
        domains = []
        for url in urls:
            match = re.search(r'https?://([^/]+)', url)
            if match:
                domain = match.group(1)
                domain = re.sub(r'^www\.', '', domain)
                domains.append(domain)
        return list(set(domains))
    
    def extract_attachments(self) -> List[Dict]:
        """Extract attachments with SHA-256 hashes"""
        attachments = []
        for part in self.parsed_email.walk():
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                if payload:
                    import hashlib
                    sha256 = hashlib.sha256(payload).hexdigest()
                    attachments.append({
                        "filename": filename,
                        "sha256": sha256,
                        "content": payload
                    })
        return attachments
```

#### **STEP 4: Authentication Protocol Checks**

```python
# Backend: app/main.py - Email validation

# 4.1: SPF Validation
sender_ip = ips[0] if ips else None
spf_status = validate_spf(sender_ip, sender)
# Result: "PASS", "FAIL", "SOFTFAIL", "NONE", "PERMERROR"

# 4.2: DKIM Signature Verification
raw_bytes = parser.get_raw_bytes()
dkim_status = validate_dkim(raw_bytes, sender.split('@')[-1] if '@' in sender else None)
# Result: "PASS", "FAIL", "NONE"

# 4.3: DMARC Alignment
dmarc_status = validate_dmarc(sender.split('@')[-1] if '@' in sender else "", spf_status, dkim_status)
# Result: "PASS", "FAIL", "NONE"

# 4.4: Spamhaus DNSBL Lookup
spamhaus_flagged = check_spamhaus(sender_ip) if sender_ip else False
# Result: True/False
```

```python
# Backend: app/core/auth_checks.py

def validate_spf(sender_ip: str, sender_email: str) -> str:
    """
    Perform SPF DNS lookup and validation
    SPF record format: "v=spf1 ip4:192.0.2.0 include:example.com ~all"
    """
    if not sender_ip or not sender_email:
        return "NONE"
    
    try:
        domain = sender_email.split('@')[1]
        
        # Query SPF record (TXT)
        spf_record = get_spf_record(domain)
        if not spf_record:
            return "NONE"
        
        # Validate IP against SPF record
        result = spf(ip=sender_ip, domain=domain, mailfrom=sender_email)
        # pyspf returns: 'pass', 'fail', 'softfail', 'neutral', 'permerror', 'temperror'
        
        return result.upper()
    except Exception as e:
        return "PERMERROR"

def validate_dkim(raw_email_bytes: bytes, domain: str) -> str:
    """
    Verify DKIM signature in email headers
    DKIM-Signature header contains cryptographic signature
    """
    if not raw_email_bytes or not domain:
        return "NONE"
    
    try:
        # Extract DKIM-Signature header
        result = verify(raw_email_bytes)
        # dkimpy.verify() returns: True/False or dict with details
        
        if result:
            return "PASS"
        else:
            return "FAIL"
    except Exception as e:
        return "NONE"

def validate_dmarc(domain: str, spf_status: str, dkim_status: str) -> str:
    """
    Check DMARC alignment
    DMARC requires SPF or DKIM to pass with domain alignment
    """
    if not domain:
        return "NONE"
    
    try:
        # Query DMARC record (TXT _dmarc.domain)
        dmarc_record = get_dmarc_record(domain)
        if not dmarc_record:
            return "NONE"
        
        # DMARC alignment: SPF and/or DKIM must pass
        if spf_status == "PASS" or dkim_status == "PASS":
            return "PASS"
        else:
            return "FAIL"
    except Exception as e:
        return "PERMERROR"

def check_spamhaus(ip_address: str) -> bool:
    """
    Query Spamhaus DNSBL for IP reputation
    """
    if not ip_address:
        return False
    
    try:
        # Reverse IP for DNSBL query: 192.168.1.1 → 1.1.168.192
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        hostname = f"{reversed_ip}.zen.spamhaus.org"
        
        # DNS lookup
        result = socket.gethostbyname(hostname)
        # If resolves, IP is blacklisted
        return True
    except:
        # No DNS resolution = not blacklisted
        return False
```

#### **STEP 5: Rule-Based Detection Engine**

```python
# Backend: app/core/rules.py - RuleBasedDetector

class RuleBasedDetector:
    def analyze(self, email_data: Dict) -> Dict:
        """
        Analyze email and return score with details - STRICT CRITERIA
        """
        score = 0
        details = []
        
        # Run all detection rules
        score += self._check_keywords(email_data, details)          # Max: 23 pts
        score += self._check_urgency(email_data, details)           # Max: 19 pts
        score += self._check_links(email_data['urls'], details)     # Max: 20 pts
        score += self._check_exclamations(email_data, details)      # Max: 12 pts
        score += self._check_uppercase(email_data, details)         # Max: 15 pts
        score += self._check_sender_spoofing(email_data, details)   # Max: 25 pts
        score += self._check_suspicious_domains(email_data['domains'], details)  # Max: 25 pts
        score += self._check_missing_headers(email_data['headers'], details)     # Max: 15 pts
        score += self._check_link_shorteners(email_data['urls'], details)        # Max: 21 pts
        score += self._check_ip_links(email_data['urls'], details)  # Max: 22 pts
        score += self._check_idn_homograph(email_data['domains'], details)       # Max: 20 pts
        
        # Cap score at 100
        normalized_score = min(100, score)
        
        # STRICT VERDICTS (Direct scoring, no multiplier)
        # >= 40: MALICIOUS (very aggressive)
        # >= 20: SUSPICIOUS (even minor findings)
        # < 20: SAFE
        if normalized_score >= 40:
            verdict = "MALICIOUS"
            confidence = "HIGH"
        elif normalized_score >= 20:
            verdict = "SUSPICIOUS"
            confidence = "MEDIUM"
        else:
            verdict = "SAFE"
            confidence = "LOW"
        
        return {
            'score': normalized_score,
            'verdict': verdict,
            'confidence': confidence,
            'details': details
        }

    # RULE 1: SPAM KEYWORDS (Max: 23 points)
    def _check_keywords(self, email_data: Dict, details: List) -> int:
        """
        Check for spam/phishing keywords
        Keywords: "free money", "claim now", "verify account", "urgent", etc.
        """
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        found_subject = [k for k in self.spam_keywords if k.lower() in subject.lower()]
        found_body = [k for k in self.spam_keywords if k.lower() in body.lower()]
        
        score = 0
        if found_subject:
            details.append(f"⚠️ SPAM keyword in subject: {', '.join(found_subject[:3])}")
            score += 15 + (len(found_subject) - 1) * 8  # 1 keyword=15, 2=23
        
        if found_body:
            details.append(f"⚠️ SPAM keyword in body: {', '.join(found_body[:3])}")
            score += 20 + (len(found_body) - 1) * 5  # 1 keyword=20
        
        return score

    # RULE 2: URGENCY PHRASES (Max: 19 points)
    def _check_urgency(self, email_data: Dict, details: List) -> int:
        """
        Check for urgency trigger phrases
        Phrases: "act now", "expires", "immediate attention", etc.
        """
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        found_subject = [p for p in self.urgency_phrases if p.lower() in subject.lower()]
        found_body = [p for p in self.urgency_phrases if p.lower() in body.lower()]
        
        score = 0
        if found_subject:
            details.append(f"🚨 URGENCY in subject: {', '.join(found_subject[:2])}")
            score += 12 + (len(found_subject) - 1) * 6  # 1=12, 2=18
        
        if found_body:
            details.append(f"🚨 URGENCY in body: {', '.join(found_body[:2])}")
            score += 15 + (len(found_body) - 1) * 4  # 1=15, 2=19
        
        return score

    # RULE 3: LINK ANALYSIS (Max: 20 points)
    def _check_links(self, urls: List[str], details: List) -> int:
        """
        Analyze link count and density
        >5 links = 20 pts, 2-5 = 12 pts, 1 = 5 pts
        """
        if len(urls) == 0:
            return 0
        
        if len(urls) > 5:
            details.append(f"🔗 MULTIPLE LINKS ({len(urls)}) - High link density")
            return 20
        elif len(urls) > 2:
            details.append(f"🔗 Multiple links present ({len(urls)})")
            return 12
        else:
            details.append(f"🔗 Single link detected")
            return 5

    # RULE 4: EXCLAMATION MARKS (Max: 12 points)
    def _check_exclamations(self, email_data: Dict, details: List) -> int:
        """
        Check for excessive exclamation marks
        Subject: any = +6, body: >3 = +12, 0-3 = +6
        """
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        score = 0
        subj_count = subject.count('!')
        body_count = body.count('!')
        
        if subj_count > 0:
            details.append(f"❗ Subject has {subj_count} exclamation mark(s)")
            score += 6 + min(10, subj_count * 2)
        
        if body_count > 3:
            details.append(f"❗ Body has excessive exclamations ({body_count})")
            score += 12
        elif body_count > 0:
            details.append(f"❗ Body has {body_count} exclamation mark(s)")
            score += 6
        
        return score

    # RULE 5: UPPERCASE ANALYSIS (Max: 15 points)
    def _check_uppercase(self, email_data: Dict, details: List) -> int:
        """
        Check for excessive uppercase letters
        Subject >50% uppercase = 10 pts, ANY ALL-CAPS words = 5 pts
        Body: ANY ALL-CAPS words = 6+ pts
        """
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        score = 0
        subj_words = re.findall(r'\b[A-Za-z]+\b', subject)
        subj_upper = re.findall(r'\b[A-Z]{3,}\b', subject)
        
        if subj_words and len(subj_upper) / len(subj_words) > 0.5:
            details.append(f"🔤 Subject is {int(len(subj_upper)/len(subj_words)*100)}% UPPERCASE")
            score += 10
        elif subj_words and len(subj_upper) > 0:
            details.append(f"🔤 Subject has {len(subj_upper)} ALL-CAPS words")
            score += 5
        
        body_words = re.findall(r'\b[A-Z]{4,}\b', body)
        if body_words:
            details.append(f"🔤 Body has {len(body_words)} ALL-CAPS word(s)")
            score += 6 + min(10, len(body_words) * 2)
        
        return score

    # RULE 6: SENDER SPOOFING (Max: 25 points)
    def _check_sender_spoofing(self, email_data: Dict, details: List) -> int:
        """
        Detect brand impersonation and spoofing
        Any brand misuse = 25 pts (e.g., "paypal" in Gmail account)
        """
        sender = email_data.get('sender', '') or ''
        if not sender:
            return 0
        
        # Free email providers
        free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        suspicious_senders = ["paypal", "apple", "microsoft", "amazon", "chase"]
        
        parts = sender.split('@')
        if len(parts) != 2:
            return 0
        
        local_part = parts[0].lower()
        domain = parts[1].lower()
        
        # Check for brand misuse in free email
        if domain in free_domains:
            for brand in suspicious_senders:
                if brand in local_part:
                    details.append(f"🔓 BRAND SPOOFING: '{brand}' in free email: {sender}")
                    return 25
        
        return 0

    # RULE 7: SUSPICIOUS TLDs (Max: 25 points)
    def _check_suspicious_domains(self, domains: List[str], details: List) -> int:
        """
        Check for suspicious top-level domains
        TLDs: .tk, .ml, .ga, .cf, .xyz, .top, .work, etc.
        Any suspicious TLD = 20+ pts
        """
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.date', '.bid']
        
        found = []
        for domain in domains:
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    found.append(domain)
                    break
        
        if found:
            details.append(f"🌐 SUSPICIOUS TLD: {', '.join(found[:2])}")
            return min(25, 20 + len(found) * 3)
        
        return 0

    # RULE 8: MISSING HEADERS (Max: 15 points)
    def _check_missing_headers(self, headers: Dict, details: List) -> int:
        """
        Check for missing security headers
        No SPF/DKIM/DMARC = 15 pts, Partial = 8 pts
        """
        critical_headers = ['received', 'message-id', 'date']
        
        has_spf = any(h in headers for h in ['spf', 'received-spf', 'authentication-results'])
        has_dkim = any(h in headers for h in ['dkim', 'dkim-signature', 'authentication-results'])
        has_dmarc = any(h in headers for h in ['dmarc', 'authentication-results'])
        
        auth_count = sum([has_spf, has_dkim, has_dmarc])
        
        score = 0
        if auth_count == 0:
            details.append("🔓 MISSING AUTH: No SPF/DKIM/DMARC headers found")
            score += 15
        elif auth_count < 3:
            details.append(f"⚠️ LIMITED AUTH: Only {auth_count}/3 authentication protocols")
            score += 8
        
        return score

    # RULE 9: LINK SHORTENERS (Max: 21 points)
    def _check_link_shorteners(self, urls: List[str], details: List) -> int:
        """
        Detect URL shortening services (common in phishing)
        Shorteners: bit.ly, tinyurl.com, t.co, goo.gl, etc.
        Any shortener = 18 pts
        """
        shorteners = ["bit.ly", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "t.co", "goo.gl"]
        
        found = []
        for url in urls:
            for shortener in shorteners:
                if shortener in url.lower():
                    found.append(shortener)
                    break
        
        if found:
            details.append(f"🔗 LINK SHORTENER: {', '.join(found)}")
            return 18 + len(found) * 3
        
        return 0

    # RULE 10: IP-BASED LINKS (Max: 22 points)
    def _check_ip_links(self, urls: List[str], details: List) -> int:
        """
        Detect links using raw IP addresses (highly suspicious)
        Pattern: http://192.168.1.1/phish
        IP link = 22 pts
        """
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        
        found = []
        for url in urls:
            if re.match(ip_pattern, url):
                found.append(url)
        
        if found:
            details.append(f"🔗 RAW IP LINK (HIGHLY SUSPICIOUS): {found[0][:40]}")
            return 22
        
        return 0

    # RULE 11: IDN HOMOGRAPH ATTACKS (Max: 20 points)
    def _check_idn_homograph(self, domains: List[str], details: List) -> int:
        """
        Detect Internationalized Domain Names (IDN) homograph attacks
        Pattern: xn-- prefix (Punycode encoding of non-ASCII characters)
        IDN domain = 20 pts
        """
        found = False
        for domain in domains:
            if domain.startswith("xn--"):
                found = True
                details.append(f"🌐 IDN HOMOGRAPH (INTERNATIONALIZED): {domain}")
                break
            if not all(ord(char) < 128 for char in domain):
                found = True
                details.append(f"🌐 NON-ASCII DOMAIN (HOMOGRAPH RISK): {domain}")
                break
        
        if found:
            return 20
        
        return 0
```

#### **STEP 6: Database Persistence**

```python
# Backend: app/main.py - Database storage

# 6.1: Create email record
db_email = Email(
    sender=sender,
    sender_domain=sender.split('@')[-1] if '@' in sender else '',
    subject=subject[:500],
    body=body[:10000],
    headers=headers,  # JSON
    rule_score=rule_result['score'],
    threat_score=rule_result['score'],
    verdict=rule_result['verdict'],
    confidence=rule_result['confidence'],
    spf_status=spf_status,
    dkim_status=dkim_status,
    dmarc_status=dmarc_status,
    attachment_verdict="NONE" if not attachments else "UNVERIFIED",
    received_at=datetime.utcnow()
)
db.add(db_email)
db.flush()  # Get the ID

# 6.2: Store extracted URLs
for url in urls[:50]:
    db_url = URL(
        email_id=db_email.id,
        url=url[:500],
        domain=url.split('/')[2] if '://' in url else ''
    )
    db.add(db_url)

# 6.3: Store extracted IPs
for ip in ips[:20]:
    is_sender = (ip == sender_ip)
    db_ip = IP(
        email_id=db_email.id,
        ip_address=ip,
        spamhaus_flagged=spamhaus_flagged if is_sender else False,
        is_malicious=spamhaus_flagged if is_sender else False
    )
    db.add(db_ip)

# 6.4: Store attachments
for att in attachments[:10]:
    db_att = Attachment(
        email_id=db_email.id,
        file_name=att['filename'][:255],
        sha256=att['sha256']
    )
    db.add(db_att)

# 6.5: Store IOCs (Indicators of Compromise)
for url in urls[:50]:
    db.add(IOC(email_id=db_email.id, ioc_type="URL", value=url[:500], threat_score=rule_result['score']))
for ip in ips[:20]:
    db.add(IOC(email_id=db_email.id, ioc_type="IP", value=ip, threat_score=rule_result['score']))
for domain in domains[:20]:
    db.add(IOC(email_id=db_email.id, ioc_type="DOMAIN", value=domain, threat_score=rule_result['score']))

db.commit()
db.refresh(db_email)
```

#### **STEP 7: Create Forensic Timeline**

```python
# Backend: app/main.py - Timeline event creation

# Create timeline events for forensic audit trail
events = [
    Event(email_id=db_email.id, event_type="RECEIVED", 
          description="Email received for forensic analysis", severity="INFO"),
    
    Event(email_id=db_email.id, event_type="PARSED", 
          description=f"Extracted {len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains, {len(attachments)} attachments", 
          severity="INFO"),
    
    Event(email_id=db_email.id, event_type="SPF_CHECK", 
          description=f"SPF authentication validation: {spf_status}", 
          severity="INFO" if spf_status == "PASS" else "WARNING"),
    
    Event(email_id=db_email.id, event_type="DKIM_CHECK", 
          description=f"DKIM cryptographic signature verification: {dkim_status}", 
          severity="INFO" if dkim_status == "PASS" else "WARNING"),
    
    Event(email_id=db_email.id, event_type="DMARC_CHECK", 
          description=f"DMARC record alignment: {dmarc_status}", 
          severity="INFO" if dmarc_status == "PASS" else "WARNING"),
    
    Event(email_id=db_email.id, event_type="SPAMHAUS_CHECK", 
          description=f"Spamhaus DNSBL reputation check for IP {sender_ip}: {'BLACKLISTED' if spamhaus_flagged else 'CLEAN'}", 
          severity="ERROR" if spamhaus_flagged else "INFO"),
    
    Event(email_id=db_email.id, event_type="RULE_ANALYSIS", 
          description=f"Rule-based detection finished. Score: {rule_result['score']}/100. Verdict: {rule_result['verdict']}", 
          severity="WARNING" if rule_result['verdict'] in ['SUSPICIOUS', 'MALICIOUS'] else "INFO"),
    
    Event(email_id=db_email.id, event_type="RULE_DETAILS", 
          description=f"Rule triggers: {', '.join(rule_result['details'][:5])}", 
          severity="INFO"),
]

# Add all events
for event in events:
    db.add(event)
db.commit()
```

#### **STEP 8: Calculate Threat Score (Dynamic)**

```python
# Backend: app/main.py - recalculate_threat_score()

def recalculate_threat_score(email: Email, db: Session):
    """
    Recalculates email threat score dynamically based on:
    1. Rule engine score
    2. Email authentication failures
    3. IP reputation & blacklist status
    4. Attachment reputation (VirusTotal)
    5. URL phishing reputation (VirusTotal)
    6. Mesa Security scan results
    """
    
    score = email.rule_score  # Start with base rule score
    
    # 1. Authentication Failures Penalty (Max: 20)
    auth_penalty = 0
    if email.spf_status == "FAIL":
        auth_penalty += 10
    if email.dkim_status == "FAIL":
        auth_penalty += 10
    if email.dmarc_status == "FAIL":
        auth_penalty += 10
    score += min(20, auth_penalty)
    
    # 2. IP Reputation Penalty (Max: 20)
    has_ip_threat = False
    for ip in email.ips:
        if ip.spamhaus_flagged or ip.is_malicious or (ip.abuse_score and ip.abuse_score > 50):
            has_ip_threat = True
            break
    if has_ip_threat:
        score += 20
    
    # 3. Attachment Reputation (Max: 20)
    has_attachment_threat = False
    for att in email.attachments:
        if att.vt_malicious > 0:
            has_attachment_threat = True
            break
    
    if has_attachment_threat:
        email.attachment_verdict = "MALICIOUS"
        score += 20
    elif len(email.attachments) > 0:
        email.attachment_verdict = "SAFE"
    else:
        email.attachment_verdict = "NONE"
    
    # 4. URL Phishing Reputation (Max: 15)
    has_url_threat = False
    for url in email.urls:
        if url.is_phishing or url.vt_malicious > 0:
            has_url_threat = True
            break
    if has_url_threat:
        score += 15
    
    # 5. Mesa Security Results (Max: 25)
    if email.mesa_status == "completed" and email.mesa_verdict:
        if email.mesa_verdict.lower() in ["phishing", "malware", "malicious"]:
            score += 25
        elif email.mesa_verdict.lower() in ["spam", "suspicious", "warning"]:
            score += 15
        elif email.mesa_score and email.mesa_score > 0:
            score += min(25, email.mesa_score // 4)
    
    # Cap at 100
    email.threat_score = min(100, score)
    
    # Final Verdict
    if email.threat_score >= 70:
        email.verdict = "MALICIOUS"
        email.confidence = "HIGH"
    elif email.threat_score >= 40:
        email.verdict = "SUSPICIOUS"
        email.confidence = "MEDIUM"
    else:
        email.verdict = "SAFE"
        email.confidence = "LOW"
```

#### **STEP 9: Return Initial Response**

```python
# Backend: app/main.py - Return response after upload

response = {
    "id": db_email.id,
    "verdict": db_email.verdict,
    "threat_score": db_email.threat_score,
    "confidence": db_email.confidence,
    "details": rule_result['details'],
    "authentication": {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status
    },
    "iocs": {
        "urls": urls[:10],
        "ips": ips[:10],
        "domains": domains[:10],
        "attachments": [a['filename'] for a in attachments[:10]]
    },
    "stats": {
        "total_urls": len(urls),
        "total_ips": len(ips),
        "total_domains": len(domains),
        "total_attachments": len(attachments)
    },
    "filename": file.filename,
    "analyzed_at": (db_email.analyzed_at or db_email.received_at).isoformat()
}

# ✅ Immediately returned to frontend (User sees results)
return response
```

#### **STEP 10: Background Enrichment (Asynchronous)**

```python
# Backend: app/main.py - Trigger background task

if background_tasks:
    if os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("ABUSEIPDB_API_KEY") or os.getenv("MESA_SECURITY_API_KEY"):
        background_tasks.add_task(enrich_email_background, email_id=db_email.id)
        response["enrichment"] = "Started in background"

# Background task runs in parallel...
# User continues working while enrichment happens

async def enrich_email_background(email_id: int):
    """Background worker - runs after response sent"""
    
    # 1. VirusTotal URL Scanning
    for url_obj in email.urls[:10]:
        result = await vt_service.get_url_report(url_obj.url)
        # Parse: {malicious: int, suspicious: int}
        url_obj.vt_malicious = result.get("malicious", 0)
        url_obj.vt_suspicious = result.get("suspicious", 0)
        url_obj.vt_score = url_obj.vt_malicious * 10 + url_obj.vt_suspicious * 5
        url_obj.is_phishing = url_obj.vt_malicious > 0
        db.add(Event(...))
        await asyncio.sleep(1)  # Rate limit
    
    # 2. AbuseIPDB IP Scanning
    for ip_obj in email.ips[:10]:
        result = await abuse_service.check_ip(ip_obj.ip_address)
        # Parse: {abuse_score: int, country: str, isp: str, reports: int}
        ip_obj.abuse_score = result.get("abuse_score", 0)
        ip_obj.is_malicious = ip_obj.abuse_score > 50
        ip_obj.country = result.get("country")
        ip_obj.isp = result.get("isp")
        ip_obj.reports_count = result.get("reports", 0)
        db.add(Event(...))
        await asyncio.sleep(1)
    
    # 3. VirusTotal File Scanning
    for att_obj in email.attachments[:10]:
        result = await vt_service.get_file_report(att_obj.sha256)
        att_obj.vt_malicious = result.get("malicious", 0)
        att_obj.vt_suspicious = result.get("suspicious", 0)
        att_obj.vt_score = att_obj.vt_malicious * 10 + att_obj.vt_suspicious * 5
        db.add(Event(...))
        await asyncio.sleep(1)
    
    # 4. Mesa Security Email Scanning
    result = await mesa_service.scan_email(email_bytes, filename=f"email_{email.id}.eml")
    email.mesa_job_id = result.get("job_id")
    email.mesa_status = result.get("status")
    email.mesa_details = result.get("result", {})
    email.mesa_verdict = result.get("result", {}).get("verdict")
    email.mesa_score = result.get("result", {}).get("threat_score")
    email.mesa_scanned_at = datetime.utcnow()
    
    # 5. Recalculate Final Score
    recalculate_threat_score(email, db)
    
    # 6. Log completion
    db.add(Event(
        email_id=email.id,
        event_type="ENRICHMENT_COMPLETE",
        description=f"Enrichment complete. Final score: {email.threat_score}/100",
        severity="INFO"
    ))
    db.commit()
```

---

## Database Schema

### **Entity Relationship Diagram**

```
┌─────────────────────────────────────────────────────────────┐
│                         EMAILS                              │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ sender           | VARCHAR(255) - "attacker@phishing.com"   │
│ sender_domain    | VARCHAR(255) - "phishing.com"            │
│ subject          | TEXT - Email subject line                │
│ body             | TEXT - Email body content (10k chars)    │
│ headers          | JSON - All SMTP headers                  │
│ spf_status       | VARCHAR(50) - PASS/FAIL/SOFTFAIL/NONE    │
│ dkim_status      | VARCHAR(50) - PASS/FAIL/NONE             │
│ dmarc_status     | VARCHAR(50) - PASS/FAIL/NONE             │
│ attachment_verdict│VARCHAR(50) - SAFE/SUSPICIOUS/MALICIOUS  │
│ mesa_job_id      | VARCHAR(255) - Mesa Security job ID      │
│ mesa_status      | VARCHAR(50) - pending/completed/failed   │
│ mesa_verdict     | VARCHAR(100) - phishing/malware/spam     │
│ mesa_score       | INTEGER (0-100) - Mesa threat score      │
│ mesa_details     | JSON - Full Mesa API response            │
│ mesa_scanned_at  | DATETIME - When Mesa scan completed      │
│ rule_score       | INTEGER (0-100) - Initial rule score     │
│ threat_score     | INTEGER (0-100) - Final combined score   │
│ verdict          | VARCHAR(50) - SAFE/SUSPICIOUS/MALICIOUS  │
│ confidence       | VARCHAR(20) - LOW/MEDIUM/HIGH            │
│ received_at      | DATETIME - When email was received       │
│ analyzed_at      | DATETIME - When analysis completed       │
└─────────────────────────────────────────────────────────────┘
        │
        ├─── 1:N ──→ URLs Table
        ├─── 1:N ──→ IPs Table
        ├─── 1:N ──→ Events Table
        ├─── 1:N ──→ Attachments Table
        ├─── 1:N ──→ IOCs Table
        └─── 1:N ──→ Reports Table

┌─────────────────────────────────────────────────────────────┐
│                         URLS                                │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ url              | TEXT - Full URL: "http://phishing.com"   │
│ domain           | VARCHAR(255) - Extracted domain          │
│ vt_malicious     | INTEGER - VT malicious detections        │
│ vt_suspicious    | INTEGER - VT suspicious detections       │
│ vt_score         | INTEGER (0-100) - Calculated score       │
│ is_phishing      | BOOLEAN - VirusTotal phishing flag       │
│ checked_at       | DATETIME - When VT was checked           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                         IPS                                 │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ ip_address       | VARCHAR(45) - IPv4 or IPv6               │
│ abuse_score      | INTEGER (0-100) - AbuseIPDB score        │
│ spamhaus_flagged | BOOLEAN - Spamhaus DNSBL result          │
│ is_malicious     | BOOLEAN - Overall malicious flag         │
│ country          | VARCHAR(100) - IP geolocation            │
│ isp              | VARCHAR(255) - ISP name                  │
│ reports_count    | INTEGER - Number of abuse reports        │
│ checked_at       | DATETIME - When AbuseIPDB was checked    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       EVENTS                                │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ event_type       | VARCHAR(50) - RECEIVED/PARSED/ENRICHED   │
│ description      | TEXT - Detailed event description        │
│ severity         | VARCHAR(20) - INFO/WARNING/ERROR         │
│ timestamp        | DATETIME - When event occurred           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    ATTACHMENTS                              │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ file_name        | VARCHAR(255) - "document.pdf"            │
│ sha256           | VARCHAR(64) - SHA-256 hash               │
│ vt_malicious     | INTEGER - VT malicious detections        │
│ vt_suspicious    | INTEGER - VT suspicious detections       │
│ vt_score         | INTEGER (0-100) - Calculated score       │
│ checked_at       | DATETIME - When VT was checked           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       IOCS                                  │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ ioc_type         | VARCHAR(20) - URL/IP/DOMAIN/HASH         │
│ value            | TEXT - Indicator value                   │
│ threat_score     | INTEGER - Associated threat score        │
│ detected_at      | DATETIME - When IOC was detected         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      REPORTS                                │
├─────────────────────────────────────────────────────────────┤
│ id (PK)          | INTEGER PRIMARY KEY                      │
│ email_id (FK)    | INTEGER → emails.id                      │
│ generated_at     | DATETIME - When report was generated     │
│ file_path        | TEXT - Path to saved PDF report          │
└─────────────────────────────────────────────────────────────┘
```

### **SQLAlchemy ORM Definitions**

```python
# app/models/database.py

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func

DATABASE_URL = "sqlite:///./email_threat_db.sqlite3"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Email(Base):
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(255))
    sender_domain = Column(String(255))
    subject = Column(Text)
    body = Column(Text)
    headers = Column(JSON)
    
    spf_status = Column(String(50), nullable=True)
    dkim_status = Column(String(50), nullable=True)
    dmarc_status = Column(String(50), nullable=True)
    attachment_verdict = Column(String(50), nullable=True)
    
    mesa_job_id = Column(String(255), nullable=True)
    mesa_status = Column(String(50), nullable=True)
    mesa_verdict = Column(String(100), nullable=True)
    mesa_score = Column(Integer, default=0)
    mesa_details = Column(JSON, nullable=True)
    mesa_scanned_at = Column(DateTime(timezone=True), nullable=True)
    
    rule_score = Column(Integer, default=0)
    threat_score = Column(Integer, default=0)
    verdict = Column(String(50))
    confidence = Column(String(20))
    
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    analyzed_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships (cascade deletes)
    urls = relationship("URL", back_populates="email", cascade="all, delete-orphan")
    ips = relationship("IP", back_populates="email", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="email", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="email", cascade="all, delete-orphan")

class URL(Base):
    __tablename__ = "urls"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    url = Column(Text)
    domain = Column(String(255))
    
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    is_phishing = Column(Boolean, default=False)
    
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    email = relationship("Email", back_populates="urls")

class IP(Base):
    __tablename__ = "ips"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    ip_address = Column(String(45))
    
    abuse_score = Column(Integer, default=0)
    spamhaus_flagged = Column(Boolean, default=False)
    is_malicious = Column(Boolean, default=False)
    country = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    reports_count = Column(Integer, default=0)
    
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    email = relationship("Email", back_populates="ips")

class Event(Base):
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    
    event_type = Column(String(50))
    description = Column(Text)
    severity = Column(String(20), default="INFO")
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    email = relationship("Email", back_populates="events")

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    
    ioc_type = Column(String(20))  # URL, IP, DOMAIN, HASH
    value = Column(Text)
    threat_score = Column(Integer, default=0)
    
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    
    email = relationship("Email", back_populates="iocs")

class Attachment(Base):
    __tablename__ = "attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    file_name = Column(String(255))
    sha256 = Column(String(64))
    
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    email = relationship("Email", back_populates="attachments")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    file_path = Column(Text, nullable=True)
    
    email = relationship("Email", back_populates="reports")

# Helper functions
def get_db():
    """FastAPI dependency for database sessions"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all tables on startup"""
    Base.metadata.create_all(bind=engine)
```

---

## Backend Structure

### **Directory Organization**

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                          # FastAPI application & endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   ├── parser.py                    # Email parsing logic
│   │   ├── rules.py                     # Rule-based detection engine
│   │   └── auth_checks.py               # SPF/DKIM/DMARC validation
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py                  # SQLAlchemy ORM models
│   └── services/
│       ├── __init__.py
│       ├── virustotal.py                # VirusTotal API client
│       ├── abuseipdb.py                 # AbuseIPDB API client
│       ├── mesa_security.py             # Mesa Security API client
│       └── report_generator.py          # PDF report generation
├── requirements.txt                     # Python dependencies
├── run.py                               # Application entry point
├── .env                                 # Environment variables
└── email_threat_db.sqlite3              # SQLite database file
```

### **Key Backend Files**

#### **1. app/main.py (FastAPI Application)**

Functions:
- `startup_event()`: Initialize database tables
- `shutdown_event()`: Close external service connections
- `health_check()`: System health & service status
- `upload_email()`: POST endpoint for file upload
- `analyze_email_text()`: POST endpoint for raw email text
- `get_email()`: GET email details by ID
- `get_email_timeline()`: GET forensic events for email
- `list_emails()`: GET paginated email history
- `get_recent_emails()`: GET last 10 emails
- `get_email_stats()`: GET dashboard statistics
- `enrich_email()`: POST synchronous enrichment
- `get_report()`: GET generated PDF report
- `enrich_email_background()`: Background async task
- `delete_email()`: DELETE email record
- `scan_email_with_mesa()`: POST Mesa Security scan
- `recalculate_threat_score()`: Dynamic scoring logic

#### **2. app/core/parser.py (Email Parser)**

Functions:
- `get_sender()`: Extract sender email address
- `get_subject()`: Extract email subject
- `get_body()`: Extract body (text or HTML conversion)
- `get_headers()`: Extract all SMTP headers
- `extract_urls()`: Regex extraction of URLs
- `extract_ips()`: Extract public IPs (sender prioritized)
- `extract_domains()`: Extract domains from URLs
- `extract_attachments()`: Extract files with SHA-256 hashes
- `get_raw_bytes()`: Convert email to bytes for DKIM

#### **3. app/core/rules.py (Detection Engine)**

Methods:
- `analyze()`: Main analysis function (calls all rules)
- `_check_keywords()`: Spam keyword detection
- `_check_urgency()`: Urgency phrase detection
- `_check_links()`: Link count analysis
- `_check_exclamations()`: Exclamation mark analysis
- `_check_uppercase()`: Uppercase letter analysis
- `_check_sender_spoofing()`: Brand impersonation detection
- `_check_suspicious_domains()`: Suspicious TLD detection
- `_check_missing_headers()`: Auth header validation
- `_check_link_shorteners()`: Link shortener detection
- `_check_ip_links()`: IP-based link detection
- `_check_idn_homograph()`: IDN homograph attack detection

#### **4. app/core/auth_checks.py (Authentication)**

Functions:
- `validate_spf()`: SPF DNS validation
- `validate_dkim()`: DKIM signature verification
- `validate_dmarc()`: DMARC alignment check
- `check_spamhaus()`: DNSBL blacklist lookup

#### **5. app/models/database.py (ORM Models)**

Classes:
- `Email`: Main email record
- `URL`: Extracted URLs
- `IP`: Extracted IP addresses
- `Event`: Forensic timeline events
- `Attachment`: Email attachments
- `IOC`: Indicators of compromise
- `Report`: Generated PDF reports

---

## Frontend Structure

### **React Component Architecture**

```
frontend/
├── src/
│   ├── main.jsx                     # React entry point (Vite)
│   ├── App.jsx                      # Main React component (1324 lines)
│   ├── api.js                       # API wrapper (15+ functions)
│   ├── index.css                    # Global styles (dark theme)
│   └── assets/                      # Static assets
├── index.html                       # HTML template
├── package.json                     # Dependencies
├── vite.config.js                   # Vite bundler config
└── eslint.config.js                 # ESLint rules
```

### **App.jsx Structure (Main React Component)**

**State Management (17 state variables):**

```javascript
// Navigation
const [activeTab, setActiveTab] = useState('dashboard');  // dashboard/analyze/history/details
const [selectedEmailId, setSelectedEmailId] = useState(null);

// Dashboard & global
const [stats, setStats] = useState({total_emails, verdicts, avg_score, iocs});
const [recentEmails, setRecentEmails] = useState([]);
const [backendHealthy, setBackendHealthy] = useState(null);

// History tab
const [historyEmails, setHistoryEmails] = useState([]);
const [historyTotal, setHistoryTotal] = useState(0);
const [historySkip, setHistorySkip] = useState(0);
const [historyFilter, setHistoryFilter] = useState('ALL');
const [historySearch, setHistorySearch] = useState('');

// Detail view
const [emailDetails, setEmailDetails] = useState(null);
const [activeDetailTab, setActiveDetailTab] = useState('iocs');
const [activeIocTab, setActiveIocTab] = useState('urls');
const [isEnriching, setIsEnriching] = useState(false);
const [showRawHeaders, setShowRawHeaders] = useState(false);

// Uploader
const [dragActive, setDragActive] = useState(false);
const [uploadFile, setUploadFile] = useState(null);
const [rawEmailText, setRawEmailText] = useState('');
const [isAnalyzing, setIsAnalyzing] = useState(false);

// Global
const [globalLoading, setGlobalLoading] = useState(false);
const [toast, setToast] = useState(null);
```

**Key Functions:**

```javascript
// UI Functions
showToast(message, type)                 // Display toast notification
checkHealthAndLoadStats()               // Get dashboard stats
loadRecentEmails()                      // Get last 10 emails
loadHistory(skip, verdict)              // Paginated email history
loadEmailDetails(id)                    // Get email details
handleDrag(e)                           // Drag & drop handler
handleDrop(e)                           // File drop handler
handleFileSelect(e)                     // File input handler
handleFileUploadSubmit(e)               // Upload .eml file
handleTextAnalyzeSubmit(e)              // Analyze raw text
handleEnrich()                          // Force VT/AbuseIPDB/Mesa
handleDeleteEmail(id, returnToDashboard) // Delete email record

// Helper Functions
getVerdictStyles(verdict)               // Color scheme for verdict
extractRuleTriggers()                   // Parse rule details from timeline
formatDate(isoString)                   // Format ISO date string

// Render Functions (4 tabs)
render_dashboard()                      // Statistics & recent history
render_analyze()                        // Upload & text paste forms
render_history()                        // Email log with filtering
render_details()                        // Forensic investigation report
```

**Tab 1: Dashboard**

```javascript
const Dashboard = () => {
  return (
    <div>
      {/* Statistics Cards (4 columns) */}
      <div className="dashboard-grid">
        <StatCard title="Scanned Emails" value={stats.total_emails} icon={<Mail />} />
        <StatCard title="Avg Threat Score" value={stats.avg_score + '%'} icon={<ShieldAlert />} />
        <StatCard title="Malicious Detected" value={stats.verdicts.MALICIOUS} icon={<ShieldAlert />} />
        <StatCard title="Verified Safe" value={stats.verdicts.SAFE} icon={<ShieldCheck />} />
      </div>
      
      {/* Two-column layout */}
      <div className="dashboard-rows">
        {/* Left: Recent Analysis History */}
        <div className="card-panel">
          <h3>Recent Analysis History</h3>
          <table className="scans-table">
            <thead>
              <tr>
                <th>Sender</th>
                <th>Subject</th>
                <th>Score</th>
                <th>Verdict</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentEmails.map(email => (
                <tr key={email.id}>
                  <td>{email.sender}</td>
                  <td>{email.subject}</td>
                  <td><span className="threat-score-badge">{email.threat_score}%</span></td>
                  <td><span className="verdict-badge">{email.verdict}</span></td>
                  <td>
                    <button onClick={() => loadEmailDetails(email.id)}>Details</button>
                    <button onClick={() => handleDeleteEmail(email.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {/* Right: Verdict Breakdown & IOC Stats */}
        <div className="card-panel">
          <h3>Verdict & IOC Breakdown</h3>
          
          {/* Progress bars for verdicts */}
          <div className="verdict-breakdown-list">
            <VerdictBar label="Malicious" count={stats.verdicts.MALICIOUS} total={stats.total_emails} />
            <VerdictBar label="Suspicious" count={stats.verdicts.SUSPICIOUS} total={stats.total_emails} />
            <VerdictBar label="Safe" count={stats.verdicts.SAFE} total={stats.total_emails} />
          </div>
          
          {/* IOC Stats Grid (2x2) */}
          <div className="ioc-stats-grid">
            <StatBox label="URLs Analyzed" value={stats.iocs.total_urls} />
            <StatBox label="IPs Checked" value={stats.iocs.total_ips} />
            <StatBox label="File Hashes" value={stats.iocs.total_attachments} />
            <StatBox label="Forensic Events" value={stats.iocs.total_events} />
          </div>
        </div>
      </div>
    </div>
  );
}
```

**Tab 2: Analyze Email**

```javascript
const AnalyzeEmail = () => {
  return (
    <div className="upload-container">
      {/* Left Panel: File Upload */}
      <div className="card-panel">
        <h3>Upload Email File (.eml / .txt)</h3>
        <form onSubmit={handleFileUploadSubmit}>
          <div 
            className={`upload-drag-area ${dragActive ? 'dragging' : ''}`}
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
          >
            <Upload size={48} />
            {uploadFile ? (
              <div>
                <p>{uploadFile.name}</p>
                <p>{(uploadFile.size / 1024).toFixed(2)} KB</p>
              </div>
            ) : (
              <p>Drag & drop .eml or .txt file here, or click to browse</p>
            )}
          </div>
          <button type="submit" disabled={!uploadFile || isAnalyzing}>
            {isAnalyzing ? 'Analyzing...' : 'Run Forensic Scan'}
          </button>
        </form>
      </div>
      
      {/* Right Panel: Paste Raw Text */}
      <div className="card-panel">
        <h3>Paste Raw Email Content</h3>
        <form onSubmit={handleTextAnalyzeSubmit}>
          <textarea
            placeholder="Paste raw email content..."
            value={rawEmailText}
            onChange={(e) => setRawEmailText(e.target.value)}
          />
          <button type="submit" disabled={!rawEmailText.trim() || isAnalyzing}>
            {isAnalyzing ? 'Analyzing...' : 'Scan Email Text'}
          </button>
        </form>
      </div>
    </div>
  );
}
```

**Tab 3: Forensic Logs**

```javascript
const ForensicLogs = () => {
  const filteredEmails = historyEmails.filter(email => {
    if (!historySearch) return true;
    return (
      email.sender.toLowerCase().includes(historySearch.toLowerCase()) ||
      email.subject.toLowerCase().includes(historySearch.toLowerCase())
    );
  });
  
  return (
    <div className="card-panel">
      <div className="panel-header">
        <h3>Forensic Log Database</h3>
        <div>
          <input 
            type="text" 
            placeholder="Search sender/subject..."
            value={historySearch}
            onChange={(e) => setHistorySearch(e.target.value)}
          />
          <button onClick={() => loadHistory(historySkip, historyFilter)}>
            Refresh
          </button>
        </div>
      </div>
      
      {/* Verdict Filter Buttons */}
      <div className="history-filters">
        {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map(v => (
          <button
            key={v}
            className={`filter-btn ${historyFilter === v ? 'active' : ''}`}
            onClick={() => {
              setHistoryFilter(v);
              loadHistory(0, v);
            }}
          >
            {v}
          </button>
        ))}
      </div>
      
      {/* Email Table */}
      <table className="emails-table">
        <thead>
          <tr>
            <th>From</th>
            <th>Subject</th>
            <th>Score</th>
            <th>Verdict</th>
            <th>Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredEmails.map(email => (
            <tr key={email.id}>
              <td>{email.sender}</td>
              <td>{email.subject}</td>
              <td>{email.threat_score}%</td>
              <td><span className={`badge ${email.verdict.toLowerCase()}`}>{email.verdict}</span></td>
              <td>{formatDate(email.received_at)}</td>
              <td>
                <button onClick={() => loadEmailDetails(email.id)}>View</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      
      {/* Pagination */}
      <div className="pagination">
        <button onClick={() => loadHistory(historySkip - 50, historyFilter)} disabled={historySkip === 0}>
          Previous
        </button>
        <span>{historySkip + 1} - {Math.min(historySkip + 50, historyTotal)} of {historyTotal}</span>
        <button onClick={() => loadHistory(historySkip + 50, historyFilter)} disabled={historySkip + 50 >= historyTotal}>
          Next
        </button>
      </div>
    </div>
  );
}
```

**Tab 4: Forensic Report**

```javascript
const ForensicReport = () => {
  if (!emailDetails) return <div>Select an email first</div>;
  
  const verdictInfo = getVerdictStyles(emailDetails.verdict);
  
  return (
    <div>
      {/* Header with verdict badge */}
      <div className="report-header">
        <h2>Forensic Analysis Report</h2>
        <span className={`verdict-badge ${verdictInfo.badgeClass}`}>
          {verdictInfo.icon} {emailDetails.verdict}
        </span>
        <span className="threat-score-large">{emailDetails.threat_score}%</span>
      </div>
      
      {/* Email Metadata */}
      <div className="card-panel">
        <h3>Email Metadata</h3>
        <div className="metadata-grid">
          <MetadataRow label="From" value={emailDetails.sender} />
          <MetadataRow label="Subject" value={emailDetails.subject} />
          <MetadataRow label="Received" value={formatDate(emailDetails.received_at)} />
          <MetadataRow label="Analyzed" value={formatDate(emailDetails.analyzed_at)} />
        </div>
      </div>
      
      {/* Authentication Status */}
      <div className="card-panel">
        <h3>Email Authentication Status</h3>
        <div className="auth-grid">
          <AuthStatus label="SPF" status={emailDetails.spf_status} />
          <AuthStatus label="DKIM" status={emailDetails.dkim_status} />
          <AuthStatus label="DMARC" status={emailDetails.dmarc_status} />
          <AuthStatus label="Attachment" status={emailDetails.attachment_verdict} />
        </div>
      </div>
      
      {/* IOCs Tab Switcher */}
      <div className="card-panel">
        <div className="tab-switcher">
          <button className={activeDetailTab === 'iocs' ? 'active' : ''} onClick={() => setActiveDetailTab('iocs')}>
            Indicators of Compromise
          </button>
          <button className={activeDetailTab === 'timeline' ? 'active' : ''} onClick={() => setActiveDetailTab('timeline')}>
            Forensic Timeline
          </button>
          <button className={activeDetailTab === 'headers' ? 'active' : ''} onClick={() => setActiveDetailTab('headers')}>
            Headers
          </button>
        </div>
        
        {activeDetailTab === 'iocs' && (
          <div>
            {/* Sub-tab for IOC Types */}
            <div className="ioc-sub-tabs">
              {['urls', 'ips', 'domains', 'attachments'].map(type => (
                <button
                  key={type}
                  className={activeIocTab === type ? 'active' : ''}
                  onClick={() => setActiveIocTab(type)}
                >
                  {type.toUpperCase()} ({emailDetails.iocs[type]?.length || 0})
                </button>
              ))}
            </div>
            
            {/* IOC Details */}
            {activeIocTab === 'urls' && (
              <div className="ioc-list">
                {emailDetails.iocs.urls?.map((url, i) => (
                  <div key={i} className="ioc-item">
                    <span className="ioc-value">{url.url}</span>
                    <span className={`vt-score ${url.is_phishing ? 'malicious' : ''}`}>
                      VT: {url.vt_score}%
                    </span>
                  </div>
                ))}
              </div>
            )}
            
            {activeIocTab === 'ips' && (
              <div className="ioc-list">
                {emailDetails.iocs.ips?.map((ip, i) => (
                  <div key={i} className="ioc-item">
                    <span className="ioc-value">{ip.ip}</span>
                    <span className={`abuse-score ${ip.is_malicious ? 'malicious' : ''}`}>
                      AbuseIPDB: {ip.abuse_score}%
                    </span>
                    <span className="isp">{ip.country} - {ip.isp}</span>
                  </div>
                ))}
              </div>
            )}
            
            {/* Similar for domains and attachments */}
          </div>
        )}
        
        {activeDetailTab === 'timeline' && (
          <div className="timeline">
            {emailDetails.timeline?.map((event, i) => (
              <div key={i} className={`timeline-event ${event.severity.toLowerCase()}`}>
                <span className="timestamp">{formatDate(event.timestamp)}</span>
                <span className="event-type">{event.event_type}</span>
                <span className="description">{event.description}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Action Buttons */}
      <div className="action-buttons">
        <button onClick={handleEnrich} disabled={isEnriching}>
          {isEnriching ? 'Enriching...' : 'Enrich with VT/AbuseIPDB/Mesa'}
        </button>
        <button onClick={() => window.open(`/report/${emailDetails.id}`, '_blank')}>
          Download PDF Report
        </button>
        <button onClick={() => handleDeleteEmail(emailDetails.id, true)} className="danger">
          Delete This Email
        </button>
      </div>
    </div>
  );
}
```

### **api.js (API Wrapper)**

```javascript
// src/api.js

const API_BASE_URL = 'http://localhost:8000';

async function handleResponse(response) {
  if (!response.ok) {
    let errorMsg = `API request failed: ${response.status}`;
    try {
      const data = await response.json();
      errorMsg = data.error?.message || data.detail || errorMsg;
    } catch {
      // Ignore JSON parse error
    }
    throw new Error(errorMsg);
  }
  return response.json();
}

export const api = {
  // Dashboard
  getDashboardStats: async () => {
    const res = await fetch(`${API_BASE_URL}/dashboard/stats`);
    return handleResponse(res);
  },

  // Email History
  getEmails: async (skip = 0, limit = 50, verdict = null) => {
    let url = `${API_BASE_URL}/emails?skip=${skip}&limit=${limit}`;
    if (verdict && verdict !== 'ALL') {
      url += `&verdict=${verdict.toUpperCase()}`;
    }
    const res = await fetch(url);
    return handleResponse(res);
  },

  getRecentEmails: async () => {
    const res = await fetch(`${API_BASE_URL}/emails/recent`);
    return handleResponse(res);
  },

  // Email Analysis
  uploadEmailFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE_URL}/upload-email`, {
      method: 'POST',
      body: formData
    });
    return handleResponse(res);
  },

  analyzeEmailText: async (rawEmail) => {
    const res = await fetch(`${API_BASE_URL}/analyze-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: rawEmail })
    });
    return handleResponse(res);
  },

  // Email Details
  getEmailDetails: async (emailId) => {
    const res = await fetch(`${API_BASE_URL}/email/${emailId}`);
    return handleResponse(res);
  },

  getEmailTimeline: async (emailId) => {
    const res = await fetch(`${API_BASE_URL}/timeline/${emailId}`);
    return handleResponse(res);
  },

  // Enrichment
  enrichEmail: async (emailId) => {
    const res = await fetch(`${API_BASE_URL}/email/${emailId}/enrich`, {
      method: 'POST'
    });
    return handleResponse(res);
  },

  // Reports
  getReportUrl: (emailId) => {
    return `${API_BASE_URL}/report/${emailId}`;
  },

  // Deletion
  deleteEmail: async (emailId) => {
    const res = await fetch(`${API_BASE_URL}/email/${emailId}`, {
      method: 'DELETE'
    });
    return handleResponse(res);
  },

  // Mesa Security
  scanEmailWithMesa: async (emailId) => {
    const res = await fetch(`${API_BASE_URL}/email/${emailId}/mesa-scan`, {
      method: 'POST'
    });
    return handleResponse(res);
  }
};
```

---

## API Reference

### **Base URL**
```
http://localhost:8000
```

### **Authentication Endpoints**

#### **GET /health**
Health check with service configuration status.

```bash
curl -X GET http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "database": "connected",
  "services": {
    "virustotal": "configured",
    "abuseipdb": "configured",
    "mesa_security": "configured"
  },
  "timestamp": "2026-06-21T16:42:30.859253"
}
```

### **Email Analysis Endpoints**

#### **POST /upload-email**
Upload and analyze an .eml or .txt email file.

```bash
curl -X POST http://localhost:8000/upload-email \
  -F "file=@email.eml"
```

Request: multipart/form-data (file: .eml or .txt)

Response:
```json
{
  "id": 1,
  "verdict": "MALICIOUS",
  "threat_score": 85,
  "confidence": "HIGH",
  "details": [
    "⚠️ SPAM keyword in subject: claim now",
    "🚨 URGENCY in body: immediately",
    "🔗 Multiple links present (3)",
    "🔓 BRAND SPOOFING: 'paypal' in free email"
  ],
  "authentication": {
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "FAIL"
  },
  "iocs": {
    "urls": ["http://phishing.com/login"],
    "ips": ["192.168.1.1"],
    "domains": ["phishing.com"],
    "attachments": ["invoice.pdf"]
  },
  "stats": {
    "total_urls": 5,
    "total_ips": 2,
    "total_domains": 3,
    "total_attachments": 1
  },
  "filename": "email.eml",
  "analyzed_at": "2026-06-21T16:34:00.123456"
}
```

#### **POST /analyze-email**
Analyze raw email text content.

```bash
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "From: user@example.com\nSubject: ...\n\nBody..."
  }'
```

Request:
```json
{
  "email_text": "raw email content as string"
}
```

Response: Same as /upload-email

### **Email Query Endpoints**

#### **GET /email/{email_id}**
Get complete details for a specific email.

```bash
curl -X GET http://localhost:8000/email/1
```

Response:
```json
{
  "id": 1,
  "sender": "attacker@phishing.com",
  "sender_domain": "phishing.com",
  "subject": "URGENT: Verify Your Account!",
  "body": "Click here to verify...",
  "verdict": "MALICIOUS",
  "threat_score": 85,
  "rule_score": 65,
  "confidence": "HIGH",
  "spf_status": "FAIL",
  "dkim_status": "FAIL",
  "dmarc_status": "FAIL",
  "attachment_verdict": "SAFE",
  "received_at": "2026-06-21T16:34:00",
  "analyzed_at": "2026-06-21T16:34:05",
  "headers_count": 15,
  "iocs": {
    "urls": [
      {
        "id": 1,
        "url": "http://phishing.com/login",
        "domain": "phishing.com",
        "vt_score": 45,
        "is_phishing": true
      }
    ],
    "ips": [
      {
        "id": 1,
        "ip": "192.168.1.1",
        "abuse_score": 75,
        "spamhaus_flagged": true,
        "is_malicious": true,
        "country": "US",
        "isp": "Unknown ISP"
      }
    ],
    "attachments": [
      {
        "id": 1,
        "file_name": "invoice.pdf",
        "sha256": "abc123...",
        "vt_score": 0,
        "checked_at": "2026-06-21T16:35:00"
      }
    ]
  },
  "timeline": [
    {
      "timestamp": "2026-06-21T16:34:00",
      "event_type": "RECEIVED",
      "description": "Email received for forensic analysis",
      "severity": "INFO"
    },
    ...
  ]
}
```

#### **GET /timeline/{email_id}**
Get forensic timeline events for an email.

```bash
curl -X GET http://localhost:8000/timeline/1
```

Response:
```json
{
  "email_id": 1,
  "total_events": 10,
  "events": [
    {
      "timestamp": "2026-06-21T16:34:00",
      "event_type": "RECEIVED",
      "description": "Email received for forensic analysis",
      "severity": "INFO"
    },
    {
      "timestamp": "2026-06-21T16:34:01",
      "event_type": "PARSED",
      "description": "Extracted 3 URLs, 1 IP, 1 domain, 1 attachment",
      "severity": "INFO"
    },
    ...
  ]
}
```

### **List & Search Endpoints**

#### **GET /emails**
Paginated email history with verdict filtering.

```bash
curl -X GET "http://localhost:8000/emails?skip=0&limit=50&verdict=MALICIOUS"
```

Parameters:
- `skip`: Pagination offset (default: 0)
- `limit`: Results per page (default: 50)
- `verdict`: Filter by verdict - ALL, MALICIOUS, SUSPICIOUS, SAFE (optional)

Response:
```json
{
  "total": 42,
  "skip": 0,
  "limit": 50,
  "emails": [
    {
      "id": 1,
      "sender": "attacker@phishing.com",
      "subject": "URGENT: Verify Your Account!",
      "verdict": "MALICIOUS",
      "threat_score": 85,
      "confidence": "HIGH",
      "received_at": "2026-06-21T16:34:00",
      "analyzed_at": "2026-06-21T16:34:05"
    },
    ...
  ]
}
```

#### **GET /emails/recent**
Get 10 most recent analyzed emails.

```bash
curl -X GET http://localhost:8000/emails/recent
```

Response:
```json
{
  "count": 10,
  "emails": [
    {
      "id": 11,
      "sender": "test@example.com",
      "subject": "Critical update",
      "verdict": "MALICIOUS",
      "threat_score": 83,
      "confidence": "HIGH",
      "received_at": "2026-06-21T16:34:59",
      "has_iocs": true
    },
    ...
  ]
}
```

#### **GET /dashboard/stats**
Get dashboard statistics.

```bash
curl -X GET http://localhost:8000/dashboard/stats
```

Response:
```json
{
  "total_emails": 11,
  "verdicts": {
    "MALICIOUS": 1,
    "SAFE": 4,
    "SUSPICIOUS": 6
  },
  "avg_score": 49.82,
  "iocs": {
    "total_urls": 6,
    "total_ips": 12,
    "total_attachments": 3,
    "total_events": 147
  }
}
```

### **Enrichment Endpoints**

#### **POST /email/{email_id}/enrich**
Force synchronous enrichment with VirusTotal, AbuseIPDB, and Mesa Security.

```bash
curl -X POST http://localhost:8000/email/1/enrich
```

Response:
```json
{
  "id": 1,
  "verdict": "MALICIOUS",
  "threat_score": 92,
  "confidence": "HIGH",
  "previous_score": 65,
  "vt_configured": true,
  "abuse_configured": true,
  "new_events": 8
}
```

### **Report Endpoints**

#### **GET /report/{email_id}**
Generate and download PDF forensic analysis report.

```bash
curl -X GET http://localhost:8000/report/1 \
  -o email_threat_report_1.pdf
```

Response: PDF file (binary)

Headers:
```
Content-Type: application/pdf
Content-Disposition: attachment; filename=email_threat_report_1.pdf
```

### **Deletion Endpoints**

#### **DELETE /email/{email_id}**
Delete an email and all associated data.

```bash
curl -X DELETE http://localhost:8000/email/1
```

Response:
```json
{
  "message": "Email 1 deleted successfully",
  "id": 1
}
```

### **Mesa Security Endpoints**

#### **POST /email/{email_id}/mesa-scan**
Manually trigger a Mesa Security scan for an email.

```bash
curl -X POST http://localhost:8000/email/1/mesa-scan
```

Response:
```json
{
  "id": 1,
  "verdict": "MALICIOUS",
  "threat_score": 92,
  "confidence": "HIGH",
  "mesa_job_id": "job_abc123",
  "mesa_status": "completed",
  "mesa_verdict": "phishing",
  "mesa_score": 89,
  "new_events": 3
}
```

#### **GET /email/{email_id}/mesa-results**
Retrieve stored Mesa Security scan results.

```bash
curl -X GET http://localhost:8000/email/1/mesa-results
```

Response:
```json
{
  "mesa_job_id": "job_abc123",
  "mesa_status": "completed",
  "mesa_verdict": "phishing",
  "mesa_score": 89,
  "mesa_details": {
    "flags": ["phishing_domain", "credential_harvesting"],
    "risk_level": "critical"
  },
  "scanned_at": "2026-06-21T16:35:00"
}
```

---

## Detection Rules Engine

### **Scoring System (Direct Points)**

| Rule | Detection | Min Points | Max Points | Trigger |
|------|-----------|-----------|-----------|---------|
| Keywords | Spam keyword detected | 15 | 23 | Even 1 keyword in subject/body |
| Urgency | Urgency phrase detected | 12 | 19 | "act now", "immediately", "expires" |
| Links | Link count analysis | 5 | 20 | 1 link = 5pts, 5+ = 20pts |
| Exclamation | Excessive ! marks | 6 | 12 | Any in subject = 6, >3 in body = 12 |
| Uppercase | Excessive CAPS | 5 | 15 | Subject >50% = 10, ANY ALL-CAPS = 5 |
| Spoofing | Brand impersonation | 0 | 25 | "paypal" in Gmail local part = 25 |
| Suspicious TLD | .tk, .ml, .ga, etc | 0 | 25 | Any suspicious TLD = 20+ |
| Missing Headers | Missing SPF/DKIM/DMARC | 0 | 15 | No auth headers = 15 |
| Link Shorteners | bit.ly, tinyurl, goo.gl | 0 | 21 | Any shortener = 18+ |
| IP Links | Raw IP URLs | 0 | 22 | http://192.168.1.1 = 22 |
| IDN Homograph | xn-- or non-ASCII | 0 | 20 | xn-- prefix or non-ASCII = 20 |

### **Verdict Determination (No Multiplier)**

**Direct Scoring (Sum of all rule points, capped at 100):**

```
IF score >= 40: MALICIOUS (HIGH confidence)
IF score >= 20: SUSPICIOUS (MEDIUM confidence)
IF score < 20:  SAFE (LOW confidence)
```

### **Example Scoring Scenarios**

**Scenario 1: Phishing Email**
```
Subject: "URGENT: Verify Your PayPal Account NOW!"
Body: "Click here immediately to confirm your card details"

Keywords (subject): "verify account" + "paypal" = 15 points
Urgency (subject): "URGENT" = 12 points
Exclamation (subject): 1 = 6 points
Uppercase (subject): "URGENT" = 5 points
Spoofing: "paypal" in body but not verified = 0 points
Link: 1 phishing link detected = 5 points
Shortener: bit.ly link = 18 points

TOTAL: 15 + 12 + 6 + 5 + 5 + 18 = 61 points → MALICIOUS ✅
```

**Scenario 2: Legitimate Email**
```
Subject: "Meeting notes from yesterday"
Body: "Hi John, here are the notes..."

Keywords: None = 0 points
Urgency: None = 0 points
Exclamation: None = 0 points
Links: 1 company.com link = 5 points
Auth headers: SPF PASS, DKIM PASS, DMARC PASS = 0 points

TOTAL: 5 points → SAFE ✅
```

---

## External Integrations

### **VirusTotal Integration**

**Service Class: `VirusTotalService`** (app/services/virustotal.py)

**Methods:**

```python
async def get_url_report(url: str) -> Dict:
    """
    Submit URL to VirusTotal API v3
    Returns: {malicious: int, suspicious: int, score: 0-100}
    """

async def get_file_report(file_hash: str) -> Dict:
    """
    Query VirusTotal for file hash reputation
    Returns: {malicious: int, suspicious: int, score: 0-100}
    """

async def close():
    """Close HTTP session"""
```

**API Endpoint:** `https://www.virustotal.com/api/v3/urls`

**Rate Limit:** Typically 4 requests/minute (free tier), 60 requests/minute (premium)

**Configuration:**
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

### **AbuseIPDB Integration**

**Service Class: `AbuseIPDBService`** (app/services/abuseipdb.py)

**Methods:**

```python
async def check_ip(ip_address: str) -> Dict:
    """
    Query AbuseIPDB for IP reputation
    Returns: {abuse_score: 0-100, country: str, isp: str, reports: int}
    """

async def close():
    """Close HTTP session"""
```

**API Endpoint:** `https://api.abuseipdb.com/api/v2/check`

**Rate Limit:** 1000 requests/month (free tier), unlimited (premium)

**Configuration:**
```
ABUSEIPDB_API_KEY=your_api_key_here
```

### **Mesa Security Integration**

**Service Class: `MesaSecurityService`** (app/services/mesa_security.py)

**Methods:**

```python
async def scan_email(
    email_bytes: bytes,
    filename: str,
    save_screenshot: bool = False,
    save_email: bool = False
) -> Dict:
    """
    Submit email to Mesa Security for full content analysis
    Returns: {job_id: str, status: str, result: Dict}
    """

async def _poll_job_status(
    job_id: str,
    max_retries: int = 30
) -> Dict:
    """
    Poll job status until completion (max 30 retries × 2 sec = 60 sec)
    """

async def get_job_status(job_id: str) -> Dict:
    """Get current status without polling"""

async def close():
    """Close HTTP session"""
```

**API Endpoint:** `https://scan.mesasecurity.com/api/v1/email/scan`

**Rate Limit:** 50 requests/day

**Configuration:**
```
MESA_SECURITY_API_KEY=your_api_key_here
```

**Response Format:**
```json
{
  "job_id": "job_abc123",
  "status": "completed",
  "result": {
    "verdict": "phishing",
    "threat_score": 89,
    "flags": ["phishing_domain", "credential_harvesting"],
    "risk_level": "critical"
  }
}
```

---

## Threat Scoring Algorithm

### **Dynamic Score Calculation**

```python
def recalculate_threat_score(email: Email, db: Session):
    """
    Final threat score combines multiple factors:
    """
    
    score = email.rule_score  # Start with base rules (0-100)
    
    # 1. EMAIL AUTHENTICATION (Max +20)
    if email.spf_status == "FAIL":
        score += 10
    if email.dkim_status == "FAIL":
        score += 10
    if email.dmarc_status == "FAIL":
        score += 10
    score = min(score, score + 20)  # Cap this section
    
    # 2. IP REPUTATION (Max +20)
    for ip in email.ips:
        if ip.abuse_score > 50 or ip.spamhaus_flagged:
            score += 20
            break
    
    # 3. ATTACHMENT REPUTATION (Max +20)
    for att in email.attachments:
        if att.vt_malicious > 0:
            score += 20
            break
    
    # 4. URL PHISHING REPUTATION (Max +15)
    for url in email.urls:
        if url.is_phishing or url.vt_malicious > 0:
            score += 15
            break
    
    # 5. MESA SECURITY (Max +25)
    if email.mesa_status == "completed":
        if email.mesa_verdict.lower() in ["phishing", "malware"]:
            score += 25
        elif email.mesa_verdict.lower() == "spam":
            score += 15
        elif email.mesa_score > 0:
            score += min(25, email.mesa_score // 4)
    
    # Cap at 100
    email.threat_score = min(100, score)
    
    # Final Verdict
    if email.threat_score >= 70:
        email.verdict = "MALICIOUS"
        email.confidence = "HIGH"
    elif email.threat_score >= 40:
        email.verdict = "SUSPICIOUS"
        email.confidence = "MEDIUM"
    else:
        email.verdict = "SAFE"
        email.confidence = "LOW"
```

### **Score Composition Example**

```
Email Analysis Breakdown:
├── Rule Score: 65/100
│   ├── Keywords: 15
│   ├── Urgency: 12
│   ├── Links: 20
│   ├── Spoofing: 18
│   └── Other: 0
├── Auth Failures: +10 (SPF FAIL)
├── IP Reputation: +20 (Abuse > 50%)
├── Attachment Threat: +0 (Clean)
├── URL Threats: +15 (Phishing detected)
└── Mesa Security: +12 (Suspicious)

TOTAL: 65 + 10 + 20 + 0 + 15 + 12 = 122 → Capped at 100
FINAL VERDICT: MALICIOUS (Score 100, HIGH confidence)
```

---

## Configuration

### **.env File**

```
# Database
DATABASE_URL=sqlite:///./email_threat_db.sqlite3

# External Services
VIRUSTOTAL_API_KEY=your_vt_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
MESA_SECURITY_API_KEY=your_mesa_api_key

# Application
SECRET_KEY=your_secret_key
DEBUG=False
```

### **requirements.txt (Backend Dependencies)**

```
fastapi==0.104.1
uvicorn==0.24.0
sqlalchemy==2.0.23
pydantic==2.5.0
python-dotenv==1.0.0
email-validator==2.1.0
dnspython==2.4.2
dkimpy==1.0.7
pyspf==2.0.12
httpx==0.25.2
beautifulsoup4==4.12.2
reportlab==4.0.7
aiofiles==23.2.1
```

### **package.json (Frontend Dependencies)**

```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lucide-react": "^0.263.1"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.0.0",
    "vite": "^5.4.21",
    "eslint": "^8.0.0",
    "eslint-plugin-react": "^7.32.0"
  }
}
```

---

## Deployment Notes

### **Running the Backend**

```bash
# Navigate to backend directory
cd backend

# Activate virtual environment
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
export MESA_SECURITY_API_KEY=your_key

# Run server
python run.py
# or
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### **Running the Frontend**

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

### **Access Points**

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/api/docs (Swagger UI)
- **ReDoc**: http://localhost:8000/api/redoc

---

## Conclusion

The **Email Threat Intelligence Platform** is a comprehensive SOC-level email security solution featuring:

✅ **Advanced Email Parsing**: Extracts all metadata, URLs, IPs, domains, attachments  
✅ **Multi-Factor Detection**: 11 rule-based detection methods with strict thresholds  
✅ **Email Authentication**: SPF, DKIM, DMARC, Spamhaus validation  
✅ **Threat Intelligence**: VirusTotal URL/file reputation, AbuseIPDB IP scoring  
✅ **Advanced Analysis**: Mesa Security API for deep content analysis  
✅ **Forensic Auditing**: Complete event timeline with severity levels  
✅ **Interactive Dashboard**: React frontend with real-time statistics  
✅ **Reportable Results**: PDF forensic analysis reports  
✅ **Database Persistence**: SQLite with comprehensive schema  

**Final Verdict Thresholds:**
- **MALICIOUS**: ≥ 40 points (aggressive, SOC-ready)
- **SUSPICIOUS**: ≥ 20 points (even minor findings)
- **SAFE**: < 20 points

---

*Documentation generated 2026-06-21*
