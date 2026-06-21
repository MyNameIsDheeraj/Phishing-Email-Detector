# backend/app/main.py

import io
import os
import uuid
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, text, func
from dotenv import load_dotenv
from pydantic import BaseModel

# Import our modules
from app.models.database import get_db, Email, URL, IP, Event, IOC, Attachment, Report, init_db
from app.core.parser import EmailParser
from app.core.rules import RuleBasedDetector
from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.mesa_security import MesaSecurityService
from app.services.report_generator import generate_pdf_report
from app.core.auth_checks import validate_spf, validate_dkim, validate_dmarc, check_spamhaus

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="Email Threat Intelligence Platform",
    description="SOC-level email phishing detection and threat analysis system",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services and components
detector = RuleBasedDetector()
vt_service = VirusTotalService()
abuse_service = AbuseIPDBService()
mesa_service = MesaSecurityService()

# Database initialization on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database tables on startup"""
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {str(e)}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup connections on shutdown"""
    try:
        await vt_service.close()
        await abuse_service.close()
        await mesa_service.close()
        print("✅ Services closed successfully")
    except Exception as e:
        print(f"❌ Error closing services: {str(e)}")


# ===================== THREAT SCORING ENGINE =====================

def recalculate_threat_score(email: Email, db: Session):
    """
    Recalculates email threat score dynamically based on rule engine results,
    SPF/DKIM/DMARC status, Spamhaus status, URL analysis, Attachment reputations,
    and Mesa Security scan results.
    """
    # 1. Base rule score
    score = email.rule_score
    
    # 2. Email Authentication Failures (Max penalty: 20)
    auth_penalty = 0
    if email.spf_status == "FAIL":
        auth_penalty += 10
    if email.dkim_status == "FAIL":
        auth_penalty += 10
    if email.dmarc_status == "FAIL":
        auth_penalty += 10
    score += min(20, auth_penalty)
    
    # 3. IP Reputation & Blacklist Status (Penalty: 20)
    has_ip_threat = False
    for ip in email.ips:
        if ip.spamhaus_flagged or ip.is_malicious or (ip.abuse_score and ip.abuse_score > 50):
            has_ip_threat = True
            break
    if has_ip_threat:
        score += 20
        
    # 4. Attachment Reputation (Penalty: 20)
    has_attachment_threat = False
    for att in email.attachments:
        if att.vt_malicious > 0:
            has_attachment_threat = True
            break
            
    if has_attachment_threat:
        email.attachment_verdict = "MALICIOUS"
        score += 20
    elif len(email.attachments) > 0:
        # Check if all attachments verified
        unverified = [a for a in email.attachments if a.checked_at is None]
        if not unverified:
            email.attachment_verdict = "SAFE"
        else:
            email.attachment_verdict = "UNVERIFIED"
    else:
        email.attachment_verdict = "NONE"
        
    # 5. URL Phishing Reputation (Penalty: 15)
    has_url_threat = False
    for url in email.urls:
        if url.is_phishing or url.vt_malicious > 0:
            has_url_threat = True
            break
    if has_url_threat:
        score += 15
    
    # 6. Mesa Security Scan Results (Penalty: 25)
    if email.mesa_status == "completed" and email.mesa_verdict:
        mesa_verdict_lower = email.mesa_verdict.lower()
        
        # High threat verdicts
        if mesa_verdict_lower in ["phishing", "malware", "malicious"]:
            score += 25
        # Medium threat verdicts
        elif mesa_verdict_lower in ["spam", "suspicious", "warning"]:
            score += 15
        # Incorporate Mesa score if available
        elif email.mesa_score and email.mesa_score > 0:
            score += min(25, email.mesa_score // 4)  # Max 25 points
        
    # Alternative: Use Mesa score directly if verdict not available
    elif email.mesa_score and email.mesa_score > 50:
        score += min(25, email.mesa_score // 4)
        
    # Cap score at 100
    email.threat_score = min(100, score)
    
    # Update overall verdict & confidence
    if email.threat_score >= 60:
        email.verdict = "MALICIOUS"
        email.confidence = "HIGH"
    elif email.threat_score >= 25:
        email.verdict = "SUSPICIOUS"
        email.confidence = "MEDIUM"
    else:
        email.verdict = "SAFE"
        email.confidence = "LOW"


# ===================== HEALTH CHECK ENDPOINTS =====================

@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "Email Threat Intelligence Platform API",
        "status": "running",
        "version": "2.0.0",
        "docs": "/api/docs"
    }

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Detailed health check including database"""
    try:
        # Test database connection
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "database": db_status,
        "services": {
            "virustotal": "configured" if os.getenv("VIRUSTOTAL_API_KEY") else "not configured",
            "abuseipdb": "configured" if os.getenv("ABUSEIPDB_API_KEY") else "not configured",
            "mesa_security": "configured" if os.getenv("MESA_SECURITY_API_KEY") else "not configured"
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# ===================== EMAIL ANALYSIS ENDPOINTS =====================

@app.post("/upload-email")
async def upload_email(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """
    Upload and analyze an email file (.eml or .txt)
    """
    try:
        # Validate file type
        allowed_extensions = ['.eml', '.txt']
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Read email content
        content = await file.read()
        try:
            raw_email = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                raw_email = content.decode('latin-1')
            except:
                raise HTTPException(
                    status_code=400,
                    detail="Unable to decode email content. Please ensure it's a valid email file."
                )
        
        # Initialize parser
        parser = EmailParser(raw_email)
        raw_bytes = parser.get_raw_bytes()
        
        # Extract metadata
        sender = parser.get_sender()
        subject = parser.get_subject()
        body = parser.get_body()
        headers = parser.get_headers()
        urls = parser.extract_urls()
        ips = parser.extract_ips()
        domains = parser.extract_domains()
        attachments = parser.extract_attachments()
        
        if not body and not subject:
            raise HTTPException(
                status_code=400,
                detail="Unable to extract email content. The file may be corrupted."
            )
            
        # 1. Perform Authentication & DNSBL Checks
        sender_ip = ips[0] if ips else None
        
        # Run checks
        spf_status = validate_spf(sender_ip, sender)
        dkim_status = validate_dkim(raw_bytes, sender.split('@')[-1] if '@' in sender else None)
        dmarc_status = validate_dmarc(sender.split('@')[-1] if '@' in sender else "", spf_status, dkim_status)
        
        spamhaus_flagged = False
        if sender_ip:
            spamhaus_flagged = check_spamhaus(sender_ip)
            
        # 2. Rule-Based Analysis
        email_data = {
            'sender': sender,
            'subject': subject,
            'body': body,
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'ips': ips
        }
        rule_result = detector.analyze(email_data)
        
        # Create Email Entry
        db_email = Email(
            sender=sender,
            sender_domain=sender.split('@')[-1] if '@' in sender else '',
            subject=subject[:500],
            body=body[:10000],
            headers=headers,
            rule_score=rule_result['score'],
            threat_score=rule_result['score'], # Will be recalculated
            verdict=rule_result['verdict'],
            confidence=rule_result['confidence'],
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            attachment_verdict="NONE" if not attachments else "UNVERIFIED",
            received_at=datetime.utcnow()
        )
        db.add(db_email)
        db.flush()  # Extract ID
        
        # Store URLs
        for url in urls[:50]:
            db_url = URL(
                email_id=db_email.id,
                url=url[:500],
                domain=url.split('/')[2] if '://' in url else ''
            )
            db.add(db_url)
            
        # Store IPs
        for ip in ips[:20]:
            is_sender = (ip == sender_ip)
            db_ip = IP(
                email_id=db_email.id,
                ip_address=ip,
                spamhaus_flagged=spamhaus_flagged if is_sender else False,
                is_malicious=spamhaus_flagged if is_sender else False
            )
            db.add(db_ip)
            
        # Store Attachments
        for att in attachments[:10]:
            db_att = Attachment(
                email_id=db_email.id,
                file_name=att['filename'][:255],
                sha256=att['sha256']
            )
            db.add(db_att)
            
        # Store IOCs
        for url in urls[:50]:
            db.add(IOC(email_id=db_email.id, ioc_type="URL", value=url[:500], threat_score=rule_result['score']))
        for ip in ips[:20]:
            db.add(IOC(email_id=db_email.id, ioc_type="IP", value=ip, threat_score=rule_result['score']))
        for domain in domains[:20]:
            db.add(IOC(email_id=db_email.id, ioc_type="DOMAIN", value=domain, threat_score=rule_result['score']))
        for att in attachments[:10]:
            db.add(IOC(email_id=db_email.id, ioc_type="HASH", value=att['sha256'], threat_score=rule_result['score']))
            
        # Commit associations to load relationships
        db.commit()
        db.refresh(db_email)
        
        # Calculate scores dynamically
        recalculate_threat_score(db_email, db)
        db.commit()
        
        # Create timeline events
        events = [
            Event(email_id=db_email.id, event_type="RECEIVED", description="Email received for forensic analysis", severity="INFO"),
            Event(email_id=db_email.id, event_type="PARSED", description=f"Extracted {len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains, {len(attachments)} attachments", severity="INFO"),
            Event(email_id=db_email.id, event_type="SPF_CHECK", description=f"SPF authentication validation: {spf_status}", severity="INFO" if spf_status == "PASS" else "WARNING"),
            Event(email_id=db_email.id, event_type="DKIM_CHECK", description=f"DKIM cryptographic signature verification: {dkim_status}", severity="INFO" if dkim_status == "PASS" else "WARNING"),
            Event(email_id=db_email.id, event_type="DMARC_CHECK", description=f"DMARC record alignment: {dmarc_status}", severity="INFO" if dmarc_status == "PASS" else "WARNING"),
        ]
        
        if sender_ip:
            events.append(
                Event(
                    email_id=db_email.id,
                    event_type="SPAMHAUS_CHECK",
                    description=f"Spamhaus DNSBL reputation check for IP {sender_ip}: {'BLACKLISTED' if spamhaus_flagged else 'CLEAN'}",
                    severity="ERROR" if spamhaus_flagged else "INFO"
                )
            )
            
        events.append(
            Event(
                email_id=db_email.id,
                event_type="RULE_ANALYSIS",
                description=f"Rule-based detection finished. Base Score: {rule_result['score']}/100. Verdict: {rule_result['verdict']}",
                severity="WARNING" if rule_result['verdict'] in ['SUSPICIOUS', 'MALICIOUS'] else "INFO"
            )
        )
        
        if rule_result['details']:
            events.append(
                Event(
                    email_id=db_email.id,
                    event_type="RULE_DETAILS",
                    description=f"Rule triggers: {', '.join(rule_result['details'][:5])}",
                    severity="INFO"
                )
            )
            
        # Add events and commit
        for event in events:
            db.add(event)
        db.commit()
        db.refresh(db_email)
        
        # Prepare response
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
        
        # Trigger background threat intel enrichment
        if background_tasks:
            if os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("ABUSEIPDB_API_KEY") or os.getenv("MESA_SECURITY_API_KEY"):
                background_tasks.add_task(
                    enrich_email_background,
                    email_id=db_email.id
                )
                response["enrichment"] = "Started in background"
                
        return response
        
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        print(f"❌ Error processing email upload: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error processing email upload: {str(e)}"
        )


class EmailTextPayload(BaseModel):
    email_text: str

@app.post("/analyze-email")
async def analyze_email_text(
    payload: EmailTextPayload,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """
    Analyze raw email text content (via Pydantic Request Body)
    """
    try:
        # Write content to dummy memory file to reuse endpoint logic
        parser = EmailParser(payload.email_text)
        raw_bytes = parser.get_raw_bytes()
        
        sender = parser.get_sender()
        subject = parser.get_subject()
        body = parser.get_body()
        headers = parser.get_headers()
        urls = parser.extract_urls()
        ips = parser.extract_ips()
        domains = parser.extract_domains()
        attachments = parser.extract_attachments()
        
        sender_ip = ips[0] if ips else None
        spf_status = validate_spf(sender_ip, sender)
        dkim_status = validate_dkim(raw_bytes, sender.split('@')[-1] if '@' in sender else None)
        dmarc_status = validate_dmarc(sender.split('@')[-1] if '@' in sender else "", spf_status, dkim_status)
        spamhaus_flagged = check_spamhaus(sender_ip) if sender_ip else False
        
        email_data = {
            'sender': sender,
            'subject': subject,
            'body': body,
            'headers': headers,
            'urls': urls,
            'domains': domains,
            'ips': ips
        }
        rule_result = detector.analyze(email_data)
        
        db_email = Email(
            sender=sender,
            sender_domain=sender.split('@')[-1] if '@' in sender else '',
            subject=subject[:500],
            body=body[:10000],
            headers=headers,
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
        db.flush()
        
        # Store URLs
        for url in urls[:50]:
            db.add(URL(email_id=db_email.id, url=url[:500], domain=url.split('/')[2] if '://' in url else ''))
        # Store IPs
        for ip in ips[:20]:
            is_sender = (ip == sender_ip)
            db.add(IP(email_id=db_email.id, ip_address=ip, spamhaus_flagged=spamhaus_flagged if is_sender else False, is_malicious=spamhaus_flagged if is_sender else False))
        # Store Attachments
        for att in attachments[:10]:
            db.add(Attachment(email_id=db_email.id, file_name=att['filename'][:255], sha256=att['sha256']))
            
        # Store IOCs
        for url in urls[:50]:
            db.add(IOC(email_id=db_email.id, ioc_type="URL", value=url[:500], threat_score=rule_result['score']))
        for ip in ips[:20]:
            db.add(IOC(email_id=db_email.id, ioc_type="IP", value=ip, threat_score=rule_result['score']))
        for domain in domains[:20]:
            db.add(IOC(email_id=db_email.id, ioc_type="DOMAIN", value=domain, threat_score=rule_result['score']))
        for att in attachments[:10]:
            db.add(IOC(email_id=db_email.id, ioc_type="HASH", value=att['sha256'], threat_score=rule_result['score']))
            
        # Commit associations to load relationships
        db.commit()
        db.refresh(db_email)
        
        # Calculate scores dynamically
        recalculate_threat_score(db_email, db)
        db.commit()
        
        # Create timeline events
        events = [
            Event(email_id=db_email.id, event_type="RECEIVED", description="Email received for forensic analysis", severity="INFO"),
            Event(email_id=db_email.id, event_type="PARSED", description=f"Extracted {len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains, {len(attachments)} attachments", severity="INFO"),
            Event(email_id=db_email.id, event_type="SPF_CHECK", description=f"SPF authentication validation: {spf_status}", severity="INFO" if spf_status == "PASS" else "WARNING"),
            Event(email_id=db_email.id, event_type="DKIM_CHECK", description=f"DKIM cryptographic signature verification: {dkim_status}", severity="INFO" if dkim_status == "PASS" else "WARNING"),
            Event(email_id=db_email.id, event_type="DMARC_CHECK", description=f"DMARC record alignment: {dmarc_status}", severity="INFO" if dmarc_status == "PASS" else "WARNING"),
        ]
        
        if sender_ip:
            events.append(
                Event(
                    email_id=db_email.id,
                    event_type="SPAMHAUS_CHECK",
                    description=f"Spamhaus DNSBL reputation check for IP {sender_ip}: {'BLACKLISTED' if spamhaus_flagged else 'CLEAN'}",
                    severity="ERROR" if spamhaus_flagged else "INFO"
                )
            )
            
        events.append(
            Event(
                email_id=db_email.id,
                event_type="RULE_ANALYSIS",
                description=f"Rule-based detection finished. Base Score: {rule_result['score']}/100. Verdict: {rule_result['verdict']}",
                severity="WARNING" if rule_result['verdict'] in ['SUSPICIOUS', 'MALICIOUS'] else "INFO"
            )
        )
        
        if rule_result['details']:
            events.append(
                Event(
                    email_id=db_email.id,
                    event_type="RULE_DETAILS",
                    description=f"Rule triggers: {', '.join(rule_result['details'][:5])}",
                    severity="INFO"
                )
            )
            
        for event in events:
            db.add(event)
        db.commit()
        db.refresh(db_email)
        
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
            }
        }
        
        # Trigger background threat intel enrichment
        if background_tasks:
            if os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("ABUSEIPDB_API_KEY") or os.getenv("MESA_SECURITY_API_KEY"):
                background_tasks.add_task(
                    enrich_email_background,
                    email_id=db_email.id
                )
                response["enrichment"] = "Started in background"
                
        return response
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Text analysis failed: {str(e)}")


# ===================== EMAIL QUERY ENDPOINTS =====================

@app.get("/email/{email_id}")
async def get_email(
    email_id: int,
    include_iocs: bool = True,
    include_timeline: bool = True,
    db: Session = Depends(get_db)
):
    """
    Get full details of a specific analyzed email
    """
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    response = {
        "id": email.id,
        "sender": email.sender,
        "sender_domain": email.sender_domain,
        "subject": email.subject,
        "body": email.body[:500] + "..." if len(email.body) > 500 else email.body,
        "verdict": email.verdict,
        "threat_score": email.threat_score,
        "rule_score": email.rule_score,
        "confidence": email.confidence,
        "spf_status": email.spf_status,
        "dkim_status": email.dkim_status,
        "dmarc_status": email.dmarc_status,
        "attachment_verdict": email.attachment_verdict,
        "received_at": email.received_at.isoformat(),
        "analyzed_at": email.analyzed_at.isoformat() if email.analyzed_at else None,
        "headers_count": len(email.headers) if email.headers else 0
    }
    
    if include_iocs:
        urls = db.query(URL).filter(URL.email_id == email_id).all()
        ips = db.query(IP).filter(IP.email_id == email_id).all()
        attachments = db.query(Attachment).filter(Attachment.email_id == email_id).all()
        
        response["iocs"] = {
            "urls": [
                {
                    "id": url.id,
                    "url": url.url,
                    "domain": url.domain,
                    "vt_score": url.vt_score,
                    "is_phishing": url.is_phishing
                }
                for url in urls
            ],
            "ips": [
                {
                    "id": ip.id,
                    "ip": ip.ip_address,
                    "abuse_score": ip.abuse_score,
                    "spamhaus_flagged": ip.spamhaus_flagged,
                    "is_malicious": ip.is_malicious,
                    "country": ip.country,
                    "isp": ip.isp
                }
                for ip in ips
            ],
            "attachments": [
                {
                    "id": att.id,
                    "file_name": att.file_name,
                    "sha256": att.sha256,
                    "vt_score": att.vt_score,
                    "checked_at": att.checked_at.isoformat() if att.checked_at else None
                }
                for att in attachments
            ]
        }
    
    if include_timeline:
        timeline = db.query(Event).filter(Event.email_id == email_id).order_by(Event.timestamp).all()
        response["timeline"] = [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "description": event.description,
                "severity": event.severity
            }
            for event in timeline
        ]
    
    return response


@app.get("/timeline/{email_id}")
async def get_email_timeline(
    email_id: int,
    db: Session = Depends(get_db)
):
    """Get forensic timeline for an email"""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    events = db.query(Event).filter(Event.email_id == email_id).order_by(Event.timestamp).all()
    
    return {
        "email_id": email_id,
        "total_events": len(events),
        "events": [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "description": event.description,
                "severity": event.severity
            }
            for event in events
        ]
    }


# ===================== LIST AND SEARCH ENDPOINTS =====================

@app.get("/emails")
async def list_emails(
    skip: int = 0,
    limit: int = 50,
    verdict: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List emails with filtering and pagination"""
    query = db.query(Email)
    if verdict:
        query = query.filter(Email.verdict == verdict.upper())
    
    total = query.count()
    emails = query.order_by(desc(Email.received_at)).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "emails": [
            {
                "id": email.id,
                "sender": email.sender,
                "subject": email.subject,
                "verdict": email.verdict,
                "threat_score": email.threat_score,
                "confidence": email.confidence,
                "received_at": email.received_at.isoformat(),
                "analyzed_at": email.analyzed_at.isoformat() if email.analyzed_at else None
            }
            for email in emails
        ]
    }

@app.get("/emails/recent")
async def get_recent_emails(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """Get recently analyzed emails"""
    emails = db.query(Email).order_by(desc(Email.received_at)).limit(limit).all()
    
    return {
        "count": len(emails),
        "emails": [
            {
                "id": email.id,
                "sender": email.sender,
                "subject": email.subject[:100] + "..." if len(email.subject) > 100 else email.subject,
                "verdict": email.verdict,
                "threat_score": email.threat_score,
                "confidence": email.confidence,
                "received_at": email.received_at.isoformat(),
                "has_iocs": len(email.urls) > 0 or len(email.ips) > 0 or len(email.attachments) > 0
            }
            for email in emails
        ]
    }

@app.get("/dashboard/stats")
async def get_email_stats(
    db: Session = Depends(get_db)
):
    """Get dashboard threat stats"""
    total = db.query(Email).count()
    
    stats = {
        "total_emails": total,
        "verdicts": {},
        "avg_score": 0,
        "iocs": {
            "total_urls": db.query(URL).count(),
            "total_ips": db.query(IP).count(),
            "total_attachments": db.query(Attachment).count(),
            "total_events": db.query(Event).count()
        }
    }
    
    verdicts = db.query(Email.verdict, func.count(Email.id)).group_by(Email.verdict).all()
    for verdict, count in verdicts:
        stats["verdicts"][verdict] = count
    
    result = db.query(func.avg(Email.threat_score)).first()
    if result[0]:
        stats["avg_score"] = round(result[0], 2)
    
    return stats


# ===================== ENRICHMENT ENDPOINTS =====================

@app.post("/email/{email_id}/enrich")
async def enrich_email(
    email_id: int,
    db: Session = Depends(get_db)
):
    """
    Force synchronous enrichment of email details using VT and AbuseIPDB
    """
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Check configurations
    vt_configured = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    abuse_configured = bool(os.getenv("ABUSEIPDB_API_KEY"))
    
    events = []
    
    # 1. Check URLs with VirusTotal
    if vt_configured and email.urls:
        for url_obj in email.urls[:10]:
            try:
                result = await vt_service.get_url_report(url_obj.url)
                if "error" not in result:
                    malicious = result.get("malicious", 0)
                    suspicious = result.get("suspicious", 0)
                    
                    url_obj.vt_malicious = malicious
                    url_obj.vt_suspicious = suspicious
                    url_obj.vt_score = malicious * 10 + suspicious * 5
                    url_obj.is_phishing = malicious > 0
                    
                    ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "URL", IOC.value == url_obj.url).first()
                    if ioc:
                        ioc.threat_score = url_obj.vt_score
                        
                    events.append(Event(
                        email_id=email.id,
                        event_type="VT_URL_SCAN",
                        description=f"VT URL check: {malicious} malicious, {suspicious} suspicious detections for {url_obj.url[:40]}",
                        severity="WARNING" if malicious > 0 else "INFO"
                    ))
                await asyncio.sleep(1)
            except Exception as e:
                print(f"VT URL enrichment exception: {e}")
                
    # 2. Check IPs with AbuseIPDB
    if abuse_configured and email.ips:
        for ip_obj in email.ips[:10]:
            try:
                result = await abuse_service.check_ip(ip_obj.ip_address)
                if "error" not in result:
                    abuse_score = result.get("abuse_score", 0)
                    
                    ip_obj.abuse_score = abuse_score
                    ip_obj.is_malicious = abuse_score > 50
                    ip_obj.country = result.get("country")
                    ip_obj.isp = result.get("isp")
                    ip_obj.reports_count = result.get("reports", 0)
                    
                    ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "IP", IOC.value == ip_obj.ip_address).first()
                    if ioc:
                        ioc.threat_score = abuse_score // 10
                        
                    events.append(Event(
                        email_id=email.id,
                        event_type="ABUSEIPDB_IP_SCAN",
                        description=f"AbuseIPDB IP check: {abuse_score}% score, Country {ip_obj.country}, ISP {ip_obj.isp} for {ip_obj.ip_address}",
                        severity="WARNING" if ip_obj.is_malicious else "INFO"
                    ))
                await asyncio.sleep(1)
            except Exception as e:
                print(f"AbuseIPDB IP enrichment exception: {e}")
                
    # 3. Check Attachments with VirusTotal
    if vt_configured and email.attachments:
        for att_obj in email.attachments[:10]:
            try:
                result = await vt_service.get_file_report(att_obj.sha256)
                if "error" not in result:
                    malicious = result.get("malicious", 0)
                    suspicious = result.get("suspicious", 0)
                    
                    att_obj.vt_malicious = malicious
                    att_obj.vt_suspicious = suspicious
                    att_obj.vt_score = malicious * 10 + suspicious * 5
                    
                    ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "HASH", IOC.value == att_obj.sha256).first()
                    if ioc:
                        ioc.threat_score = att_obj.vt_score
                        
                    events.append(Event(
                        email_id=email.id,
                        event_type="VT_FILE_SCAN",
                        description=f"VT File check: {malicious} malicious detections for attachment {att_obj.file_name}",
                        severity="ERROR" if malicious > 0 else "INFO"
                    ))
                await asyncio.sleep(1)
            except Exception as e:
                print(f"VT file enrichment exception: {e}")
                
    # Recalculate score and verdict
    recalculate_threat_score(email, db)
    
    events.append(Event(
        email_id=email.id,
        event_type="ENRICHMENT_COMPLETE",
        description=f"Forced enrichment completed. Recalculated threat score: {email.threat_score}/100. Verdict: {email.verdict}",
        severity="INFO"
    ))
    
    for event in events:
        db.add(event)
    
    db.commit()
    db.refresh(email)
    
    return {
        "id": email.id,
        "verdict": email.verdict,
        "threat_score": email.threat_score,
        "confidence": email.confidence,
        "previous_score": email.rule_score,
        "vt_configured": vt_configured,
        "abuse_configured": abuse_configured,
        "new_events": len(events)
    }


# ===================== PDF REPORT GENERATION =====================

@app.get("/report/{email_id}")
async def get_report(
    email_id: int,
    db: Session = Depends(get_db)
):
    """
    Generate and stream a PDF forensic analysis report for an email
    """
    # Fetch email details
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
        
    # Gather database collections
    urls_list = [{"url": u.url, "domain": u.domain, "vt_score": u.vt_score, "is_phishing": u.is_phishing} for u in email.urls]
    ips_list = [{"ip": ip.ip_address, "abuse_score": ip.abuse_score, "spamhaus_flagged": ip.spamhaus_flagged, "is_malicious": ip.is_malicious} for ip in email.ips]
    attachments_list = [{"file_name": att.file_name, "sha256": att.sha256, "vt_score": att.vt_score} for att in email.attachments]
    
    events = db.query(Event).filter(Event.email_id == email_id).order_by(Event.timestamp).all()
    timeline_list = [{"timestamp": ev.timestamp, "event_type": ev.event_type, "severity": ev.severity, "description": ev.description} for ev in events]
    
    # Extract rule triggers
    rule_details_list = []
    for ev in events:
        if ev.event_type == "RULE_DETAILS":
            desc_text = ev.description
            if desc_text.startswith("Rule triggers: "):
                rule_details_list = [r.strip() for r in desc_text[15:].split(",")]
                
    email_data = {
        "id": email.id,
        "sender": email.sender,
        "sender_domain": email.sender_domain,
        "subject": email.subject,
        "verdict": email.verdict,
        "threat_score": email.threat_score,
        "rule_score": email.rule_score,
        "confidence": email.confidence,
        "received_at": email.received_at,
        "spf_status": email.spf_status,
        "dkim_status": email.dkim_status,
        "dmarc_status": email.dmarc_status,
        "urls": urls_list,
        "ips": ips_list,
        "attachments": attachments_list,
        "timeline": timeline_list,
        "rule_details": rule_details_list
    }
    
    try:
        pdf_bytes = generate_pdf_report(email_data)
        
        # Log report generation activity
        db_report = Report(email_id=email_id)
        db.add(db_report)
        db.commit()
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=email_threat_report_{email_id}.pdf"}
        )
    except Exception as e:
        print(f"❌ Error generating PDF: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error generating PDF report: {str(e)}"
        )


# ===================== BACKGROUND TASKS =====================

async def enrich_email_background(email_id: int):
    """
    Background worker process to query VirusTotal and AbuseIPDB
    """
    try:
        from app.models.database import SessionLocal
        db = SessionLocal()
        
        try:
            email = db.query(Email).filter(Email.id == email_id).first()
            if not email:
                return
                
            vt_configured = bool(os.getenv("VIRUSTOTAL_API_KEY"))
            abuse_configured = bool(os.getenv("ABUSEIPDB_API_KEY"))
            
            if not vt_configured and not abuse_configured:
                return
                
            db.add(Event(
                email_id=email.id,
                event_type="ENRICHMENT_STARTED",
                description="Background enrichment started",
                severity="INFO"
            ))
            db.commit()
            
            # 1. URL Scanning
            if vt_configured and email.urls:
                for url_obj in email.urls[:10]:
                    try:
                        result = await vt_service.get_url_report(url_obj.url)
                        if "error" not in result:
                            url_obj.vt_malicious = result.get("malicious", 0)
                            url_obj.vt_suspicious = result.get("suspicious", 0)
                            url_obj.vt_score = url_obj.vt_malicious * 10 + url_obj.vt_suspicious * 5
                            url_obj.is_phishing = url_obj.vt_malicious > 0
                            
                            ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "URL", IOC.value == url_obj.url).first()
                            if ioc:
                                ioc.threat_score = url_obj.vt_score
                                
                            db.add(Event(
                                email_id=email.id,
                                event_type="VT_URL_SCAN",
                                description=f"VT URL check: {url_obj.vt_malicious} malicious for {url_obj.url[:40]}",
                                severity="WARNING" if url_obj.is_phishing else "INFO"
                            ))
                        await asyncio.sleep(1)
                    except Exception as e:
                        print(f"Background VT URL error: {e}")
                        
            # 2. IP Scanning
            if abuse_configured and email.ips:
                for ip_obj in email.ips[:10]:
                    try:
                        result = await abuse_service.check_ip(ip_obj.ip_address)
                        if "error" not in result:
                            ip_obj.abuse_score = result.get("abuse_score", 0)
                            ip_obj.is_malicious = ip_obj.abuse_score > 50
                            ip_obj.country = result.get("country")
                            ip_obj.isp = result.get("isp")
                            ip_obj.reports_count = result.get("reports", 0)
                            
                            ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "IP", IOC.value == ip_obj.ip_address).first()
                            if ioc:
                                ioc.threat_score = ip_obj.abuse_score // 10
                                
                            db.add(Event(
                                email_id=email.id,
                                event_type="ABUSEIPDB_IP_SCAN",
                                description=f"AbuseIPDB check: {ip_obj.abuse_score}% confidence for {ip_obj.ip_address}",
                                severity="WARNING" if ip_obj.is_malicious else "INFO"
                            ))
                        await asyncio.sleep(1)
                    except Exception as e:
                        print(f"Background AbuseIPDB IP error: {e}")
                        
            # 3. File Attachment scanning
            if vt_configured and email.attachments:
                for att_obj in email.attachments[:10]:
                    try:
                        result = await vt_service.get_file_report(att_obj.sha256)
                        if "error" not in result:
                            malicious = result.get("malicious", 0)
                            suspicious = result.get("suspicious", 0)
                            
                            att_obj.vt_malicious = malicious
                            att_obj.vt_suspicious = suspicious
                            att_obj.vt_score = malicious * 10 + suspicious * 5
                            att_obj.checked_at = datetime.utcnow()
                            
                            ioc = db.query(IOC).filter(IOC.email_id == email_id, IOC.ioc_type == "HASH", IOC.value == att_obj.sha256).first()
                            if ioc:
                                ioc.threat_score = att_obj.vt_score
                                
                            db.add(Event(
                                email_id=email.id,
                                event_type="VT_FILE_SCAN",
                                description=f"VT File check: {malicious} malicious detections for attachment {att_obj.file_name}",
                                severity="ERROR" if malicious > 0 else "INFO"
                            ))
                        await asyncio.sleep(1)
                    except Exception as e:
                        print(f"Background VT File error: {e}")
                        
            # 4. Mesa Security Email Scanning
            mesa_configured = bool(os.getenv("MESA_SECURITY_API_KEY"))
            if mesa_configured:
                try:
                    # Get raw email content
                    raw_email_content = ""
                    # Reconstruct email from stored fields
                    for header_key, header_value in email.headers.items():
                        raw_email_content += f"{header_key}: {header_value}\n"
                    raw_email_content += "\n" + (email.body or "")
                    
                    email_bytes = raw_email_content.encode('utf-8')
                    
                    db.add(Event(
                        email_id=email.id,
                        event_type="MESA_SCAN_STARTED",
                        description="Mesa Security scan initiated",
                        severity="INFO"
                    ))
                    db.commit()
                    
                    result = await mesa_service.scan_email(
                        email_bytes,
                        filename=f"email_{email.id}.eml",
                        save_screenshot=True,
                        save_email=False
                    )
                    
                    if "error" not in result:
                        email.mesa_job_id = result.get("job_id")
                        email.mesa_status = result.get("status", "unknown")
                        
                        # Parse Mesa results
                        mesa_result = result.get("result", {})
                        email.mesa_details = mesa_result
                        
                        # Extract verdict from Mesa results
                        if mesa_result:
                            # Mesa might provide a verdict field or we need to analyze the result
                            if "verdict" in mesa_result:
                                email.mesa_verdict = mesa_result.get("verdict")
                            elif "classification" in mesa_result:
                                email.mesa_verdict = mesa_result.get("classification")
                            
                            # Try to extract a score from Mesa results
                            if "threat_score" in mesa_result:
                                email.mesa_score = min(100, int(mesa_result.get("threat_score", 0)))
                            elif "risk_score" in mesa_result:
                                email.mesa_score = min(100, int(mesa_result.get("risk_score", 0)))
                        
                        email.mesa_scanned_at = datetime.utcnow()
                        
                        db.add(Event(
                            email_id=email.id,
                            event_type="MESA_SCAN_COMPLETE",
                            description=f"Mesa Security scan completed. Verdict: {email.mesa_verdict}. Score: {email.mesa_score}",
                            severity="WARNING" if email.mesa_verdict and email.mesa_verdict.lower() != "clean" else "INFO"
                        ))
                    else:
                        error_msg = result.get("error", "Unknown error")
                        email.mesa_status = "failed"
                        
                        db.add(Event(
                            email_id=email.id,
                            event_type="MESA_SCAN_FAILED",
                            description=f"Mesa Security scan failed: {error_msg}",
                            severity="WARNING"
                        ))
                    
                    db.commit()
                    
                except Exception as e:
                    print(f"Background Mesa Security error: {e}")
                    email.mesa_status = "error"
                    db.add(Event(
                        email_id=email.id,
                        event_type="MESA_SCAN_ERROR",
                        description=f"Mesa Security scan error: {str(e)}",
                        severity="WARNING"
                    ))
                    db.commit()
                        
            # Recalculate and update
            recalculate_threat_score(email, db)
            
            db.add(Event(
                email_id=email.id,
                event_type="ENRICHMENT_COMPLETE",
                description=f"Background enrichment completed. Final score: {email.threat_score}/100. Verdict: {email.verdict}",
                severity="INFO"
            ))
            db.commit()
            
        except Exception as e:
            print(f"❌ Background enrichment error: {str(e)}")
            db.rollback()
        finally:
            db.close()
            
    except Exception as e:
        print(f"❌ Background task error: {str(e)}")


# ===================== DELETE ENDPOINTS =====================

@app.delete("/email/{email_id}")
async def delete_email(
    email_id: int,
    db: Session = Depends(get_db)
):
    """Delete an email and all associated data"""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    db.delete(email)
    db.commit()
    
    return {
        "message": f"Email {email_id} deleted successfully",
        "id": email_id
    }


# ===================== MESA SECURITY ENDPOINTS =====================

@app.post("/email/{email_id}/mesa-scan")
async def scan_email_with_mesa(
    email_id: int,
    db: Session = Depends(get_db)
):
    """
    Manually trigger a Mesa Security scan for a specific email
    """
    if not os.getenv("MESA_SECURITY_API_KEY"):
        raise HTTPException(
            status_code=400,
            detail="Mesa Security API key not configured"
        )
    
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    try:
        # Reconstruct raw email content
        raw_email_content = ""
        if email.headers:
            for header_key, header_value in email.headers.items():
                raw_email_content += f"{header_key}: {header_value}\n"
        raw_email_content += "\n" + (email.body or "")
        
        email_bytes = raw_email_content.encode('utf-8')
        
        # Log event
        db.add(Event(
            email_id=email.id,
            event_type="MESA_MANUAL_SCAN_STARTED",
            description="Manual Mesa Security scan initiated",
            severity="INFO"
        ))
        db.commit()
        
        # Submit to Mesa
        result = await mesa_service.scan_email(
            email_bytes,
            filename=f"email_{email.id}.eml",
            save_screenshot=True,
            save_email=False
        )
        
        if "error" in result:
            error_msg = result.get("error", "Unknown error")
            email.mesa_status = "failed"
            
            db.add(Event(
                email_id=email.id,
                event_type="MESA_MANUAL_SCAN_FAILED",
                description=f"Mesa Security manual scan failed: {error_msg}",
                severity="WARNING"
            ))
            db.commit()
            
            raise HTTPException(
                status_code=400,
                detail=f"Mesa scan failed: {error_msg}"
            )
        
        # Update email with scan results
        email.mesa_job_id = result.get("job_id")
        email.mesa_status = result.get("status", "unknown")
        
        # Parse results
        mesa_result = result.get("result", {})
        email.mesa_details = mesa_result
        
        if mesa_result:
            if "verdict" in mesa_result:
                email.mesa_verdict = mesa_result.get("verdict")
            elif "classification" in mesa_result:
                email.mesa_verdict = mesa_result.get("classification")
            
            if "threat_score" in mesa_result:
                email.mesa_score = min(100, int(mesa_result.get("threat_score", 0)))
            elif "risk_score" in mesa_result:
                email.mesa_score = min(100, int(mesa_result.get("risk_score", 0)))
        
        email.mesa_scanned_at = datetime.utcnow()
        
        db.add(Event(
            email_id=email.id,
            event_type="MESA_MANUAL_SCAN_COMPLETE",
            description=f"Mesa Security manual scan completed. Verdict: {email.mesa_verdict}. Score: {email.mesa_score}",
            severity="WARNING" if email.mesa_verdict and email.mesa_verdict.lower() != "clean" else "INFO"
        ))
        
        # Recalculate overall threat score
        recalculate_threat_score(email, db)
        db.commit()
        
        return {
            "email_id": email_id,
            "mesa_job_id": email.mesa_job_id,
            "mesa_status": email.mesa_status,
            "mesa_verdict": email.mesa_verdict,
            "mesa_score": email.mesa_score,
            "mesa_details": email.mesa_details,
            "overall_threat_score": email.threat_score,
            "overall_verdict": email.verdict,
            "message": "Mesa Security scan completed successfully"
        }
        
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error in manual Mesa scan: {str(e)}")
        email.mesa_status = "error"
        db.add(Event(
            email_id=email.id,
            event_type="MESA_MANUAL_SCAN_ERROR",
            description=f"Mesa Security scan error: {str(e)}",
            severity="ERROR"
        ))
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Mesa scan error: {str(e)}"
        )


@app.get("/email/{email_id}/mesa-results")
async def get_mesa_results(
    email_id: int,
    db: Session = Depends(get_db)
):
    """
    Get Mesa Security scan results for a specific email
    """
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if not email.mesa_job_id:
        return {
            "email_id": email_id,
            "message": "No Mesa scan results available for this email",
            "mesa_status": None
        }
    
    return {
        "email_id": email_id,
        "mesa_job_id": email.mesa_job_id,
        "mesa_status": email.mesa_status,
        "mesa_verdict": email.mesa_verdict,
        "mesa_score": email.mesa_score,
        "mesa_details": email.mesa_details,
        "mesa_scanned_at": email.mesa_scanned_at.isoformat() if email.mesa_scanned_at else None
    }


@app.get("/mesa/job/{job_id}")
async def get_mesa_job_status(job_id: str):
    """
    Get the status of a Mesa Security scan job by job ID
    """
    if not os.getenv("MESA_SECURITY_API_KEY"):
        raise HTTPException(
            status_code=400,
            detail="Mesa Security API key not configured"
        )
    
    try:
        result = await mesa_service.get_job_status(job_id)
        
        if "error" in result:
            raise HTTPException(
                status_code=400,
                detail=result.get("error", "Failed to get job status")
            )
        
        return result
        
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error checking job status: {str(e)}"
        )



# ===================== ERROR HANDLERS =====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Global exception handler"""
    print(f"❌ Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "An internal server error occurred",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )