
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/email_threat_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Email(Base):
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(255))
    sender_domain = Column(String(255))
    subject = Column(Text)
    body = Column(Text)
    headers = Column(JSON)  # Store as JSON
    
    # Email Security Protocols
    spf_status = Column(String(50), nullable=True)  # PASS, FAIL, SOFTFAIL, NONE, etc.
    dkim_status = Column(String(50), nullable=True)  # PASS, FAIL, NONE
    dmarc_status = Column(String(50), nullable=True)  # PASS, FAIL, NONE
    
    # Attachment Verdict
    attachment_verdict = Column(String(50), nullable=True)  # SAFE, SUSPICIOUS, MALICIOUS, NONE
    
    # Threat Scores
    rule_score = Column(Integer, default=0)
    threat_score = Column(Integer, default=0)  # Combined score
    verdict = Column(String(50))  # SAFE, SUSPICIOUS, MALICIOUS
    confidence = Column(String(20))  # LOW, MEDIUM, HIGH
    
    # Timestamps
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    analyzed_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    urls = relationship("URL", back_populates="email", cascade="all, delete-orphan")
    ips = relationship("IP", back_populates="email", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="email", cascade="all, delete-orphan")

class URL(Base):
    __tablename__ = "urls"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    url = Column(Text)
    domain = Column(String(255))
    
    # Threat Intel
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    is_phishing = Column(Boolean, default=False)
    
    # Timestamp
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    email = relationship("Email", back_populates="urls")

class IP(Base):
    __tablename__ = "ips"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    ip_address = Column(String(45))  # IPv4 or IPv6
    
    # Threat Intel
    abuse_score = Column(Integer, default=0)
    spamhaus_flagged = Column(Boolean, default=False)
    is_malicious = Column(Boolean, default=False)
    country = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    reports_count = Column(Integer, default=0)
    
    # Timestamp
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    email = relationship("Email", back_populates="ips")

class Event(Base):
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    
    event_type = Column(String(50))  # PARSED, URL_EXTRACTED, THREAT_CHECKED, etc.
    description = Column(Text)
    severity = Column(String(20), default="INFO")  # INFO, WARNING, ERROR
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    email = relationship("Email", back_populates="events")

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    
    ioc_type = Column(String(20))  # URL, IP, DOMAIN, HASH
    value = Column(Text)
    threat_score = Column(Integer, default=0)
    
    # Timestamp
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    email = relationship("Email", back_populates="iocs")

# Update Email relationship
Email.iocs = relationship("IOC", back_populates="email", cascade="all, delete-orphan")

class Attachment(Base):
    __tablename__ = "attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    file_name = Column(String(255))
    sha256 = Column(String(64))
    
    # Threat Intel
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    
    # Timestamp
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    email = relationship("Email", back_populates="attachments")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    file_path = Column(Text, nullable=True)
    
    # Relationship
    email = relationship("Email", back_populates="reports")

# Database utilities
def get_db():
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)
    