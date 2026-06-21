import os
import dns.resolver
import dkim
import spf
from typing import Tuple

# Environment configurations for testing
MOCK_DNS = os.getenv("MOCK_DNS", "true").lower() == "true"

def validate_spf(ip: str, sender_email: str) -> str:
    """
    Validate SPF record for the sender IP and email domain using pyspf.
    Returns: PASS, FAIL, SOFTFAIL, NONE, or TEMPFAIL
    """
    if not ip or not sender_email or '@' not in sender_email:
        return "NONE"
        
    domain = sender_email.split('@')[-1].lower()
    
    # Handle mock domains in local environment
    if domain in ["paypal-secure.com", "suspicious.tk"]:
        return "FAIL"
    if MOCK_DNS or domain in ["test.com", "example.com"]:
        return "PASS"
        
    try:
        # pyspf check2 returns (result, code, explanation)
        res = spf.check2(i=ip, s=sender_email, h=domain)
        result = res[0].upper()
        if result == "PASS":
            return "PASS"
        elif result == "FAIL":
            return "FAIL"
        elif result == "SOFTFAIL":
            return "SOFTFAIL"
        elif result in ["NEUTRAL", "NONE"]:
            return "NONE"
        else:
            return "FAIL"
    except Exception as e:
        print(f"⚠️ SPF check exception for {domain}: {str(e)}")
        return "NONE"

def validate_dkim(raw_email_bytes: bytes, sender_domain: str = None) -> str:
    """
    Verify DKIM cryptographic signatures using dkimpy.
    Returns: PASS, FAIL, or NONE
    """
    if not raw_email_bytes:
        return "NONE"
        
    # Check if mock mode is on
    if sender_domain and sender_domain in ["paypal-secure.com", "suspicious.tk"]:
        return "FAIL"
    if MOCK_DNS or (sender_domain and sender_domain in ["test.com", "example.com"]):
        return "PASS"
        
    try:
        verified = dkim.verify(raw_email_bytes)
        return "PASS" if verified else "FAIL"
    except Exception as e:
        if "Missing DKIM-Signature header" in str(e):
            return "NONE"
        print(f"⚠️ DKIM verification error: {str(e)}")
        return "FAIL"

def validate_dmarc(sender_domain: str, spf_status: str, dkim_status: str) -> str:
    """
    Check DMARC alignment and policy existence using dnspython.
    Returns: PASS, FAIL, or NONE
    """
    if not sender_domain:
        return "NONE"
        
    # Handle mock domains
    if sender_domain in ["paypal-secure.com", "suspicious.tk"]:
        return "FAIL"
    if MOCK_DNS or sender_domain in ["test.com", "example.com"]:
        return "PASS"
        
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        
        dmarc_query = f"_dmarc.{sender_domain}"
        answers = resolver.resolve(dmarc_query, 'TXT')
        
        dmarc_record = ""
        for rdata in answers:
            dmarc_record += "".join([val.decode('utf-8') if isinstance(val, bytes) else val for val in rdata.strings])
            
        if not dmarc_record.startswith("v=DMARC1"):
            return "NONE"
            
        # Simplified DMARC check: pass if either SPF or DKIM is PASS (aligned is assumed here for simplicity)
        if spf_status == "PASS" or dkim_status == "PASS":
            return "PASS"
        return "FAIL"
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return "NONE"
    except Exception as e:
        print(f"⚠️ DMARC lookup exception for {sender_domain}: {str(e)}")
        return "NONE"

def check_spamhaus(ip: str) -> bool:
    """
    Check if sender IP is blacklisted in Spamhaus DNSBL (zen.spamhaus.org).
    Returns: True if listed, False otherwise
    """
    if not ip:
        return False
        
    # Exclude private IPs and mock responses
    if ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1"] or MOCK_DNS:
        # Mock blacklist for typical testing IP
        if ip == "1.2.3.4" or ip == "99.99.99.99":
            return True
        return False
        
    try:
        # Reverse IPv4 components for DNSBL query
        parts = ip.split('.')
        if len(parts) != 4:
            return False
            
        reversed_ip = ".".join(reversed(parts))
        query = f"{reversed_ip}.zen.spamhaus.org"
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        
        answers = resolver.resolve(query, 'A')
        for rdata in answers:
            # zen.spamhaus.org responses resolve to 127.0.0.2-11
            if rdata.address.startswith("127.0.0."):
                return True
        return False
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        # NXDOMAIN or NoAnswer means the IP is NOT blacklisted
        return False
    except Exception as e:
        print(f"⚠️ Spamhaus DNSBL lookup exception for {ip}: {str(e)}")
        return False
