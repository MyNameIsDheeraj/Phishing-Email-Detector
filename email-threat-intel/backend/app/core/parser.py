
import email
import re
from email.policy import default
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
import html

class EmailParser:
    """Parses raw email content and extracts structured data"""
    
    def __init__(self, raw_email: str):
        self.raw_email = raw_email
        self.parsed_email = None
        self._parse()
    
    def _parse(self):
        """Parse the raw email using Python's email library"""
        try:
            self.parsed_email = email.message_from_string(
                self.raw_email, 
                policy=default
            )
        except Exception as e:
            raise ValueError(f"Failed to parse email: {str(e)}")
    
    def get_sender(self) -> str:
        """Extract sender email address"""
        from_header = self.parsed_email.get('From', '')
        # Extract email from "Name <email@domain.com>" format
        match = re.search(r'<(.+?)>', from_header)
        if match:
            return match.group(1)
        return from_header.strip()
    
    def get_subject(self) -> str:
        """Extract email subject"""
        return self.parsed_email.get('Subject', '').strip()
    
    def get_body(self) -> str:
        """Extract email body, handling both plain text and HTML"""
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
                        # Convert HTML to plain text
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
    
    def get_headers(self) -> Dict[str, str]:
        """Extract all email headers"""
        headers = {}
        for key, value in self.parsed_email.items():
            headers[key.lower()] = value
        return headers
    
    def extract_urls(self) -> List[str]:
        """Extract all URLs from email body"""
        body = self.get_body()
        # Pattern for URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)
        return list(set(urls))  # Remove duplicates
    
    def get_sender_ip(self) -> Optional[str]:
        """Extract the actual SMTP sending server IP from Received headers"""
        # Check Received headers first
        received_headers = self.parsed_email.get_all('Received', [])
        if not received_headers:
            # Fallback if get_all returned None
            received_headers = []
            
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for rh in received_headers:
            found = re.findall(ip_pattern, rh)
            for ip in found:
                if not self._is_private_ip(ip):
                    return ip
                    
        # Fallback to X-Originating-IP or X-Forwarded-For
        headers = self.get_headers()
        for header in ['x-originating-ip', 'x-forwarded-for']:
            if header in headers:
                found = re.findall(ip_pattern, headers[header])
                for ip in found:
                    if not self._is_private_ip(ip):
                        return ip
        return None

    def extract_ips(self) -> List[str]:
        """Extract public IP addresses with sender IP prioritized at index 0"""
        sender_ip = self.get_sender_ip()
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = []
        if sender_ip:
            ips.append(sender_ip)
            
        # Check headers
        headers = self.get_headers()
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
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        parts = list(map(int, ip.split('.')))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    
    def extract_domains(self) -> List[str]:
        """Extract domains from URLs"""
        urls = self.extract_urls()
        domains = []
        for url in urls:
            # Simple domain extraction from URL
            match = re.search(r'https?://([^/]+)', url)
            if match:
                domain = match.group(1)
                # Remove www. prefix if present
                domain = re.sub(r'^www\.', '', domain)
                domains.append(domain)
        return list(set(domains))

    def extract_attachments(self) -> List[Dict]:
        """Extract all attachments and calculate their SHA256 hashes"""
        attachments = []
        if not self.parsed_email:
            return attachments
            
        for part in self.parsed_email.walk():
            filename = part.get_filename()
            if filename:
                # Retrieve binary payload
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

    def get_raw_bytes(self) -> bytes:
        """Get the raw email content as bytes for DKIM verification"""
        try:
            return self.raw_email.encode('utf-8')
        except:
            return self.raw_email.encode('latin-1', errors='ignore')