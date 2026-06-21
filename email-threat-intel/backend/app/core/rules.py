# backend/app/core/rules.py

import re
from typing import Dict, List, Tuple
from datetime import datetime

class RuleBasedDetector:
    """Rule-based phishing detection engine"""
    
    def __init__(self):
        self.spam_keywords = [
            "free money", "win now", "click here", "urgent", 
            "limited offer", "congratulations", "claim now",
            "verify your account", "update your information",
            "suspended", "immediately", "password reset",
            "bank account", "credit card", "social security",
            "bitcoin", "crypto", "gift card", "paypal", "inheritance",
            "lottery", "security alert", "suspicious activity",
            "payment confirmation", "invoice", "refund", "receipt",
            "overdue", "delivery failed", "dhl", "fedex", "ups",
            "wallet", "login details", "security verification", "wire transfer"
        ]
        
        self.urgency_phrases = [
            "act now", "expires", "limited time",
            "immediately", "as soon as possible",
            "don't delay", "last chance", "urgent action",
            "within 24 hours", "action required", "critical alert",
            "final warning", "immediate attention", "prevent suspension",
            "block your account", "before it is deleted", "resolve this issue"
        ]
        
        self.suspicious_senders = [
            "paypal", "apple", "microsoft", "google", "amazon", 
            "netflix", "chase", "wells fargo", "citibank", "bank of america",
            "dhl", "fedex", "ups", "facebook", "instagram"
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz',
            '.top', '.work', '.date', '.men', '.gq',
            '.bid', '.stream', '.download', '.loan'
        ]

        self.link_shorteners = [
            "bit.ly", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", 
            "t.co", "rebrand.ly", "goo.gl", "bit.do", "adf.ly"
        ]
    
    def analyze(self, email_data: Dict) -> Dict:
        """
        Analyze email and return score with details - STRICT CRITERIA
        """
        score = 0
        details = []
        
        # Check each rule
        score += self._check_keywords(email_data, details)
        score += self._check_urgency(email_data, details)
        score += self._check_links(email_data['urls'], details)
        score += self._check_exclamations(email_data, details)
        score += self._check_uppercase(email_data, details)
        score += self._check_sender_spoofing(email_data, details)
        score += self._check_suspicious_domains(email_data['domains'], details)
        score += self._check_missing_headers(email_data['headers'], details)
        score += self._check_link_shorteners(email_data['urls'], details)
        score += self._check_ip_links(email_data['urls'], details)
        score += self._check_idn_homograph(email_data['domains'], details)
        
        # Direct scoring with STRICT thresholds (no multiplication)
        # Any suspicious activity detected = MALICIOUS
        normalized_score = min(100, score)
        
        # STRICT VERDICTS: Much lower thresholds
        # >= 40: MALICIOUS (very aggressive - any significant finding)
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
    
    def _check_keywords(self, email_data: Dict, details: List) -> int:
        """Check for spam/phishing keywords in subject and body - STRICT DETECTION"""
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        subject_lower = subject.lower()
        body_lower = body.lower()
        
        found_subject = []
        found_body = []
        
        for keyword in self.spam_keywords:
            if keyword.lower() in subject_lower:
                found_subject.append(keyword)
            if keyword.lower() in body_lower:
                found_body.append(keyword)
        
        score = 0
        # STRICT: Even a single keyword in subject = 15 points
        if found_subject:
            details.append(f"⚠️ SPAM keyword in subject: {', '.join(found_subject[:3])}")
            score += 15 + (len(found_subject) - 1) * 8  # 15 base + 8 per additional keyword
        # STRICT: Even a single keyword in body = 20 points
        if found_body:
            details.append(f"⚠️ SPAM keyword in body: {', '.join(found_body[:3])}")
            score += 20 + (len(found_body) - 1) * 5  # 20 base + 5 per additional keyword
            
        return score
    
    def _check_urgency(self, email_data: Dict, details: List) -> int:
        """Check for urgency phrases - STRICT DETECTION"""
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        subject_lower = subject.lower()
        body_lower = body.lower()
        
        found_subject = []
        found_body = []
        
        for phrase in self.urgency_phrases:
            if phrase.lower() in subject_lower:
                found_subject.append(phrase)
            if phrase.lower() in body_lower:
                found_body.append(phrase)
        
        score = 0
        # STRICT: Any urgency phrase in subject = 12 points
        if found_subject:
            details.append(f"🚨 URGENCY in subject: {', '.join(found_subject[:2])}")
            score += 12 + (len(found_subject) - 1) * 6
        # STRICT: Any urgency phrase in body = 15 points
        if found_body:
            details.append(f"🚨 URGENCY in body: {', '.join(found_body[:2])}")
            score += 15 + (len(found_body) - 1) * 4
            
        return score
    
    def _check_links(self, urls: List[str], details: List) -> int:
        """Check link count and quality - STRICT"""
        if len(urls) == 0:
            return 0
        
        # STRICT: Any links at all in suspicious email context
        if len(urls) > 5:
            details.append(f"🔗 MULTIPLE LINKS ({len(urls)}) - High link density")
            return 20
        elif len(urls) > 2:
            details.append(f"🔗 Multiple links present ({len(urls)})")
            return 12
        elif len(urls) == 1:
            details.append(f"🔗 Single link detected")
            return 5
        return 0
    
    def _check_exclamations(self, email_data: Dict, details: List) -> int:
        """Check for excessive exclamation marks - STRICT"""
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        subj_count = subject.count('!')
        body_count = body.count('!')
        
        score = 0
        # STRICT: Any exclamation in subject = 6 points
        if subj_count > 0:
            details.append(f"❗ Subject has {subj_count} exclamation mark(s)")
            score += 6 + min(10, subj_count * 2)
        # STRICT: Any exclamations in body = 8 points base
        if body_count > 3:
            details.append(f"❗ Body has excessive exclamation marks ({body_count})")
            score += 12
        elif body_count > 0:
            details.append(f"❗ Body has {body_count} exclamation mark(s)")
            score += 6
        return score
    
    def _check_uppercase(self, email_data: Dict, details: List) -> int:
        """Check for excessive uppercase words - STRICT"""
        subject = email_data.get('subject', '') or ''
        body = email_data.get('body', '') or ''
        
        # Check if subject has excessive uppercase
        subj_words = re.findall(r'\b[A-Za-z]+\b', subject)
        subj_upper = re.findall(r'\b[A-Z]{3,}\b', subject)
        
        score = 0
        # STRICT: If subject is >50% uppercase = 10 points
        if subj_words and len(subj_upper) / len(subj_words) > 0.5:
            details.append(f"🔤 Subject is {int(len(subj_upper)/len(subj_words)*100)}% UPPERCASE")
            score += 10
        elif subj_words and len(subj_upper) > 0:
            details.append(f"🔤 Subject has {len(subj_upper)} ALL-CAPS words")
            score += 5
            
        # STRICT: Any ALL-CAPS words in body = 6 points each
        body_words = re.findall(r'\b[A-Z]{4,}\b', body)
        if body_words:
            details.append(f"🔤 Body has {len(body_words)} ALL-CAPS word(s)")
            score += 6 + min(10, len(body_words) * 2)
        return score
    
    def _check_sender_spoofing(self, email_data: Dict, details: List) -> int:
        """Check for display name spoofing - STRICT"""
        sender = email_data.get('sender', '') or ''
        headers = email_data.get('headers', {}) or {}
        from_header = headers.get('from', '') or ''
        
        if not sender:
            return 0
            
        parts = sender.split('@')
        if len(parts) != 2:
            return 0
            
        local_part = parts[0].lower()
        domain = parts[1].lower()
        
        # Free/Generic email providers
        free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "mail.com", "aol.com", "icloud.com", "zoho.com"]
        
        # STRICT: Any brand misuse = 25 points
        if domain in free_domains:
            for brand in self.suspicious_senders:
                if brand in local_part:
                    details.append(f"🔓 BRAND SPOOFING: '{brand}' in free email local part: {sender}")
                    return 25
                    
        # Brand name in display name but domain doesn't match
        from_header_lower = from_header.lower()
        for brand in self.suspicious_senders:
            if brand in from_header_lower:
                brand_clean = brand.replace(' ', '')
                if brand_clean not in domain:
                    details.append(f"🔓 BRAND MISMATCH: Display name mentions '{brand}' but domain is {domain}")
                    return 25
                    
        # Lookalike domains
        for brand in self.suspicious_senders:
            brand_clean = brand.replace(' ', '')
            if brand_clean in domain and not (domain == f"{brand_clean}.com" or domain.endswith(f".{brand_clean}.com")):
                details.append(f"🔓 LOOKALIKE DOMAIN: {domain}")
                return 25
                
        return 0
    
    def _check_suspicious_domains(self, domains: List[str], details: List) -> int:
        """Check for suspicious TLDs - STRICT"""
        suspicious_found = []
        for domain in domains:
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    suspicious_found.append(domain)
                    break
        
        # STRICT: Any suspicious TLD = 20+ points
        if suspicious_found:
            details.append(f"🌐 SUSPICIOUS TLD: {', '.join(suspicious_found[:2])}")
            return min(25, 20 + len(suspicious_found) * 3)
        return 0
    
    def _check_missing_headers(self, headers: Dict, details: List) -> int:
        """Check for missing security headers - STRICT"""
        score = 0
        missing = []
        
        # Check critical headers
        critical_headers = ['received', 'message-id', 'date']
        for header in critical_headers:
            if header not in headers:
                missing.append(header)
        
        # Check authentication headers
        has_spf = any(h in headers for h in ['spf', 'received-spf', 'authentication-results'])
        has_dkim = any(h in headers for h in ['dkim', 'dkim-signature', 'authentication-results'])
        has_dmarc = any(h in headers for h in ['dmarc', 'authentication-results'])
        
        present_count = sum([has_spf, has_dkim, has_dmarc])
        
        # STRICT: Missing auth headers = 15 points
        if present_count == 0:
            missing.append('all auth headers')
            score += 15
            details.append("🔓 MISSING AUTH: No SPF/DKIM/DMARC headers found")
        # STRICT: Partial auth = 8 points
        elif present_count < 3:
            score += 8
            details.append(f"⚠️ LIMITED AUTH: Only {present_count}/3 authentication protocols")
        
        # Missing critical headers
        if missing and 'all auth headers' not in missing:
            details.append(f"📧 Missing critical headers: {', '.join(missing[:2])}")
            score += 5
        
        return score

    def _check_link_shorteners(self, urls: List[str], details: List) -> int:
        """Check if email contains link shorteners - STRICT"""
        found = []
        for url in urls:
            for shortener in self.link_shorteners:
                if shortener in url.lower():
                    found.append(shortener)
                    break
        # STRICT: Any link shortener = 18 points
        if found:
            details.append(f"🔗 LINK SHORTENER: {', '.join(found)}")
            return 18 + len(found) * 3
        return 0

    def _check_ip_links(self, urls: List[str], details: List) -> int:
        """Check if any links use raw IP addresses - STRICT"""
        ip_url_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        found = []
        for url in urls:
            if re.match(ip_url_pattern, url):
                found.append(url)
        # STRICT: IP-based links = 22 points
        if found:
            details.append(f"🔗 RAW IP LINK (HIGHLY SUSPICIOUS): {found[0][:40]}")
            return 22
        return 0

    def _check_idn_homograph(self, domains: List[str], details: List) -> int:
        """Check for IDN homograph attacks - STRICT"""
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
        # STRICT: IDN attack = 20 points
        if found:
            return 20
        return 0