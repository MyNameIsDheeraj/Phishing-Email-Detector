
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
            "bank account", "credit card", "social security"
        ]
        
        self.urgency_phrases = [
            "act now", "expires", "limited time",
            "immediately", "as soon as possible",
            "don't delay", "last chance", "urgent action"
        ]
        
        self.suspicious_senders = [
            "paypal.com", "apple.com", "microsoft.com", 
            "google.com", "amazon.com", "bank", "chase",
            "wells fargo", "citibank"
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz',
            '.top', '.work', '.date', '.men', '.gq'
        ]
    
    def analyze(self, email_data: Dict) -> Dict:
        """
        Analyze email and return score with details
        """
        score = 0
        details = []
        
        # Check each rule
        score += self._check_keywords(email_data['body'], details)
        score += self._check_urgency(email_data['body'], details)
        score += self._check_links(email_data['urls'], details)
        score += self._check_exclamations(email_data['body'], details)
        score += self._check_uppercase(email_data['body'], details)
        score += self._check_sender_spoofing(email_data['sender'], details)
        score += self._check_suspicious_domains(email_data['domains'], details)
        score += self._check_missing_headers(email_data['headers'], details)
        
        # Normalize score to 0-100
        normalized_score = min(100, score * 5)
        
        # Determine verdict
        if normalized_score >= 70:
            verdict = "MALICIOUS"
            confidence = "HIGH"
        elif normalized_score >= 40:
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
    
    def _check_keywords(self, text: str, details: List) -> int:
        """Check for spam/phishing keywords"""
        text_lower = text.lower()
        found = []
        for keyword in self.spam_keywords:
            if keyword.lower() in text_lower:
                found.append(keyword)
        
        if found:
            details.append(f"Found suspicious keywords: {', '.join(found[:3])}")
            return min(15, len(found) * 2)
        return 0
    
    def _check_urgency(self, text: str, details: List) -> int:
        """Check for urgency phrases"""
        text_lower = text.lower()
        found = []
        for phrase in self.urgency_phrases:
            if phrase.lower() in text_lower:
                found.append(phrase)
        
        if found:
            details.append("Contains urgency phrases creating pressure")
            return min(10, len(found) * 2)
        return 0
    
    def _check_links(self, urls: List[str], details: List) -> int:
        """Check link count and quality"""
        if len(urls) == 0:
            return 0
        
        if len(urls) > 5:
            details.append(f"High number of links ({len(urls)})")
            return 10
        elif len(urls) > 2:
            details.append(f"Multiple links present ({len(urls)})")
            return 5
        return 0
    
    def _check_exclamations(self, text: str, details: List) -> int:
        """Check for excessive exclamation marks"""
        count = text.count('!')
        if count > 10:
            details.append(f"Excessive exclamation marks ({count})")
            return 8
        elif count > 5:
            details.append(f"Multiple exclamation marks ({count})")
            return 4
        return 0
    
    def _check_uppercase(self, text: str, details: List) -> int:
        """Check for excessive uppercase words"""
        words = re.findall(r'\b[A-Z]{4,}\b', text)
        if len(words) > 5:
            details.append(f"Excessive uppercase words ({len(words)})")
            return 8
        elif len(words) > 3:
            details.append(f"Multiple uppercase words ({len(words)})")
            return 4
        return 0
    
    def _check_sender_spoofing(self, sender: str, details: List) -> int:
        """Check if sender domain looks spoofed"""
        if not sender:
            return 0
            
        # Extract domain from sender
        parts = sender.split('@')
        if len(parts) != 2:
            return 0
            
        domain = parts[1].lower()
        
        for suspicious in self.suspicious_senders:
            if suspicious in domain and not domain.endswith(suspicious):
                details.append(f"Potential domain spoofing: {domain}")
                return 15
        
        return 0
    
    def _check_suspicious_domains(self, domains: List[str], details: List) -> int:
        """Check for suspicious TLDs"""
        suspicious_count = 0
        for domain in domains:
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    suspicious_count += 1
                    break
        
        if suspicious_count > 0:
            details.append(f"Contains suspicious TLDs: {suspicious_count} domains")
            return min(10, suspicious_count * 3)
        return 0
    
    def _check_missing_headers(self, headers: Dict, details: List) -> int:
        """Check for missing security headers"""
        score = 0
        missing = []
        
        # Check critical headers
        critical_headers = ['received', 'message-id', 'date']
        for header in critical_headers:
            if header not in headers:
                missing.append(header)
        
        # Check authentication headers (look for standard SMTP keys)
        has_spf = any(h in headers for h in ['spf', 'received-spf', 'authentication-results'])
        has_dkim = any(h in headers for h in ['dkim', 'dkim-signature', 'authentication-results'])
        has_dmarc = any(h in headers for h in ['dmarc', 'authentication-results'])
        
        present_count = sum([has_spf, has_dkim, has_dmarc])
        
        if present_count == 0:
            missing.append('all auth headers')
            score += 4  # Reduced from 8 (+20% in normalized score instead of +40%)
            details.append("Missing authentication headers (SPF/DKIM/DMARC)")
        elif present_count < 3:
            score += 2  # Reduced from 4 (+10% in normalized score)
            details.append("Limited authentication headers present")
        
        if missing:
            details.append(f"Missing headers: {', '.join(missing[:3])}")
        
        return score
        