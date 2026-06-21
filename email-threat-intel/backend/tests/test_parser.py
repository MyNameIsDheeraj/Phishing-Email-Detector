import os
os.environ["MOCK_DNS"] = "true"

import unittest
from app.core.parser import EmailParser
from app.core.rules import RuleBasedDetector

class TestEmailParser(unittest.TestCase):
    def test_parse_email(self):
        raw_email = """From: sender@test.com
To: receiver@test.com
Subject: Test Email
Date: Wed, 20 Dec 2023 10:00:00 +0000

This is a test email body with a link http://test.com"""
        
        parser = EmailParser(raw_email)
        
        self.assertEqual(parser.get_sender(), "sender@test.com")
        self.assertEqual(parser.get_subject(), "Test Email")
        self.assertTrue("test email body" in parser.get_body().lower())
        self.assertEqual(parser.extract_urls(), ["http://test.com"])
    
    def test_rule_detector(self):
        email_data = {
            'sender': 'support@paypal-secure.com',
            'subject': 'URGENT: Your Account Will Be Suspended',
            'body': '!!! Congratulations!!! You won free money! Click here: http://suspicious.tk/verify',
            'headers': {'received': 'from spam-server.com'},
            'urls': ['http://suspicious.tk/verify'],
            'domains': ['suspicious.tk']
        }
        
        detector = RuleBasedDetector()
        result = detector.analyze(email_data)
        
        self.assertGreater(result['score'], 50)
        self.assertIn('MALICIOUS', result['verdict'])
        self.assertTrue(len(result['details']) > 0)

    def test_parse_attachments(self):
        raw_email = """From: sender@test.com
To: receiver@test.com
Subject: Test Email with Attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary-string"

--boundary-string
Content-Type: text/plain

This is a test email body.
--boundary-string
Content-Type: text/plain; name="test_attachment.txt"
Content-Disposition: attachment; filename="test_attachment.txt"
Content-Transfer-Encoding: base64

SGVsbG8gV29ybGQh
--boundary-string--"""
        parser = EmailParser(raw_email)
        attachments = parser.extract_attachments()
        
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['filename'], "test_attachment.txt")
        self.assertEqual(attachments[0]['content'], b"Hello World!")
        import hashlib
        self.assertEqual(attachments[0]['sha256'], hashlib.sha256(b"Hello World!").hexdigest())

    def test_auth_checks(self):
        from app.core.auth_checks import validate_spf, validate_dkim, validate_dmarc, check_spamhaus
        
        # Test mock domain validation
        self.assertEqual(validate_spf("1.2.3.4", "sender@test.com"), "PASS")
        self.assertEqual(validate_spf("1.2.3.4", "sender@paypal-secure.com"), "FAIL")
        
        # Test mock DKIM validation
        self.assertEqual(validate_dkim(b"raw bytes", "test.com"), "PASS")
        self.assertEqual(validate_dkim(b"raw bytes", "paypal-secure.com"), "FAIL")
        
        # Test mock DMARC validation
        self.assertEqual(validate_dmarc("test.com", "PASS", "PASS"), "PASS")
        self.assertEqual(validate_dmarc("paypal-secure.com", "FAIL", "FAIL"), "FAIL")
        
        # Test mock Spamhaus validation
        self.assertTrue(check_spamhaus("1.2.3.4"))
        self.assertFalse(check_spamhaus("127.0.0.1"))

    def test_new_heuristic_rules(self):
        detector = RuleBasedDetector()
        
        # Test 1: Brand misuse in free email local part
        email_data_1 = {
            'sender': 'paypal-support@gmail.com',
            'subject': 'Alert',
            'body': 'Hello',
            'headers': {'from': 'paypal-support@gmail.com'},
            'urls': [],
            'domains': []
        }
        res1 = detector.analyze(email_data_1)
        self.assertIn("Brand 'paypal' misused in free email local part", "".join(res1['details']))
        
        # Test 2: Display name spoofing
        email_data_2 = {
            'sender': 'attacker@scam-mail.com',
            'subject': 'Alert',
            'body': 'Hello',
            'headers': {'from': 'PayPal Support <attacker@scam-mail.com>'},
            'urls': [],
            'domains': ['scam-mail.com']
        }
        res2 = detector.analyze(email_data_2)
        self.assertIn("Brand 'paypal' in display name doesn't match sender domain", "".join(res2['details']))
        
        # Test 3: Link shorteners
        email_data_3 = {
            'sender': 'test@test.com',
            'subject': 'Check this',
            'body': 'Link: http://bit.ly/12345',
            'headers': {},
            'urls': ['http://bit.ly/12345'],
            'domains': ['bit.ly']
        }
        res3 = detector.analyze(email_data_3)
        self.assertIn("Uses link shortener: bit.ly", "".join(res3['details']))
        
        # Test 4: Raw IP URL
        email_data_4 = {
            'sender': 'test@test.com',
            'subject': 'Check this',
            'body': 'Link: http://192.168.1.1/verify',
            'headers': {},
            'urls': ['http://192.168.1.1/verify'],
            'domains': []
        }
        res4 = detector.analyze(email_data_4)
        self.assertIn("URL uses raw IP address", "".join(res4['details']))

        # Test 5: IDN homograph domain
        email_data_5 = {
            'sender': 'test@test.com',
            'subject': 'Check this',
            'body': 'Link: http://xn--pypal-43d.com/login',
            'headers': {},
            'urls': ['http://xn--pypal-43d.com/login'],
            'domains': ['xn--pypal-43d.com']
        }
        res5 = detector.analyze(email_data_5)
        self.assertIn("Detected potential IDN homograph domain spoofing", "".join(res5['details']))

    def test_pdf_report_generation(self):
        from app.services.report_generator import generate_pdf_report
        
        email_data = {
            "id": 123,
            "sender": "sender@test.com",
            "sender_domain": "test.com",
            "subject": "Test Security Phishing Alert",
            "verdict": "MALICIOUS",
            "threat_score": 85,
            "rule_score": 60,
            "confidence": "HIGH",
            "received_at": "2026-06-20 12:00:00",
            "spf_status": "PASS",
            "dkim_status": "FAIL",
            "dmarc_status": "FAIL",
            "urls": [
                {"url": "http://phishing.com/login", "domain": "phishing.com", "vt_score": 75, "is_phishing": True}
            ],
            "ips": [
                {"ip": "1.2.3.4", "abuse_score": 90, "spamhaus_flagged": True, "is_malicious": True}
            ],
            "attachments": [
                {"file_name": "malware.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "vt_score": 80}
            ],
            "timeline": [
                {"timestamp": "2026-06-20 12:00:00", "event_type": "RECEIVED", "severity": "INFO", "description": "Email received"},
                {"timestamp": "2026-06-20 12:01:00", "event_type": "VT_URL_SCAN", "severity": "WARNING", "description": "Malicious URL detected"}
            ],
            "rule_details": ["Found suspicious keywords", "Urgent action requested"]
        }
        
        pdf_bytes = generate_pdf_report(email_data)
        self.assertGreater(len(pdf_bytes), 1000)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

if __name__ == '__main__':
    unittest.main()
    