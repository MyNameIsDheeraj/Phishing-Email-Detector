import os
os.environ["MOCK_DNS"] = "true"

import unittest
from fastapi.testclient import TestClient
from app.main import app

class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.models.database import init_db
        init_db()
        cls.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
        self.assertEqual(response.json()["database"], "connected")

    def test_stats_endpoint(self):
        response = self.client.get("/dashboard/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_emails", data)
        self.assertIn("verdicts", data)
        self.assertIn("avg_score", data)
        self.assertIn("iocs", data)

    def test_analyze_text_endpoint(self):
        payload = {
            "email_text": "From: test@example.com\nTo: victim@example.com\nSubject: Critical update\n\nClick here immediately http://malicious.top/verify"
        }
        response = self.client.post("/analyze-email", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertIn("verdict", data)
        self.assertIn("threat_score", data)
        self.assertIn("authentication", data)

