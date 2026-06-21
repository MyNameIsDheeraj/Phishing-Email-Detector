import os
import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.mesa_security import MesaSecurityService


class TestMesaSecurityService(unittest.TestCase):
    """Test suite for Mesa Security Service"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        os.environ["MESA_SECURITY_API_KEY"] = "mapi_test_key_12345"
        cls.service = MesaSecurityService()
    
    def test_service_initialization(self):
        """Test that Mesa service initializes correctly"""
        self.assertIsNotNone(self.service)
        self.assertEqual(self.service.api_key, "mapi_test_key_12345")
        self.assertEqual(self.service.base_url, "https://scan.mesasecurity.com/api/v1")
    
    def test_missing_api_key(self):
        """Test that missing API key returns error"""
        with patch.dict(os.environ, {"MESA_SECURITY_API_KEY": ""}):
            service = MesaSecurityService()
            result = asyncio.run(service.scan_email(b"test email"))
            self.assertIn("error", result)
            self.assertEqual(result["error"], "Mesa Security API key not configured")
    
    @patch('app.services.mesa_security.httpx.AsyncClient')
    def test_scan_email_success(self, mock_client):
        """Test successful email scanning"""
        # Mock the POST response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "job_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "pending",
            "message": "File uploaded successfully"
        }
        
        # Mock the GET response (for polling)
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "job_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "completed",
            "file_name": "email.eml",
            "file_size": 1024,
            "created_at": "2023-01-01T12:00:00Z",
            "result": {
                "verdict": "clean",
                "threat_score": 0
            }
        }
        mock_get_response.headers = {
            "X-RateLimit-Limit": "50",
            "X-RateLimit-Remaining": "49",
            "X-RateLimit-Reset": "2023-01-02T00:00:00Z"
        }
        
        # Configure mock
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.get = AsyncMock(return_value=mock_get_response)
        
        # Replace service session
        self.service.session = mock_session
        
        result = asyncio.run(self.service.scan_email(
            b"test email content",
            filename="test.eml"
        ))
        
        self.assertNotIn("error", result)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["job_id"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(result["result"]["verdict"], "clean")
    
    @patch('app.services.mesa_security.httpx.AsyncClient')
    def test_scan_email_malicious(self, mock_client):
        """Test email flagged as malicious"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "job_id": "test-job-id",
            "status": "pending"
        }
        
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "job_id": "test-job-id",
            "status": "completed",
            "file_name": "email.eml",
            "file_size": 2048,
            "created_at": "2023-01-01T12:00:00Z",
            "result": {
                "verdict": "phishing",
                "threat_score": 85,
                "details": {
                    "phishing_indicators": ["suspicious_links", "spoofed_sender"]
                }
            }
        }
        mock_get_response.headers = {
            "X-RateLimit-Limit": "50",
            "X-RateLimit-Remaining": "48",
            "X-RateLimit-Reset": "2023-01-02T00:00:00Z"
        }
        
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.get = AsyncMock(return_value=mock_get_response)
        self.service.session = mock_session
        
        result = asyncio.run(self.service.scan_email(b"malicious email"))
        
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["result"]["verdict"], "phishing")
        self.assertEqual(result["result"]["threat_score"], 85)
    
    @patch('app.services.mesa_security.httpx.AsyncClient')
    def test_scan_email_failed_submission(self, mock_client):
        """Test failed email submission"""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid file format"
        mock_response.json.side_effect = Exception("Not JSON")
        
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        self.service.session = mock_session
        
        result = asyncio.run(self.service.scan_email(b"invalid email"))
        
        self.assertIn("error", result)
        self.assertEqual(result["status"], 400)
    
    @patch('app.services.mesa_security.httpx.AsyncClient')
    def test_get_job_status(self, mock_client):
        """Test getting job status"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "job_id": "test-job-id",
            "status": "completed",
            "file_name": "email.eml",
            "file_size": 1024,
            "created_at": "2023-01-01T12:00:00Z",
            "result": {"verdict": "clean"}
        }
        mock_response.headers = {
            "X-RateLimit-Limit": "50",
            "X-RateLimit-Remaining": "48",
            "X-RateLimit-Reset": "2023-01-02T00:00:00Z"
        }
        
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_response)
        self.service.session = mock_session
        
        result = asyncio.run(self.service.get_job_status("test-job-id"))
        
        self.assertEqual(result["job_id"], "test-job-id")
        self.assertEqual(result["status"], "completed")
    
    def test_close_session(self):
        """Test closing the session"""
        async def test_async():
            await self.service.close()
        
        # Should not raise an error
        asyncio.run(test_async())


if __name__ == "__main__":
    unittest.main()
