import httpx
import os
import asyncio
import io
from typing import Optional, Dict, Any
from datetime import datetime

class MesaSecurityService:
    """Mesa Security Email Scanning API Service
    
    Scans emails for phishing, malware, spam, and other threats
    using Mesa Security's advanced threat detection engine.
    """
    
    def __init__(self):
        self.api_key = os.getenv("MESA_SECURITY_API_KEY")
        self.base_url = "https://scan.mesasecurity.com/api/v1"
        self.session = None
        self.max_retries = 30  # Max attempts to check job status (30 * 2 = 60 seconds)
        self.retry_delay = 2  # Wait 2 seconds between status checks
    
    async def get_session(self):
        """Get or create async HTTP client session"""
        if self.session is None:
            self.session = httpx.AsyncClient(
                headers={"x-api-key": self.api_key},
                timeout=60.0
            )
        return self.session
    
    async def scan_email(
        self, 
        email_content: bytes, 
        filename: str = "email.eml",
        save_screenshot: bool = True,
        save_email: bool = False
    ) -> Dict[str, Any]:
        """
        Upload and scan an email file using Mesa Security API
        
        Args:
            email_content: Raw email bytes
            filename: Email filename (default: email.eml)
            save_screenshot: Whether to save email screenshot
            save_email: Whether to save email content
            
        Returns:
            Dict containing scan results or error information
        """
        if not self.api_key:
            return {"error": "Mesa Security API key not configured"}
        
        try:
            session = await self.get_session()
            
            # Prepare file upload
            files = {
                "file": (filename, io.BytesIO(email_content), "message/rfc822"),
            }
            data = {
                "save_screenshot": "true" if save_screenshot else "false",
                "save_email": "true" if save_email else "false"
            }
            
            # Submit email for scanning
            response = await session.post(
                f"{self.base_url}/scan",
                files=files,
                data=data
            )
            
            if response.status_code == 200:
                result = response.json()
                job_id = result.get("job_id")
                
                if job_id:
                    # Poll for results
                    return await self._poll_job_status(job_id)
                else:
                    return {
                        "error": "No job ID returned",
                        "response": result
                    }
            else:
                error_msg = response.text
                try:
                    error_json = response.json()
                    error_msg = error_json.get("message", error_msg)
                except:
                    pass
                
                return {
                    "error": f"Scan submission failed",
                    "status": response.status_code,
                    "message": error_msg
                }
                
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}
    
    async def _poll_job_status(
        self, 
        job_id: str,
        max_retries: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Poll job status until completion or timeout
        
        Args:
            job_id: Mesa Security job ID
            max_retries: Maximum polling attempts (default: instance setting)
            
        Returns:
            Dict containing final job status and results
        """
        if max_retries is None:
            max_retries = self.max_retries
        
        try:
            session = await self.get_session()
            
            for attempt in range(max_retries):
                response = await session.get(
                    f"{self.base_url}/jobs/{job_id}"
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("status")
                    
                    # Check rate limit headers
                    rate_limit_info = {
                        "rate_limit": response.headers.get("X-RateLimit-Limit"),
                        "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                        "rate_limit_reset": response.headers.get("X-RateLimit-Reset")
                    }
                    
                    if status == "completed":
                        return {
                            "job_id": job_id,
                            "status": status,
                            "file_name": data.get("file_name"),
                            "file_size": data.get("file_size"),
                            "created_at": data.get("created_at"),
                            "result": data.get("result", {}),
                            "rate_limit": rate_limit_info
                        }
                    elif status == "failed":
                        return {
                            "error": "Mesa Security scan failed",
                            "job_id": job_id,
                            "status": status,
                            "result": data.get("result", {}),
                            "rate_limit": rate_limit_info
                        }
                    elif status == "pending":
                        # Not ready yet, wait and retry
                        await asyncio.sleep(self.retry_delay)
                        continue
                    else:
                        return {
                            "job_id": job_id,
                            "status": status,
                            "result": data.get("result", {}),
                            "rate_limit": rate_limit_info
                        }
                else:
                    return {
                        "error": f"Failed to get job status",
                        "status": response.status_code,
                        "job_id": job_id
                    }
            
            # Timeout after max retries
            return {
                "error": "Job status check timed out",
                "job_id": job_id,
                "status": "timeout",
                "message": f"No result after {max_retries} attempts"
            }
            
        except Exception as e:
            return {
                "error": f"Status polling failed: {str(e)}",
                "job_id": job_id
            }
    
    async def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get current status of a specific job without polling
        
        Args:
            job_id: Mesa Security job ID
            
        Returns:
            Dict containing current job status
        """
        if not self.api_key:
            return {"error": "API key not configured"}
        
        try:
            session = await self.get_session()
            
            response = await session.get(
                f"{self.base_url}/jobs/{job_id}"
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "job_id": job_id,
                    "status": data.get("status"),
                    "file_name": data.get("file_name"),
                    "file_size": data.get("file_size"),
                    "created_at": data.get("created_at"),
                    "result": data.get("result", {}),
                    "rate_limit": {
                        "rate_limit": response.headers.get("X-RateLimit-Limit"),
                        "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                        "rate_limit_reset": response.headers.get("X-RateLimit-Reset")
                    }
                }
            else:
                return {
                    "error": f"Failed to get job status: {response.text}",
                    "status": response.status_code
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.aclose()
