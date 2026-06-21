import httpx
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio

class VirusTotalService:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = None
    
    async def get_session(self):
        if self.session is None:
            self.session = httpx.AsyncClient(
                headers={"x-apikey": self.api_key},
                timeout=30.0
            )
        return self.session
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a URL using VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            session = await self.get_session()
            
            # Submit URL for scanning
            response = await session.post(
                f"{self.base_url}/urls",
                data={"url": url}
            )
            
            if response.status_code == 200:
                data = response.json()
                # Get analysis ID
                analysis_id = data.get("data", {}).get("id")
                
                if analysis_id:
                    # Get results
                    await asyncio.sleep(2.5)  # Wait for analysis
                    result = await session.get(
                        f"{self.base_url}/analyses/{analysis_id}"
                    )
                    if result.status_code == 200:
                        res_data = result.json()
                        stats = res_data.get("data", {}).get("attributes", {}).get("stats", {})
                        if stats:
                            return {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "harmless": stats.get("harmless", 0),
                                "undetected": stats.get("undetected", 0),
                                "total": sum(stats.values())
                            }
            
            return {"error": "Scan failed", "status": response.status_code}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL reputation report, falling back to scanning if not found"""
        if not self.api_key:
            return {"error": "API key not configured"}
        
        try:
            session = await self.get_session()
            
            # URL must be base64 url-safe encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = await session.get(
                f"{self.base_url}/urls/{url_id}"
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0
                }
            elif response.status_code == 404:
                # URL is not in VirusTotal database, submit it for scan
                return await self.scan_url(url)
            else:
                return {"error": f"URL lookup failed: {response.text}", "status": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file SHA256 reputation report from VirusTotal"""
        if not self.api_key:
            return {"error": "API key not configured"}
            
        try:
            session = await self.get_session()
            response = await session.get(
                f"{self.base_url}/files/{file_hash}"
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0
                }
            else:
                return {"error": f"File hash report fetch failed: {response.text}", "status": response.status_code}
        except Exception as e:
            return {"error": str(e)}

    async def close(self):
        if self.session:
            await self.session.aclose()
