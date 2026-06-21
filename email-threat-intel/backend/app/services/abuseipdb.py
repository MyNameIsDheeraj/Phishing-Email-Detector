import httpx
import os
from typing import Dict, Any

class AbuseIPDBService:
    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = None
    
    async def get_session(self):
        if self.session is None:
            self.session = httpx.AsyncClient(
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=30.0
            )
        return self.session
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        try:
            session = await self.get_session()
            
            response = await session.get(
                f"{self.base_url}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                return {
                    "abuse_score": abuse_score,
                    "is_malicious": abuse_score > 50,
                    "country": data.get("data", {}).get("countryCode"),
                    "reports": data.get("data", {}).get("totalReports", 0),
                    "isp": data.get("data", {}).get("isp")
                }
            else:
                return {"error": f"AbuseIPDB check failed: {response.text}", "status": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}

    async def close(self):
        if self.session:
            await self.session.aclose()