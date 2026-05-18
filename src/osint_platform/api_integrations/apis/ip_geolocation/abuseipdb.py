"""AbuseIPDB API integration."""
from typing import Dict, Any
import time
from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult

class AbuseIPDBI(APIKeyAdapter):
    """AbuseIPDB API for IP reputation checking."""
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="abuseipdb", api_key=api_key, **kwargs)

    async def check_ip(self, ip: str, max_age_days: int = 90, **kwargs) -> StandardResult:
        """Check IP reputation in AbuseIPDB."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["Key"] = self.api_key

            params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
            response = await self.http_get(
                f"{self.BASE_URL}/check",
                params=params, headers=headers
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json().get("data", {})
                return self._create_result(
                    query=ip, data=[data], success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=ip, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=ip, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
