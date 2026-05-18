"""WHOIS API integration."""
import time
from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult

class WhoisAPI(APIKeyAdapter):
    """WHOIS API for domain registration information."""
    BASE_URL = "https://www.whoisxmlapi.com/api/v1"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="whois", api_key=api_key, **kwargs)

    async def domain_lookup(self, domain: str, **kwargs) -> StandardResult:
        """Look up WHOIS information for a domain."""
        start_time = time.time()
        try:
            params = {"apiKey": self.api_key, "domain": domain}
            response = await self.http_get(f"{self.BASE_URL}/whois", params=params)
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=domain, data=[data], success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=domain, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=domain, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
