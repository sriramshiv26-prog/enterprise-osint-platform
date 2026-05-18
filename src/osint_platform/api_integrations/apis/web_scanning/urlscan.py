"""URLScan.io API integration."""
import time
from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult

class URLScanAPI(APIKeyAdapter):
    """URLScan.io API for web scanning and analysis."""
    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="urlscan", api_key=api_key, **kwargs)

    async def scan_url(self, url: str, **kwargs) -> StandardResult:
        """Scan a URL with URLScan.io."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["API-Key"] = self.api_key
            
            data = {"url": url}
            response = await self.http_post(
                f"{self.BASE_URL}/scan/", json=data, headers=headers
            )
            execution_time = time.time() - start_time

            if response.status_code in [200, 201]:
                result = response.json()
                return self._create_result(
                    query=url, data=[result], success=True,
                    execution_time=execution_time, response_code=response.status_code
                )
            else:
                return self._create_result(
                    query=url, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=url, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
