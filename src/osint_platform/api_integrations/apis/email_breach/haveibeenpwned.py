"""HaveIBeenPwned API integration."""
from typing import Dict, Any
import time
from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult

class HaveIBeenPwnedAPI(APIKeyAdapter):
    """HIBP API for checking email breaches."""
    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(
            api_name="haveibeenpwned", api_key=api_key,
            header_name="User-Agent", key_prefix="", **kwargs
        )
        self.api_key_header = api_key

    async def check_email(self, email: str, **kwargs) -> StandardResult:
        """Check if email has been in a breach."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["hibp-api-key"] = self.api_key_header
            response = await self.http_get(
                f"{self.BASE_URL}/breachedaccount/{email}",
                headers=headers
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                breaches = response.json()
                return self._create_result(
                    query=email, data=breaches, success=True,
                    execution_time=execution_time, response_code=200
                )
            elif response.status_code == 404:
                return self._create_result(
                    query=email, data=[], success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=email, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=email, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
