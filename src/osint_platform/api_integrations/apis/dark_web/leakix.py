"""LeakIX API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class LeakIXAPI(BearerTokenAdapter):
    """LeakIX for leaked data, dark web, and breach intelligence."""

    BASE_URL = "https://api.leakix.net"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="leakix", bearer_token=api_key, **kwargs)

    async def search(self, query: str, **kwargs) -> StandardResult:
        """Search LeakIX for leaked information."""
        start_time = time.time()
        try:
            params = {"q": query}
            response = await self.http_get(
                f"{self.BASE_URL}/search",
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=query,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=query,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=query,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def search_ip(self, ip: str, **kwargs) -> StandardResult:
        """Search for IP in LeakIX."""
        return await self.search(ip, **kwargs)

    async def search_domain(self, domain: str, **kwargs) -> StandardResult:
        """Search for domain in LeakIX."""
        return await self.search(domain, **kwargs)
