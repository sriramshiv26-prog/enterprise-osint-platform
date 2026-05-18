"""IntelX API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class IntelXAPI(APIKeyAdapter):
    """IntelX for search in leaked data, dark web, and general OSINT."""

    BASE_URL = "https://2.intelx.io"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="intelx", api_key=api_key, **kwargs)

    async def search(self, query: str, search_type: str = "email", **kwargs) -> StandardResult:
        """Search IntelX database."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["x-key"] = self.api_key
            params = {"q": query, "type": search_type}
            response = await self.http_get(
                f"{self.BASE_URL}/intelligent/search",
                params=params,
                headers=headers,
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
