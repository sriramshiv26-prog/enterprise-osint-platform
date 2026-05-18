"""CommonCrawl API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BaseAdapter
from src.osint_platform.api_integrations.models import StandardResult


class CommonCrawlAPI(BaseAdapter):
    """CommonCrawl for searching indexed web pages."""

    BASE_URL = "https://index.commoncrawl.org"

    def __init__(self, **kwargs):
        super().__init__(api_name="commoncrawl", **kwargs)

    async def search_url(self, url: str, **kwargs) -> StandardResult:
        """Search for URL in CommonCrawl index."""
        start_time = time.time()
        try:
            params = {
                "url": url,
                "output": "json",
                "matchType": "domain",
                "showNumPages": "true",
            }
            response = await self.http_get(
                f"{self.BASE_URL}/query",
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=url,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=url,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=url,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
