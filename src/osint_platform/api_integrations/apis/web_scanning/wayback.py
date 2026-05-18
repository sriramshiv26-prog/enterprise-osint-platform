"""Wayback Machine API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BaseAdapter
from src.osint_platform.api_integrations.models import StandardResult


class WaybackMachineAPI(BaseAdapter):
    """Wayback Machine for historical website snapshots."""

    BASE_URL = "https://archive.org/wayback/available"

    def __init__(self, **kwargs):
        super().__init__(api_name="wayback_machine", **kwargs)

    async def get_snapshots(self, url: str, **kwargs) -> StandardResult:
        """Get available snapshots for a URL."""
        start_time = time.time()
        try:
            params = {"url": url}
            response = await self.http_get(
                self.BASE_URL,
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
