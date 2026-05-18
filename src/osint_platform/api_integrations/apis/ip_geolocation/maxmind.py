"""MaxMind GeoIP2 API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class MaxMindAPI(APIKeyAdapter):
    """MaxMind GeoIP2 for IP geolocation and threat data."""

    BASE_URL = "https://geoip.maxmind.com/geoip/v2.1"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(
            api_name="maxmind",
            api_key=api_key,
            header_name="Authorization",
            key_prefix="",
            **kwargs,
        )

    async def lookup_ip(self, ip: str, **kwargs) -> StandardResult:
        """Look up IP geolocation data."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["Authorization"] = f"Basic {self.api_key}"
            response = await self.http_get(
                f"{self.BASE_URL}/country/{ip}",
                headers=headers,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=ip,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=ip,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=ip,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
