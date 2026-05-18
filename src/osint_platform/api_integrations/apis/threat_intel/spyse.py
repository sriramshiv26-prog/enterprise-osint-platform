"""Spyse API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class SpyseAPI(BearerTokenAdapter):
    """Spyse for IP, domain, and SSL certificate intelligence."""

    BASE_URL = "https://api.spyse.com/v4"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="spyse", bearer_token=api_key, **kwargs)

    async def search_ip(self, ip: str, **kwargs) -> StandardResult:
        """Search IP in Spyse."""
        start_time = time.time()
        try:
            response = await self.http_get(f"{self.BASE_URL}/data/ip/{ip}")
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

    async def search_domain(self, domain: str, **kwargs) -> StandardResult:
        """Search domain in Spyse."""
        start_time = time.time()
        try:
            response = await self.http_get(f"{self.BASE_URL}/data/domain/{domain}")
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=domain,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=domain,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=domain,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
