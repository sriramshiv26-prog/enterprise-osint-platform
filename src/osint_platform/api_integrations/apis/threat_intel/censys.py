"""Censys API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class CensysAPI(BearerTokenAdapter):
    """Censys API for IP and certificate intelligence."""

    BASE_URL = "https://api.censys.io/v2"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="censys", bearer_token=api_key, **kwargs)

    async def search_ip(self, ip: str, **kwargs) -> StandardResult:
        """Search for IP address in Censys."""
        start_time = time.time()
        try:
            response = await self.http_get(f"{self.BASE_URL}/ip/{ip}")
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

    async def search_certificate(self, cert_id: str, **kwargs) -> StandardResult:
        """Search for certificate in Censys."""
        start_time = time.time()
        try:
            response = await self.http_get(
                f"{self.BASE_URL}/certificates/{cert_id}"
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=cert_id,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=cert_id,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=cert_id,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
