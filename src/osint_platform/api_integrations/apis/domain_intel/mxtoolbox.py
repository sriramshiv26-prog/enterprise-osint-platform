"""MXToolbox API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import QueryParamAPIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class MXToolboxAPI(QueryParamAPIKeyAdapter):
    """MXToolbox for MX records, DNS, and email server information."""

    BASE_URL = "https://api.mxtoolbox.com"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="mxtoolbox", api_key=api_key, **kwargs)

    async def lookup_mx(self, domain: str, **kwargs) -> StandardResult:
        """Look up MX records for domain."""
        start_time = time.time()
        try:
            params = {"domain": domain, "api_key": self.api_key}
            response = await self.http_get(
                f"{self.BASE_URL}/api/v1/lookup/mx",
                params=params,
            )
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

    async def lookup_dns(self, domain: str, **kwargs) -> StandardResult:
        """Look up DNS records for domain."""
        start_time = time.time()
        try:
            params = {"domain": domain, "api_key": self.api_key}
            response = await self.http_get(
                f"{self.BASE_URL}/api/v1/lookup/dns",
                params=params,
            )
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
