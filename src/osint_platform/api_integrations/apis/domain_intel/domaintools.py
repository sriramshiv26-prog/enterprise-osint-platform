"""DomainTools API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class DomainToolsAPI(APIKeyAdapter):
    """DomainTools API for domain intelligence and WHOIS data."""

    BASE_URL = "https://api.domaintools.com"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(
            api_name="domaintools",
            api_key=api_key,
            header_name="Authorization",
            key_prefix="",
            **kwargs,
        )

    async def get_whois(self, domain: str, **kwargs) -> StandardResult:
        """Get WHOIS information for domain."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["Authorization"] = f"Bearer {self.api_key}"
            response = await self.http_get(
                f"{self.BASE_URL}/v1/{domain}/whois",
                headers=headers,
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

    async def get_dns_records(self, domain: str, **kwargs) -> StandardResult:
        """Get DNS records for domain."""
        start_time = time.time()
        try:
            headers = self._get_headers()
            headers["Authorization"] = f"Bearer {self.api_key}"
            response = await self.http_get(
                f"{self.BASE_URL}/v1/{domain}/dns",
                headers=headers,
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
