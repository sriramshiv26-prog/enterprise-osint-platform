"""SecurityTrails API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class SecurityTrailsAPI(BearerTokenAdapter):
    """SecurityTrails API for domain and DNS intelligence."""

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="securitytrails", bearer_token=api_key, **kwargs)

    async def domain_info(self, domain: str, **kwargs) -> StandardResult:
        """Get domain information and DNS records."""
        start_time = time.time()
        try:
            response = await self.http_get(f"{self.BASE_URL}/domain/{domain}")
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=domain, data=[data], success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=domain, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=domain, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )

    async def subdomain_enum(self, domain: str, **kwargs) -> StandardResult:
        """Enumerate subdomains for a domain."""
        start_time = time.time()
        try:
            response = await self.http_get(
                f"{self.BASE_URL}/domain/{domain}/subdomains"
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                subdomains = [{"subdomain": s} for s in data.get("subdomains", [])]
                return self._create_result(
                    query=domain, data=subdomains, success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=domain, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=domain, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
