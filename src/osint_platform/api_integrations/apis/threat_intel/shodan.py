"""Shodan API integration."""
from typing import Dict, Any, Optional
from datetime import datetime
import time

from src.osint_platform.api_integrations.adapters import QueryParamAPIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class ShodanAPI(QueryParamAPIKeyAdapter):
    """
    Shodan API wrapper for threat intelligence.

    Uses query parameter API key authentication.
    Rate limit: 1 request/second (paid tier)
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str, **kwargs):
        """Initialize Shodan API."""
        super().__init__(
            api_name="shodan",
            api_key=api_key,
            param_name="key",
            **kwargs,
        )

    async def search(self, query: str, page: int = 1, **kwargs) -> StandardResult:
        """
        Search Shodan for vulnerable hosts.

        Args:
            query: Shodan query (e.g., "apache 2.4.1")
            page: Results page
            **kwargs: Additional params (limit, etc.)

        Returns:
            StandardResult with found hosts
        """
        start_time = time.time()
        self._current_query = query

        try:
            params = self.add_api_key_param({
                "q": query,
                "page": page,
                "limit": kwargs.get("limit", 100),
            })

            response = await self.http_get(
                f"{self.BASE_URL}/shodan/host/search",
                params=params,
            )

            execution_time = time.time() - start_time
            rate_limit_remaining = self._extract_rate_limit(response)

            if response.status_code == 200:
                data = response.json()
                results = self._parse_shodan_results(data)

                return self._create_result(
                    query=query,
                    data=results,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=rate_limit_remaining,
                    response_code=200,
                )
            else:
                error = response.json().get("error", "Unknown error")
                return self._create_result(
                    query=query,
                    data=[],
                    success=False,
                    error=error,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return self._create_result(
                query=query,
                data=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    async def host_info(self, ip: str, **kwargs) -> StandardResult:
        """Get detailed info about a specific host."""
        start_time = time.time()

        try:
            params = self.add_api_key_param({})

            response = await self.http_get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params=params,
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
                error = response.json().get("error", "Host not found")
                return self._create_result(
                    query=ip,
                    data=[],
                    success=False,
                    error=error,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return self._create_result(
                query=ip,
                data=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    def _parse_shodan_results(self, data: Dict[str, Any]) -> list:
        """Parse Shodan search results into standard format."""
        results = []

        for match in data.get("matches", []):
            results.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "hostname": match.get("hostnames", [None])[0],
                "org": match.get("org"),
                "os": match.get("os"),
                "product": match.get("product"),
                "data": match.get("data", ""),
                "last_update": match.get("_shodan", {}).get("last_update"),
            })

        return results

    def _extract_rate_limit(self, response) -> Optional[int]:
        """Extract rate limit info from response headers."""
        try:
            return int(response.headers.get("X-Rate-Limit-Remaining", -1))
        except (ValueError, TypeError):
            return None
