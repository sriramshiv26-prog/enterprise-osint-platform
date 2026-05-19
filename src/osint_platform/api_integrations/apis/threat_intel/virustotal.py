"""VirusTotal API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class VirusTotalAPI(BearerTokenAdapter):
    """
    VirusTotal API wrapper for threat intelligence.

    Uses Bearer token authentication.
    Rate limit: 4 requests/minute (free tier)
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, **kwargs):
        """Initialize VirusTotal API."""
        super().__init__(
            api_name="virustotal",
            bearer_token=api_key,
            **kwargs,
        )

    async def search_ip(self, ip: str, **kwargs) -> StandardResult:
        """
        Search for IP address in VirusTotal.

        Args:
            ip: IP address to search
            **kwargs: Additional options

        Returns:
            StandardResult with threat info
        """
        start_time = time.time()

        try:
            response = await self.http_get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
            )

            execution_time = time.time() - start_time
            rate_limit_remaining = self._extract_rate_limit(response)

            if response.status_code == 200:
                data = response.json()
                results = self._parse_ip_response(data)

                return self._create_result(
                    query=ip,
                    data=results,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=rate_limit_remaining,
                    response_code=200,
                )
            else:
                error = response.json().get("error", {}).get("message", "Unknown error")
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

    async def search_domain(self, domain: str, **kwargs) -> StandardResult:
        """Search for domain in VirusTotal."""
        start_time = time.time()

        try:
            response = await self.http_get(
                f"{self.BASE_URL}/domains/{domain}",
            )

            execution_time = time.time() - start_time
            rate_limit_remaining = self._extract_rate_limit(response)

            if response.status_code == 200:
                data = response.json()
                results = self._parse_domain_response(data)

                return self._create_result(
                    query=domain,
                    data=results,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=rate_limit_remaining,
                    response_code=200,
                )
            else:
                error = response.json().get("error", {}).get("message", "Unknown error")
                return self._create_result(
                    query=domain,
                    data=[],
                    success=False,
                    error=error,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return self._create_result(
                query=domain,
                data=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    async def search_hash(self, hash_value: str, **kwargs) -> StandardResult:
        """Search for file hash in VirusTotal."""
        start_time = time.time()

        try:
            response = await self.http_get(
                f"{self.BASE_URL}/files/{hash_value}",
            )

            execution_time = time.time() - start_time
            rate_limit_remaining = self._extract_rate_limit(response)

            if response.status_code == 200:
                data = response.json()
                results = self._parse_file_response(data)

                return self._create_result(
                    query=hash_value,
                    data=results,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=rate_limit_remaining,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=hash_value,
                    data=[],
                    success=False,
                    error="Hash not found",
                    execution_time=execution_time,
                    response_code=response.status_code,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return self._create_result(
                query=hash_value,
                data=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    async def search(self, query: str, **kwargs) -> StandardResult:
        """
        Generic search that delegates to specific search methods.

        Args:
            query: IP, domain, hash, or URL to search
            **kwargs: Additional search options

        Returns:
            StandardResult with threat intelligence data
        """
        # Detect query type and delegate to appropriate search method
        if self._is_ip(query):
            return await self.search_ip(query, **kwargs)
        elif self._is_domain(query):
            return await self.search_domain(query, **kwargs)
        elif self._is_hash(query):
            return await self.search_hash(query, **kwargs)
        else:
            # Default to domain search for unknown types
            return await self.search_domain(query, **kwargs)

    def _is_ip(self, query: str) -> bool:
        """Check if query is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(query)
            return True
        except ValueError:
            return False

    def _is_domain(self, query: str) -> bool:
        """Check if query is a domain."""
        return "." in query and not self._is_ip(query) and not self._is_hash(query)

    def _is_hash(self, query: str) -> bool:
        """Check if query is a file hash."""
        return len(query) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in query)

    def _parse_ip_response(self, data: Dict[str, Any]) -> list:
        """Parse IP search response."""
        attributes = data.get("data", {}).get("attributes", {})

        return [{
            "ip": attributes.get("last_dns_records", [{}])[0].get("value"),
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation"),
        }]

    def _parse_domain_response(self, data: Dict[str, Any]) -> list:
        """Parse domain search response."""
        attributes = data.get("data", {}).get("attributes", {})

        return [{
            "domain": attributes.get("last_dns_records", [{}])[0].get("value"),
            "registrar": attributes.get("registrar"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
        }]

    def _parse_file_response(self, data: Dict[str, Any]) -> list:
        """Parse file hash search response."""
        attributes = data.get("data", {}).get("attributes", {})

        return [{
            "sha256": attributes.get("sha256"),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "file_size": attributes.get("size"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "magic": attributes.get("magic"),
            "type_description": attributes.get("type_description"),
        }]

    def _extract_rate_limit(self, response) -> Optional[int]:
        """Extract rate limit info from response headers."""
        try:
            return int(response.headers.get("X-Apiversion-Remaining", -1))
        except (ValueError, TypeError):
            return None
