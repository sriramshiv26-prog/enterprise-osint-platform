"""
Sublist3r - Subdomain enumeration tool wrapper.
Finds subdomains using multiple search engines.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import subprocess

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class Sublist3rTool(BaseTool):
    """
    Sublist3r tool for subdomain enumeration.

    Rate Limit: ~10 requests/minute
    Typical execution: 30-120 seconds per domain
    """

    def __init__(self, timeout: int = 120):
        super().__init__("sublist3r", timeout)
        self.rate_limit_per_minute = 10
        self.last_request_time = None
        self.request_count_this_minute = 0

    async def search(
        self,
        domain: str,
        threads: int = 100,
        engines: Optional[List[str]] = None,
        **kwargs,
    ) -> ToolResult:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Target domain (e.g., example.com)
            threads: Number of parallel threads
            engines: Specific search engines (baidu, bing, yahoo, google, etc.)
            **kwargs: Additional options

        Returns:
            ToolResult with found subdomains
        """
        self._current_query = domain

        if not self.validate_query(domain):
            return self._standardize_result(
                data=[],
                success=False,
                error="Invalid domain format",
            )

        try:
            start_time = datetime.utcnow()

            # Respect rate limiting
            await self._respect_rate_limit()

            # Build Sublist3r command
            cmd = [
                "sublist3r",
                "-d", domain,
                "-t", str(threads),
                "-o", f"sublist3r_results_{domain}.txt",
            ]

            if engines:
                cmd.extend(["-e", ",".join(engines)])

            if kwargs.get("verbosity"):
                cmd.append("-v")

            # Execute Sublist3r
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            if result.returncode == 0 or "found" in result.stdout.lower():
                subdomains = self._parse_subdomains(result.stdout)
                logger.info(f"Sublist3r found {len(subdomains)} subdomains for '{domain}'")

                return self._standardize_result(
                    data=subdomains,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=self._calculate_remaining_requests(),
                )
            else:
                return self._standardize_result(
                    data=[],
                    success=False,
                    error=f"Sublist3r error: {result.stderr}",
                    execution_time=execution_time,
                )

        except subprocess.TimeoutExpired:
            return self._standardize_result(
                data=[],
                success=False,
                error=f"Sublist3r timeout after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"Sublist3r search failed: {e}")
            return self._standardize_result(
                data=[],
                success=False,
                error=str(e),
            )

    def _parse_subdomains(self, output: str) -> List[Dict[str, Any]]:
        """Parse Sublist3r output into standardized format."""
        subdomains = []
        seen = set()

        # Parse output lines
        for line in output.split('\n'):
            line = line.strip()
            if line and '.' in line and not line.startswith('['):
                # Extract subdomain
                subdomain = line.split(':')[-1].strip() if ':' in line else line

                if subdomain and subdomain not in seen:
                    seen.add(subdomain)
                    subdomains.append({
                        "subdomain": subdomain,
                        "status": "found",
                        "source": "sublist3r",
                    })

        return subdomains

    async def _respect_rate_limit(self):
        """Enforce rate limiting (10 requests/minute)."""
        now = datetime.utcnow()

        if self.last_request_time:
            # Reset counter if minute has passed
            if (now - self.last_request_time).total_seconds() > 60:
                self.request_count_this_minute = 0

            # Check if we're at limit
            if self.request_count_this_minute >= self.rate_limit_per_minute:
                sleep_time = 60 - (now - self.last_request_time).total_seconds()
                if sleep_time > 0:
                    logger.warning(f"Rate limit approaching, sleeping {sleep_time:.1f}s")
                    await asyncio.sleep(sleep_time)
                self.request_count_this_minute = 0

        self.last_request_time = now
        self.request_count_this_minute += 1

    def _calculate_remaining_requests(self) -> Optional[int]:
        """Calculate remaining requests in current minute."""
        return max(0, self.rate_limit_per_minute - self.request_count_this_minute)

    def validate_query(self, domain: str) -> bool:
        """Validate domain format."""
        if not super().validate_query(domain):
            return False

        # Basic domain validation
        parts = domain.split('.')
        if len(parts) < 2:
            return False

        # Check valid TLD
        return all(part.isalnum() or '-' in part for part in parts)
