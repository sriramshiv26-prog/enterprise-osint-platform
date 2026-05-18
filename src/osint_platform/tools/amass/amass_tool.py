"""
Amass - Asset discovery and reconnaissance tool wrapper.
Performs network enumeration and asset discovery.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
import subprocess
import json

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class AmassTool(BaseTool):
    """
    Amass tool for comprehensive asset discovery and reconnaissance.

    Rate Limit: ~100 requests/hour (depends on data sources)
    Typical execution: 30-300 seconds depending on domain size
    """

    def __init__(self, timeout: int = 300):
        super().__init__("amass", timeout)
        self.rate_limit_per_hour = 100
        self.last_request_time = None
        self.request_times = []

    async def search(
        self,
        domain: str,
        intel_sources: bool = True,
        active_enum: bool = False,
        brute_force: bool = False,
        **kwargs,
    ) -> ToolResult:
        """
        Perform comprehensive asset discovery.

        Args:
            domain: Target domain
            intel_sources: Use public Intel sources
            active_enum: Enable active enumeration (slower, noisier)
            brute_force: Enable brute force enumeration
            **kwargs: Additional options

        Returns:
            ToolResult with discovered assets
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

            # Build Amass command
            cmd = [
                "amass",
                "enum",
                "-d", domain,
                "-json", f"amass_results_{domain}.json",
            ]

            if intel_sources:
                cmd.append("-intel")

            if active_enum:
                cmd.append("-active")

            if brute_force:
                cmd.append("-brute")

            if kwargs.get("max_dns_queries"):
                cmd.extend(["-max-dns-queries", str(kwargs["max_dns_queries"])])

            # Execute Amass
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            if result.returncode == 0:
                assets = self._parse_amass_output(result.stdout)
                logger.info(f"Amass discovered {len(assets)} assets for '{domain}'")

                return self._standardize_result(
                    data=assets,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=self._calculate_remaining_requests(),
                )
            else:
                return self._standardize_result(
                    data=[],
                    success=False,
                    error=f"Amass error: {result.stderr}",
                    execution_time=execution_time,
                )

        except subprocess.TimeoutExpired:
            return self._standardize_result(
                data=[],
                success=False,
                error=f"Amass timeout after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"Amass search failed: {e}")
            return self._standardize_result(
                data=[],
                success=False,
                error=str(e),
            )

    def _parse_amass_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Amass JSON output into standardized format."""
        assets = []

        try:
            for line in output.split('\n'):
                if line.strip():
                    data = json.loads(line)

                    # Extract relevant fields
                    asset = {
                        "name": data.get("name", ""),
                        "type": data.get("type", "domain"),
                        "tag": data.get("tag", ""),
                        "source": data.get("source", ""),
                        "address": data.get("address", ""),
                        "addresses": data.get("addresses", []),
                        "metadata": data,
                    }

                    if asset["name"]:
                        assets.append(asset)

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse Amass output: {e}")

        return assets

    async def _respect_rate_limit(self):
        """Enforce rate limiting (100 requests/hour)."""
        now = datetime.utcnow()

        # Remove requests older than 1 hour
        self.request_times = [
            t for t in self.request_times
            if (now - t).total_seconds() < 3600
        ]

        # Check if at limit
        if len(self.request_times) >= self.rate_limit_per_hour:
            oldest_request = min(self.request_times)
            sleep_time = 3600 - (now - oldest_request).total_seconds()
            if sleep_time > 0:
                logger.warning(f"Rate limit reached, sleeping {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)
            self.request_times = []

        self.request_times.append(now)

    def _calculate_remaining_requests(self) -> Optional[int]:
        """Calculate remaining requests in current hour."""
        return max(0, self.rate_limit_per_hour - len(self.request_times))

    def validate_query(self, domain: str) -> bool:
        """Validate domain format."""
        if not super().validate_query(domain):
            return False

        parts = domain.split('.')
        if len(parts) < 2:
            return False

        return all(part.isalnum() or '-' in part for part in parts)
