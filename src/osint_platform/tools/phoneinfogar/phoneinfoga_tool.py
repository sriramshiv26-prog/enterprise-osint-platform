"""
PhoneInfoga - Phone number OSINT tool wrapper.
Gathers information about phone numbers from multiple sources.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
import subprocess
import json

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class PhoneInfogaTool(BaseTool):
    """
    PhoneInfoga tool for phone number reconnaissance.

    Rate Limit: ~30 requests/minute
    Typical execution: 5-15 seconds per number
    """

    def __init__(self, timeout: int = 30):
        super().__init__("phoneinfoga", timeout)
        self.rate_limit_per_minute = 30
        self.last_request_time = None
        self.request_count_this_minute = 0

    async def search(
        self,
        phone_number: str,
        country_code: Optional[str] = None,
        scan_osint: bool = True,
        **kwargs,
    ) -> ToolResult:
        """
        Gather information about a phone number.

        Args:
            phone_number: Phone number to search (international format)
            country_code: Country code (optional)
            scan_osint: Enable OSINT scanning
            **kwargs: Additional options

        Returns:
            ToolResult with phone information
        """
        self._current_query = phone_number

        if not self.validate_query(phone_number):
            return self._standardize_result(
                data=[],
                success=False,
                error="Invalid phone number format",
            )

        try:
            start_time = datetime.utcnow()

            # Respect rate limiting
            await self._respect_rate_limit()

            # Build PhoneInfoga command
            cmd = [
                "phoneinfoga",
                "scan",
                "-n", phone_number,
                "--json",
            ]

            if country_code:
                cmd.extend(["-c", country_code])

            if scan_osint:
                cmd.append("--scan-osint")

            if kwargs.get("disable_recon"):
                cmd.append("--disable-local-recon")

            # Execute PhoneInfoga
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            if result.returncode == 0:
                phone_info = self._parse_phoneinfoga_output(result.stdout)
                logger.info(f"PhoneInfoga gathered data for '{phone_number}'")

                return self._standardize_result(
                    data=phone_info,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=self._calculate_remaining_requests(),
                )
            else:
                return self._standardize_result(
                    data=[],
                    success=False,
                    error=f"PhoneInfoga error: {result.stderr}",
                    execution_time=execution_time,
                )

        except subprocess.TimeoutExpired:
            return self._standardize_result(
                data=[],
                success=False,
                error=f"PhoneInfoga timeout after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"PhoneInfoga search failed: {e}")
            return self._standardize_result(
                data=[],
                success=False,
                error=str(e),
            )

    def _parse_phoneinfoga_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse PhoneInfoga JSON output into standardized format."""
        results = []

        try:
            data = json.loads(output)

            # Extract phone information
            phone_info = {
                "number": data.get("number", ""),
                "country": data.get("country", ""),
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", ""),
                "is_valid": data.get("is_valid", False),
                "is_possible": data.get("is_possible", False),
                "location": data.get("location", ""),
                "osint": data.get("osint", []),
                "metadata": data,
            }

            if phone_info["number"]:
                results.append(phone_info)

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse PhoneInfoga output: {e}")

        return results

    async def _respect_rate_limit(self):
        """Enforce rate limiting (30 requests/minute)."""
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

    def validate_query(self, phone_number: str) -> bool:
        """Validate phone number format."""
        if not super().validate_query(phone_number):
            return False

        # Basic phone number validation (should contain digits and +)
        return any(c.isdigit() for c in phone_number) and len(phone_number) >= 7
