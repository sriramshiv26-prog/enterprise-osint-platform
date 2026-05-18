"""
Holehe - Email breach detection tool wrapper.
Searches for email addresses in known data breaches.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
import subprocess
import json

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class HoleheTool(BaseTool):
    """
    Holehe tool for email breach detection across multiple services.

    Rate Limit: ~1 request/second
    Typical execution: 5-20 seconds per email
    """

    def __init__(self, timeout: int = 30):
        super().__init__("holehe", timeout)
        self.rate_limit_per_second = 1
        self.last_request_time = None

    async def search(
        self,
        email: str,
        only_breaches: bool = False,
        **kwargs,
    ) -> ToolResult:
        """
        Search for email in breaches and registrations.

        Args:
            email: Email address to search
            only_breaches: Show only breach results
            **kwargs: Additional options

        Returns:
            ToolResult with breach information
        """
        self._current_query = email

        if not self.validate_query(email):
            return self._standardize_result(
                data=[],
                success=False,
                error="Invalid email format",
            )

        try:
            start_time = datetime.utcnow()

            # Respect rate limiting
            await self._respect_rate_limit()

            # Build Holehe command
            cmd = [
                "holehe",
                email,
            ]

            if only_breaches:
                cmd.append("--onlybreaches")

            if kwargs.get("verbose"):
                cmd.append("-v")

            # Execute Holehe
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            if result.returncode == 0:
                breaches = self._parse_holehe_output(result.stdout)
                logger.info(f"Holehe found {len(breaches)} results for '{email}'")

                return self._standardize_result(
                    data=breaches,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=1,  # Holehe is simple rate limiting
                )
            else:
                return self._standardize_result(
                    data=[],
                    success=False,
                    error=f"Holehe error: {result.stderr}",
                    execution_time=execution_time,
                )

        except subprocess.TimeoutExpired:
            return self._standardize_result(
                data=[],
                success=False,
                error=f"Holehe timeout after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"Holehe search failed: {e}")
            return self._standardize_result(
                data=[],
                success=False,
                error=str(e),
            )

    def _parse_holehe_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Holehe output into standardized format."""
        results = []

        # Parse output lines
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('['):
                continue

            # Format: [+] Site: Service (URL)
            if '[+]' in line:
                parts = line.replace('[+]', '').strip().split(' : ')
                if len(parts) >= 2:
                    site_info = parts[0].strip()
                    status = parts[1].strip() if len(parts) > 1 else "found"

                    results.append({
                        "site": site_info,
                        "status": "found" if "[+]" in line else "not_found",
                        "breach_info": status,
                        "source": "holehe",
                    })

        return results

    async def _respect_rate_limit(self):
        """Enforce rate limiting (1 request/second)."""
        if self.last_request_time:
            elapsed = (datetime.utcnow() - self.last_request_time).total_seconds()
            required_delay = 1.0  # 1 second per request
            if elapsed < required_delay:
                await asyncio.sleep(required_delay - elapsed)

        self.last_request_time = datetime.utcnow()

    def validate_query(self, email: str) -> bool:
        """Validate email format."""
        if not super().validate_query(email):
            return False

        # Basic email validation
        return '@' in email and '.' in email.split('@')[1]
