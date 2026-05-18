"""
Sherlock - Username OSINT tool wrapper.
Searches for usernames across 300+ websites.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import subprocess
import json

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class SherlockTool(BaseTool):
    """
    Sherlock tool for username enumeration across multiple sites.

    Rate Limit: ~2 requests/second (depends on target sites)
    Typical execution: 10-30 seconds per username
    """

    def __init__(self, timeout: int = 60):
        super().__init__("sherlock", timeout)
        self.rate_limit_per_second = 2
        self.last_request_time = None

    async def search(self, username: str, sites: Optional[List[str]] = None, **kwargs) -> ToolResult:
        """
        Search for username across social media and websites.

        Args:
            username: Username to search for
            sites: Specific sites to search (optional, all if None)
            **kwargs: Additional options (verbose, print_found_only, etc.)

        Returns:
            ToolResult with found accounts
        """
        self._current_query = username

        if not self.validate_query(username):
            return self._standardize_result(
                data=[],
                success=False,
                error="Invalid username format",
            )

        try:
            start_time = datetime.utcnow()

            # Respect rate limiting
            await self._respect_rate_limit()

            # Build Sherlock command
            cmd = ["sherlock", username, "--csv", "--output=sherlock_results"]

            if sites:
                cmd.extend(["--sites", ",".join(sites)])

            if kwargs.get("print_found_only"):
                cmd.append("--print-found-only")

            # Execute Sherlock
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            if result.returncode == 0:
                # Parse results from output
                found_accounts = self._parse_sherlock_output(result.stdout)
                logger.info(f"Sherlock found {len(found_accounts)} matches for '{username}'")

                return self._standardize_result(
                    data=found_accounts,
                    success=True,
                    execution_time=execution_time,
                    rate_limit_remaining=self._estimate_remaining_requests(),
                )
            else:
                return self._standardize_result(
                    data=[],
                    success=False,
                    error=f"Sherlock error: {result.stderr}",
                    execution_time=execution_time,
                )

        except subprocess.TimeoutExpired:
            return self._standardize_result(
                data=[],
                success=False,
                error=f"Sherlock timeout after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"Sherlock search failed: {e}")
            return self._standardize_result(
                data=[],
                success=False,
                error=str(e),
            )

    def _parse_sherlock_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Sherlock JSON output into standardized format."""
        results = []

        try:
            lines = output.strip().split('\n')
            for line in lines:
                if line.startswith('{'):
                    data = json.loads(line)
                    results.append({
                        "site": data.get("site", ""),
                        "url": data.get("url", ""),
                        "status": "found",
                        "metadata": data,
                    })
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse Sherlock output: {e}")

        return results

    async def _respect_rate_limit(self):
        """Enforce rate limiting (2 requests/second)."""
        if self.last_request_time:
            elapsed = (datetime.utcnow() - self.last_request_time).total_seconds()
            required_delay = 1.0 / self.rate_limit_per_second
            if elapsed < required_delay:
                await asyncio.sleep(required_delay - elapsed)

        self.last_request_time = datetime.utcnow()

    def _estimate_remaining_requests(self) -> Optional[int]:
        """Estimate remaining requests (Sherlock doesn't provide explicit limit)."""
        return None  # Sherlock rate limit is implicit

    def validate_query(self, username: str) -> bool:
        """Validate username format."""
        if not super().validate_query(username):
            return False

        # Username should be alphanumeric + common special chars
        valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return all(c in valid_chars for c in username)
