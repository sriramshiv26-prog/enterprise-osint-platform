"""Base adapter class for all API integrations."""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime
import httpx

from src.osint_platform.api_integrations.models import StandardResult, APIMetadata

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """
    Abstract base class for API adapters.

    Provides:
    - HTTP client (httpx with timeout/retry)
    - Rate limit tracking
    - Standard result formatting
    - Error handling
    """

    def __init__(
        self,
        api_name: str,
        timeout_seconds: int = 30,
        max_retries: int = 3,
    ):
        """
        Initialize adapter.

        Args:
            api_name: Name of API (shodan, censys, etc.)
            timeout_seconds: HTTP timeout
            max_retries: Max retry attempts on transient errors
        """
        self.api_name = api_name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.logger = logging.getLogger(f"api.{api_name}")
        self.client: Optional[httpx.AsyncClient] = None
        self.is_authenticated = False

    async def initialize(self) -> None:
        """Initialize HTTP client and authenticate."""
        self.client = httpx.AsyncClient(timeout=self.timeout_seconds)
        self.is_authenticated = await self.authenticate()

        if not self.is_authenticated:
            self.logger.warning(f"{self.api_name} authentication failed")
        else:
            self.logger.info(f"{self.api_name} authenticated successfully")

    async def close(self) -> None:
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()

    @abstractmethod
    async def authenticate(self) -> bool:
        """
        Authenticate with the API.

        Returns:
            True if authenticated, False otherwise
        """
        pass

    @abstractmethod
    async def search(self, query: str, **kwargs) -> StandardResult:
        """
        Execute search query on API.

        Args:
            query: Search query
            **kwargs: API-specific parameters

        Returns:
            StandardResult with findings
        """
        pass

    async def http_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> httpx.Response:
        """
        Make async GET request with retry logic.

        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers
            **kwargs: Additional httpx arguments

        Returns:
            Response object
        """
        if not self.client:
            raise RuntimeError(f"{self.api_name} not initialized")

        merged_headers = self._get_headers()
        if headers:
            merged_headers.update(headers)

        for attempt in range(self.max_retries):
            try:
                response = await self.client.get(
                    url,
                    params=params,
                    headers=merged_headers,
                    **kwargs,
                )

                # Retry on transient errors (429, 503, 504)
                if response.status_code in [429, 503, 504] and attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self.logger.warning(
                        f"{self.api_name} rate limited, retrying in {wait_time}s"
                    )
                    import asyncio
                    await asyncio.sleep(wait_time)
                    continue

                return response

            except httpx.TimeoutException as e:
                if attempt == self.max_retries - 1:
                    raise
                self.logger.debug(f"{self.api_name} timeout, retrying...")
                continue

        raise RuntimeError(f"{self.api_name} failed after {self.max_retries} attempts")

    async def http_post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> httpx.Response:
        """Make async POST request with retry logic."""
        if not self.client:
            raise RuntimeError(f"{self.api_name} not initialized")

        merged_headers = self._get_headers()
        if headers:
            merged_headers.update(headers)

        for attempt in range(self.max_retries):
            try:
                response = await self.client.post(
                    url,
                    data=data,
                    json=json,
                    headers=merged_headers,
                    **kwargs,
                )

                if response.status_code in [429, 503, 504] and attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    await asyncio.sleep(wait_time)
                    continue

                return response

            except httpx.TimeoutException:
                if attempt == self.max_retries - 1:
                    raise
                continue

        raise RuntimeError(f"{self.api_name} POST failed after {self.max_retries} attempts")

    def _get_headers(self) -> Dict[str, str]:
        """Get base headers. Override in subclass for auth headers."""
        return {
            "User-Agent": f"EnterpriseOSINT/1.0 ({self.api_name})",
        }

    def _create_result(
        self,
        query: str,
        data: list,
        success: bool = True,
        error: Optional[str] = None,
        execution_time: float = 0.0,
        rate_limit_remaining: Optional[int] = None,
        rate_limit_reset: Optional[datetime] = None,
        response_code: Optional[int] = None,
    ) -> StandardResult:
        """Create standardized result."""
        metadata = APIMetadata(
            source=self.api_name,
            rate_limit_remaining=rate_limit_remaining,
            rate_limit_reset=rate_limit_reset,
            execution_time_seconds=execution_time,
            api_response_code=response_code,
        )

        return StandardResult(
            source=self.api_name,
            query=query,
            success=success,
            data=data,
            error=error,
            metadata=metadata,
        )

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
