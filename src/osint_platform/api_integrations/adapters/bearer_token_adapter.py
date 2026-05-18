"""Bearer token authentication adapter."""
from typing import Dict, Optional
from datetime import datetime, timedelta
from src.osint_platform.api_integrations.adapters.base_adapter import BaseAdapter


class BearerTokenAdapter(BaseAdapter):
    """
    Adapter for APIs that use Bearer token authentication.

    Examples: VirusTotal, SecurityTrails, URLScan.io, AbuseIPDB
    """

    def __init__(
        self,
        api_name: str,
        bearer_token: str,
        **kwargs,
    ):
        """
        Initialize bearer token adapter.

        Args:
            api_name: Name of API
            bearer_token: Bearer token
            **kwargs: Additional adapter args
        """
        super().__init__(api_name, **kwargs)
        self.bearer_token = bearer_token

    async def authenticate(self) -> bool:
        """Verify bearer token is valid."""
        # Most APIs don't have explicit auth check
        # Validation happens on first API call
        return bool(self.bearer_token)

    def _get_headers(self) -> Dict[str, str]:
        """Add Authorization header with bearer token."""
        headers = super()._get_headers()
        headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers


class BasicAuthAdapter(BaseAdapter):
    """
    Adapter for APIs that use HTTP Basic authentication.

    Examples: Some private OSINT APIs
    """

    def __init__(
        self,
        api_name: str,
        username: str,
        password: str,
        **kwargs,
    ):
        """
        Initialize basic auth adapter.

        Args:
            api_name: Name of API
            username: Username
            password: Password
            **kwargs: Additional adapter args
        """
        super().__init__(api_name, **kwargs)
        self.username = username
        self.password = password

    async def authenticate(self) -> bool:
        """Verify basic auth credentials."""
        return bool(self.username and self.password)

    def _get_headers(self) -> Dict[str, str]:
        """Add Authorization header with basic auth."""
        import base64
        headers = super()._get_headers()
        credentials = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {credentials}"
        return headers
