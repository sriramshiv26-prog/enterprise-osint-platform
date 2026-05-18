"""API Key authentication adapter."""
from typing import Dict, Optional
from src.osint_platform.api_integrations.adapters.base_adapter import BaseAdapter


class APIKeyAdapter(BaseAdapter):
    """
    Adapter for APIs that use simple API key authentication.

    Examples: Shodan, SecurityTrails, BuiltWith, Censys (part of auth)
    """

    def __init__(
        self,
        api_name: str,
        api_key: str,
        header_name: str = "Authorization",
        key_prefix: str = "Bearer",
        **kwargs,
    ):
        """
        Initialize API key adapter.

        Args:
            api_name: Name of API
            api_key: API key/token
            header_name: Header to send key in (default: Authorization)
            key_prefix: Prefix for key (default: Bearer) - can be "Bearer", "Token", etc.
            **kwargs: Additional adapter args
        """
        super().__init__(api_name, **kwargs)
        self.api_key = api_key
        self.header_name = header_name
        self.key_prefix = key_prefix

    async def authenticate(self) -> bool:
        """Verify API key is valid."""
        # Most APIs don't have a dedicated auth endpoint
        # We'll consider valid if key is not empty
        # Subclasses can override for APIs with explicit auth endpoints
        return bool(self.api_key)

    def _get_headers(self) -> Dict[str, str]:
        """Add Authorization header with API key."""
        headers = super()._get_headers()
        headers[self.header_name] = f"{self.key_prefix} {self.api_key}"
        return headers


class QueryParamAPIKeyAdapter(APIKeyAdapter):
    """
    Adapter for APIs that pass API key as query parameter.

    Examples: Shodan, BuiltWith, AlienVault OTX
    """

    def __init__(
        self,
        api_name: str,
        api_key: str,
        param_name: str = "api_key",
        **kwargs,
    ):
        """
        Initialize query param API key adapter.

        Args:
            api_name: Name of API
            api_key: API key
            param_name: Query parameter name (default: api_key)
            **kwargs: Additional adapter args
        """
        # Disable header-based auth
        super().__init__(api_name, api_key, header_name=None, **kwargs)
        self.param_name = param_name
        self.api_key_param = param_name

    def add_api_key_param(self, params: Dict) -> Dict:
        """Add API key to query parameters."""
        params = params or {}
        params[self.param_name] = self.api_key
        return params
