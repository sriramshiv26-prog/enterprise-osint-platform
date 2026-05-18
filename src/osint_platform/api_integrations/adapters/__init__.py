"""API authentication adapters."""
from src.osint_platform.api_integrations.adapters.base_adapter import BaseAdapter
from src.osint_platform.api_integrations.adapters.api_key_adapter import (
    APIKeyAdapter,
    QueryParamAPIKeyAdapter,
)
from src.osint_platform.api_integrations.adapters.bearer_token_adapter import (
    BearerTokenAdapter,
    BasicAuthAdapter,
)
from src.osint_platform.api_integrations.adapters.oauth_adapter import (
    OAuth2Adapter,
    TwitterOAuth2Adapter,
    LinkedInOAuth2Adapter,
)

__all__ = [
    "BaseAdapter",
    "APIKeyAdapter",
    "QueryParamAPIKeyAdapter",
    "BearerTokenAdapter",
    "BasicAuthAdapter",
    "OAuth2Adapter",
    "TwitterOAuth2Adapter",
    "LinkedInOAuth2Adapter",
]
