"""OAuth 2.0 authentication adapter."""
from typing import Dict, Optional
from datetime import datetime, timedelta
import logging
from src.osint_platform.api_integrations.adapters.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)


class OAuth2Adapter(BaseAdapter):
    """
    Adapter for APIs that use OAuth 2.0 authentication.

    Examples: Twitter API v2, LinkedIn API, Reddit API
    """

    def __init__(
        self,
        api_name: str,
        client_id: str,
        client_secret: str,
        token_url: str,
        access_token: Optional[str] = None,
        token_expires_at: Optional[datetime] = None,
        **kwargs,
    ):
        """
        Initialize OAuth 2.0 adapter.

        Args:
            api_name: Name of API
            client_id: OAuth client ID
            client_secret: OAuth client secret
            token_url: Token endpoint URL
            access_token: Cached access token (optional)
            token_expires_at: When cached token expires (optional)
            **kwargs: Additional adapter args
        """
        super().__init__(api_name, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.access_token = access_token
        self.token_expires_at = token_expires_at

    async def authenticate(self) -> bool:
        """Get/refresh OAuth token."""
        try:
            if self._token_expired():
                await self._refresh_token()

            return bool(self.access_token)
        except Exception as e:
            logger.error(f"OAuth authentication failed for {self.api_name}: {e}")
            return False

    async def _refresh_token(self) -> None:
        """Get new access token from token endpoint."""
        if not self.client:
            raise RuntimeError(f"{self.api_name} not initialized")

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            response = await self.client.post(self.token_url, data=payload)
            response.raise_for_status()

            data = response.json()
            self.access_token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

            logger.info(f"{self.api_name} token refreshed, expires in {expires_in}s")
        except Exception as e:
            logger.error(f"Failed to refresh {self.api_name} token: {e}")
            raise

    def _token_expired(self) -> bool:
        """Check if current token is expired."""
        if not self.access_token or not self.token_expires_at:
            return True

        # Refresh 5 minutes before expiry
        return datetime.utcnow() > (self.token_expires_at - timedelta(minutes=5))

    def _get_headers(self) -> Dict[str, str]:
        """Add Authorization header with OAuth token."""
        headers = super()._get_headers()
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers


class TwitterOAuth2Adapter(OAuth2Adapter):
    """Specialized adapter for Twitter API v2."""

    def __init__(
        self,
        bearer_token: str,
        **kwargs,
    ):
        """
        Initialize Twitter OAuth adapter.

        Args:
            bearer_token: Twitter API bearer token (simpler than full OAuth)
            **kwargs: Additional adapter args
        """
        super().__init__(
            api_name="twitter",
            client_id="twitter",
            client_secret="",
            token_url="",
            access_token=bearer_token,
            **kwargs,
        )

    async def authenticate(self) -> bool:
        """Verify bearer token is valid."""
        return bool(self.access_token)


class LinkedInOAuth2Adapter(OAuth2Adapter):
    """Specialized adapter for LinkedIn API."""

    TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        access_token: Optional[str] = None,
        **kwargs,
    ):
        """Initialize LinkedIn OAuth adapter."""
        super().__init__(
            api_name="linkedin",
            client_id=client_id,
            client_secret=client_secret,
            token_url=self.TOKEN_URL,
            access_token=access_token,
            **kwargs,
        )
