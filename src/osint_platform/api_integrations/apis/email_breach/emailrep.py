"""EmailRep API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import APIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class EmailRepAPI(APIKeyAdapter):
    """EmailRep API for email reputation and breach data."""

    BASE_URL = "https://emailrep.io"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="emailrep", api_key=api_key, **kwargs)

    async def check_email(self, email: str, **kwargs) -> StandardResult:
        """Check email reputation and breach status."""
        start_time = time.time()
        try:
            params = {"key": self.api_key}
            response = await self.http_get(
                f"{self.BASE_URL}/query/{email}",
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=email,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=email,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=email,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
