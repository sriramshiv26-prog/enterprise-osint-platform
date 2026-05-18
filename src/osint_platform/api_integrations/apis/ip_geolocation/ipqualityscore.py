"""IPQualityScore API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import QueryParamAPIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class IPQualityScoreAPI(QueryParamAPIKeyAdapter):
    """IPQualityScore for IP and email reputation."""

    BASE_URL = "https://ipqualityscore.com/api/json"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="ipqualityscore", api_key=api_key, **kwargs)

    async def check_ip(self, ip: str, **kwargs) -> StandardResult:
        """Check IP reputation score."""
        start_time = time.time()
        try:
            params = {"ip": ip, "key": self.api_key, "strictness": 0}
            response = await self.http_get(
                f"{self.BASE_URL}/ip",
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=ip,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=ip,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=ip,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def check_email(self, email: str, **kwargs) -> StandardResult:
        """Check email reputation."""
        start_time = time.time()
        try:
            params = {"email": email, "key": self.api_key}
            response = await self.http_get(
                f"{self.BASE_URL}/email",
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
