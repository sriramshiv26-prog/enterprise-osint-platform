"""BuiltWith API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import QueryParamAPIKeyAdapter
from src.osint_platform.api_integrations.models import StandardResult


class BuiltWithAPI(QueryParamAPIKeyAdapter):
    """BuiltWith for website technology intelligence."""

    BASE_URL = "https://api.builtwith.com/v20/api.php"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="builtwith", api_key=api_key, **kwargs)

    async def lookup_domain(self, domain: str, **kwargs) -> StandardResult:
        """Look up technology stack for domain."""
        start_time = time.time()
        try:
            params = {"Domain": domain, "GetIcon": "Y", "key": self.api_key}
            response = await self.http_get(
                self.BASE_URL,
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=domain,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=domain,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=domain,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
