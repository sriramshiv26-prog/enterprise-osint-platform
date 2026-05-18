"""GitHub API integration."""
from typing import Dict, Any, Optional
import time

from src.osint_platform.api_integrations.adapters import BearerTokenAdapter
from src.osint_platform.api_integrations.models import StandardResult


class GitHubAPI(BearerTokenAdapter):
    """GitHub API for repository and user intelligence."""

    BASE_URL = "https://api.github.com"

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_name="github", bearer_token=api_key, **kwargs)

    async def search_user(self, username: str, **kwargs) -> StandardResult:
        """Search for GitHub user."""
        start_time = time.time()
        try:
            response = await self.http_get(f"{self.BASE_URL}/users/{username}")
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=username,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=username,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=username,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def search_repositories(self, query: str, **kwargs) -> StandardResult:
        """Search for repositories."""
        start_time = time.time()
        try:
            params = {"q": query, "sort": "stars", "order": "desc"}
            response = await self.http_get(
                f"{self.BASE_URL}/search/repositories",
                params=params,
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=query,
                    data=[data],
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=query,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=query,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def get_user_repos(self, username: str, **kwargs) -> StandardResult:
        """Get repositories for a user."""
        start_time = time.time()
        try:
            response = await self.http_get(
                f"{self.BASE_URL}/users/{username}/repos"
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                return self._create_result(
                    query=username,
                    data=data,
                    success=True,
                    execution_time=execution_time,
                    response_code=200,
                )
            else:
                return self._create_result(
                    query=username,
                    data=[],
                    success=False,
                    error=response.text,
                    execution_time=execution_time,
                    response_code=response.status_code,
                )
        except Exception as e:
            return self._create_result(
                query=username,
                data=[],
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
