"""Twitter API v2 integration."""
import time
from src.osint_platform.api_integrations.adapters import TwitterOAuth2Adapter
from src.osint_platform.api_integrations.models import StandardResult

class TwitterAPIv2(TwitterOAuth2Adapter):
    """Twitter API v2 for social intelligence."""
    BASE_URL = "https://api.twitter.com/2"

    async def search_tweets(self, query: str, max_results: int = 100, **kwargs) -> StandardResult:
        """Search for tweets matching query."""
        start_time = time.time()
        try:
            params = {
                "query": query,
                "max_results": min(max_results, 100),
                "tweet.fields": "created_at,author_id,public_metrics"
            }
            response = await self.http_get(
                f"{self.BASE_URL}/tweets/search/recent",
                params=params
            )
            execution_time = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                tweets = [{"tweet": t} for t in data.get("data", [])]
                return self._create_result(
                    query=query, data=tweets, success=True,
                    execution_time=execution_time, response_code=200
                )
            else:
                return self._create_result(
                    query=query, data=[], success=False,
                    error=response.text, execution_time=execution_time,
                    response_code=response.status_code
                )
        except Exception as e:
            return self._create_result(
                query=query, data=[], success=False, error=str(e),
                execution_time=time.time() - start_time
            )
