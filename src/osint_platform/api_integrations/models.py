"""Standardized models for API responses."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
import json


@dataclass
class APIMetadata:
    """Metadata about API response."""
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[datetime] = None
    execution_time_seconds: float = 0.0
    api_response_code: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "rate_limit_remaining": self.rate_limit_remaining,
            "rate_limit_reset": self.rate_limit_reset.isoformat() if self.rate_limit_reset else None,
            "execution_time_seconds": self.execution_time_seconds,
            "api_response_code": self.api_response_code,
        }


@dataclass
class StandardResult:
    """Standardized result from any API."""
    source: str
    query: str
    success: bool
    data: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    metadata: APIMetadata = field(default_factory=lambda: APIMetadata(source="unknown"))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "query": self.query,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "metadata": self.metadata.to_dict(),
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @property
    def result_count(self) -> int:
        """Number of results found."""
        return len(self.data)

    def is_rate_limited(self) -> bool:
        """Check if API rate limited based on remaining requests."""
        if self.metadata.rate_limit_remaining is not None:
            return self.metadata.rate_limit_remaining == 0
        return False
