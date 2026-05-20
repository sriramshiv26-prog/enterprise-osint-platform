"""Google Dork Engine — automated dork query execution and analysis."""
from src.osint_platform.tools.dork.dork_tool import DorkTool, run_dork_batch
from src.osint_platform.tools.dork.dork_library import (
    get_all_dorks,
    get_dorks_by_category,
    get_dorks_by_risk,
    resolve_dork_query,
    DorkCategory,
    CATEGORY_DESCRIPTIONS,
    DORKS_BY_CATEGORY,
)

__all__ = [
    "DorkTool",
    "run_dork_batch",
    "get_all_dorks",
    "get_dorks_by_category",
    "get_dorks_by_risk",
    "resolve_dork_query",
    "DorkCategory",
    "CATEGORY_DESCRIPTIONS",
    "DORKS_BY_CATEGORY",
]
