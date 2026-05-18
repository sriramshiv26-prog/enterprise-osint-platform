"""
Enterprise OSINT Platform - Main FastAPI Application
"""
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.osint_platform.config import get_config
from src.osint_platform.tools.tool_manager import get_tool_manager
from src.osint_platform.api_integrations.manager import get_api_manager
from src.osint_platform.api.routes import tools as tools_routes
from src.osint_platform.api.routes import apis as apis_routes
from src.osint_platform.api.routes import questionnaires as questionnaires_routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown events."""
    # Startup
    logger.info("Starting Enterprise OSINT Platform")
    config = get_config()
    logger.info(f"Environment: {config.get('environment', 'development')}")
    logger.info(f"Debug Mode: {config.get('debug', False)}")

    # Initialize database connection
    try:
        logger.info("Initializing database connection...")
        # TODO: Initialize database connection
        logger.info("Database connection initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Initialize Redis connection
    try:
        logger.info("Initializing Redis connection...")
        # TODO: Initialize Redis connection
        logger.info("Redis connection initialized")
    except Exception as e:
        logger.warning(f"Redis connection failed (non-critical): {e}")

    # Initialize OSINT tool manager
    try:
        logger.info("Starting OSINT tool executors...")
        tool_manager = get_tool_manager()
        await tool_manager.start()
        logger.info("Tool executors started")
    except Exception as e:
        logger.error(f"Failed to start tool executors: {e}")
        raise

    # Initialize API Manager
    try:
        logger.info("Initializing OSINT API Manager...")
        api_manager = get_api_manager()
        api_keys = {
            "shodan": config.get("apis", {}).get("shodan_key", ""),
            "virustotal": config.get("apis", {}).get("virustotal_key", ""),
            "securitytrails": config.get("apis", {}).get("securitytrails_key", ""),
            "haveibeenpwned": config.get("apis", {}).get("haveibeenpwned_key", ""),
            "abuseipdb": config.get("apis", {}).get("abuseipdb_key", ""),
            "urlscan": config.get("apis", {}).get("urlscan_key", ""),
            "whois": config.get("apis", {}).get("whois_key", ""),
            "twitter": config.get("apis", {}).get("twitter_key", ""),
        }
        await api_manager.initialize(api_keys)
        logger.info("API Manager initialized")
    except Exception as e:
        logger.warning(f"API Manager initialization warning: {e}")

    yield

    # Shutdown
    logger.info("Shutting down Enterprise OSINT Platform")
    try:
        # Stop tool executors
        logger.info("Stopping OSINT tool executors...")
        tool_manager = get_tool_manager()
        await tool_manager.stop()
        logger.info("Tool executors stopped")

        # Close API Manager connections
        logger.info("Closing API Manager...")
        api_manager = get_api_manager()
        await api_manager.close()
        logger.info("API Manager closed")

        # TODO: Close database connections
        # TODO: Close Redis connection
        logger.info("All connections closed")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    config = get_config()

    app = FastAPI(
        title=config.get("app", {}).get("name", "Enterprise OSINT Platform"),
        version=config.get("app", {}).get("version", "0.1.0"),
        description="Autonomous Open Source Intelligence platform powered by Claude",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS Configuration
    cors_config = config.get("cors", {})
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_config.get("allowed_origins", ["*"]),
        allow_credentials=True,
        allow_methods=cors_config.get("allowed_methods", ["GET", "POST", "PUT", "DELETE"]),
        allow_headers=cors_config.get("allowed_headers", ["*"]),
    )

    # Health check endpoint
    @app.get("/health", tags=["System"])
    async def health_check() -> Dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "version": config.get("app", {}).get("version", "0.1.0"),
            "environment": config.get("environment", "development"),
        }

    # Root endpoint
    @app.get("/", tags=["System"])
    async def root() -> Dict[str, str]:
        """Root endpoint."""
        return {
            "message": "Enterprise OSINT Platform API",
            "docs": "/docs",
            "status": "running",
        }

    # API Routes
    app.include_router(tools_routes.router)
    app.include_router(apis_routes.router)
    app.include_router(questionnaires_routes.router)
    # @app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
    # @app.include_router(investigations.router, prefix="/api/v1/investigations", tags=["Investigations"])

    # Error handlers
    @app.exception_handler(Exception)
    async def general_exception_handler(request, exc: Exception):
        """Global exception handler."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return {
            "error": "Internal Server Error",
            "code": "INTERNAL_ERROR",
            "message": str(exc) if config.get("debug") else "An unexpected error occurred",
        }

    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "src.osint_platform.main:app",
        host=config.get("api_host", "0.0.0.0"),
        port=config.get("api_port", 8000),
        reload=config.get("debug", False),
        log_level="info",
    )
