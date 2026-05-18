"""
Enterprise OSINT Platform - Main FastAPI Application
"""
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.osint_platform.config import get_config

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

    yield

    # Shutdown
    logger.info("Shutting down Enterprise OSINT Platform")
    try:
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

    # API Routes - will be added in subsequent steps
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
