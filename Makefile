.PHONY: help setup dev test lint format clean docker-up docker-down

help:
	@echo "Enterprise OSINT Platform - Development Commands"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make setup              Install dependencies and setup environment"
	@echo "  make docker-up          Start Docker services (PostgreSQL, Redis, ES, Neo4j)"
	@echo "  make docker-down        Stop Docker services"
	@echo ""
	@echo "Development:"
	@echo "  make dev                Run FastAPI development server (with auto-reload)"
	@echo "  make test               Run test suite with coverage"
	@echo "  make lint               Run code quality checks (mypy, flake8)"
	@echo "  make format             Format code with black and isort"
	@echo ""
	@echo "Database:"
	@echo "  make migrate            Run database migrations"
	@echo "  make migrate-create     Create new migration"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean              Remove build artifacts and cache files"

setup:
	@echo "Setting up Enterprise OSINT Platform..."
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	cp config/.env.example config/.env
	@echo "Setup complete! Next: make docker-up && make dev"

docker-up:
	@echo "Starting Docker services..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	sleep 5
	docker-compose ps
	@echo ""
	@echo "Services running:"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis: localhost:6379"
	@echo "  Elasticsearch: localhost:9200"
	@echo "  Neo4j: localhost:7687 (Browser: localhost:7474)"

docker-down:
	@echo "Stopping Docker services..."
	docker-compose down

docker-logs:
	docker-compose logs -f

dev:
	python -m uvicorn src.osint_platform.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v --cov=src/osint_platform --cov-report=html

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	mypy src/osint_platform --strict
	flake8 src/osint_platform tests --max-line-length=100
	pylint src/osint_platform

format:
	black src/ tests/
	isort src/ tests/

migrate:
	alembic upgrade head

migrate-create:
	@read -p "Migration name: " migration_name; \
	alembic revision --autogenerate -m "$$migration_name"

migrate-downgrade:
	alembic downgrade -1

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache htmlcov
	rm -rf build/ dist/ *.egg-info

shell:
	python -m ipython

requirements-freeze:
	pip freeze > requirements.txt.frozen

.PHONY: help setup dev test lint format clean docker-up docker-down migrate
