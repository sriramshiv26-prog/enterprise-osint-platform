# Phase 1 Implementation Plan - Core Infrastructure

**Duration:** 2 weeks (42 hours total, 14 hours with 3 developers)  
**Deliverable:** Working FastAPI application with PostgreSQL backend, JWT auth, RBAC, and Investigation CRUD  
**Model:** Qwen2.5-coder-1.5B (local via Ollama) + Claude Sonnet (1-2 calls for complex decisions)

---

## Step-by-Step Implementation (11 Steps)

### Step 1: Project Initialization (Day 1, 1-2 hours)

**Tasks:**
1. Create project directory structure
2. Initialize git repository  
3. Create requirements.txt with dependencies
4. Create docker-compose.yml for local services
5. Create config files

**Files to Create:**
- `requirements.txt` — Python dependencies
- `docker-compose.yml` — PostgreSQL, Redis, Elasticsearch, Neo4j
- `config/osint_platform.yaml` — Default configuration
- `config/.env.example` — Secrets template
- `.gitignore` — Standard Python gitignore

**Docker Services:**
```yaml
postgres:     localhost:5432  (POSTGRES_PASSWORD=dev_password)
redis:        localhost:6379
elasticsearch: localhost:9200
neo4j:        localhost:7687 (NEO4J_AUTH=neo4j/dev_password)
```

**Command:**
```bash
# Use Ollama to generate boilerplate
ollama run qwen2.5-coder:1.5b "Generate complete docker-compose.yml with PostgreSQL, Redis, Elasticsearch, Neo4j for OSINT platform"
```

**Estimate:** 1-2 hours

---

### Step 2: Database Schema Design (Day 1-2, 2-3 hours)

**Create PostgreSQL schema with 12 tables:**

| Table | Columns | Purpose |
|-------|---------|---------|
| **users** | id, email (UNIQUE), password_hash, username, created_at, updated_at, is_active | User accounts |
| **teams** | id, name, owner_id (FK users), created_at, is_active | Team management |
| **team_members** | id, team_id (FK teams), user_id (FK users), role, created_at | Team membership |
| **api_keys** | id, user_id (FK users), key_hash, name, last_used_at, created_at, expires_at | API authentication |
| **investigations** | id, user_id (FK users), team_id (FK teams), title, status, query, created_at, updated_at, started_at, completed_at | Investigation records |
| **findings** | id, investigation_id (FK investigations), finding_type, source, value, confidence, raw_data (JSON), created_at | Investigation results |
| **relationships** | id, finding_id_1, finding_id_2, relationship_type, confidence, created_at | Entity relationships |
| **timeline_events** | id, investigation_id (FK investigations), event_type, timestamp, description, source, created_at | Timeline entries |
| **breach_records** | id, investigation_id (FK investigations), breach_name, breach_date, record_count, email/username, source, created_at | Breach data |
| **audit_logs** | id, user_id (FK users), action, resource_type, resource_id, details (JSON), timestamp | Audit trail |
| **cached_results** | id, cache_key, result_data (JSON), expires_at, created_at | Result caching |
| **threat_indicators** | id, investigation_id (FK investigations), indicator_type, value, severity, source, created_at | Threat data |

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate PostgreSQL CREATE TABLE statements for OSINT platform with these tables: users, teams, team_members, api_keys, investigations, findings, relationships, timeline_events, breach_records, audit_logs, cached_results, threat_indicators. Include foreign keys, indexes, and timestamps."
```

**Estimate:** 2-3 hours

---

### Step 3: SQLAlchemy ORM Models (Day 2-3, 5 hours)

**Create model files in `src/osint_platform/models/`:**
- `user.py` — User, Team, TeamMember models
- `api_key.py` — APIKey model
- `investigation.py` — Investigation, Finding models
- `relationship.py` — Relationship, TimelineEvent models
- `breach_record.py` — BreachRecord model
- `audit_log.py` — AuditLog model
- `cache.py` — CachedResult model
- `threat_indicator.py` — ThreatIndicator model

**Each model includes:**
- SQLAlchemy column definitions with proper types
- Relationships (ForeignKey, backref)
- Validation methods
- `__repr__` for debugging
- Timestamps (created_at, updated_at)

**Example Structure:**
```python
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()

class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(String(20), default="draft")  # draft/in_progress/completed/archived
    query = Column(String(2000))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = relationship("User", backref="investigations")
    findings = relationship("Finding", backref="investigation", cascade="all, delete-orphan")
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate complete SQLAlchemy ORM models for User, Investigation, Finding, Relationship, TimelineEvent, and BreachRecord with proper foreign keys and relationships"
```

**Estimate:** 4-5 hours

---

### Step 4: Database Connection & Migrations (Day 3, 2-3 hours)

**Create:**
- `src/osint_platform/database/connection.py` — SQLAlchemy engine, session factory
- `src/osint_platform/database/migrations/` — Alembic setup
- Initial migration: `alembic revision --autogenerate -m "Initial schema"`

**Database Connection Code:**
```python
# src/osint_platform/database/connection.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:dev_password@localhost/osint_platform")

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True  # Verify connections alive
)

SessionLocal = sessionmaker(bind=engine)

@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

**Commands:**
```bash
# Initialize Alembic
alembic init alembic

# Generate initial migration
alembic revision --autogenerate -m "Initial schema"

# Apply migration
alembic upgrade head
```

**Estimate:** 2-3 hours

---

### Step 5: FastAPI Application Setup (Day 4, 2-3 hours)

**Create:**
- `src/osint_platform/main.py` — FastAPI app initialization
- `src/osint_platform/config.py` — Configuration loader
- `src/osint_platform/api/middleware/` — Logging, error handling

**FastAPI Application:**
```python
# src/osint_platform/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.osint_platform.config import load_config

config = load_config()

app = FastAPI(
    title="Enterprise OSINT Platform",
    version="0.1.0",
    description="Autonomous intelligence gathering platform"
)

# Middleware
app.add_middleware(CORSMiddleware, allow_origins=["*"])

@app.on_event("startup")
async def startup():
    # Initialize database connection
    pass

@app.on_event("shutdown")
async def shutdown():
    # Cleanup
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate FastAPI main.py with startup/shutdown events, CORS middleware, and request logging"
```

**Estimate:** 2-3 hours

---

### Step 6: Authentication System (Day 4-5, 4-5 hours)

**Create:**
- `src/osint_platform/auth/jwt.py` — JWT token handling
- `src/osint_platform/auth/rbac.py` — Role-based access control
- `src/osint_platform/api/routes/auth.py` — Auth endpoints

**Endpoints:**
- `POST /api/v1/auth/register` — User registration
- `POST /api/v1/auth/login` — Login (returns JWT token)
- `POST /api/v1/auth/refresh` — Refresh token
- `POST /api/v1/auth/logout` — Logout

**JWT Implementation:**
```python
import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret_key")
ALGORITHM = "HS256"
TOKEN_EXPIRY = timedelta(hours=24)

def create_access_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + TOKEN_EXPIRY,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_access_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
```

**RBAC Roles:**
- **admin** — Full access, user/team management, system settings
- **analyst** — Run investigations, view team findings, create reports
- **investigator** — Run investigations, only see own findings

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate FastAPI JWT authentication with register/login endpoints, token refresh, and RBAC roles (admin/analyst/investigator)"
```

**Estimate:** 4-5 hours

---

### Step 7: Investigation CRUD Endpoints (Day 5-6, 5-6 hours)

**Create:**
- `src/osint_platform/api/routes/investigations.py` — Endpoint handlers
- `src/osint_platform/api/schemas/investigation.py` — Pydantic models

**Endpoints:**
- `POST /api/v1/investigations` — Create investigation
- `GET /api/v1/investigations` — List (with pagination, filtering)
- `GET /api/v1/investigations/{id}` — Get details
- `PUT /api/v1/investigations/{id}` — Update
- `DELETE /api/v1/investigations/{id}` — Delete
- `POST /api/v1/investigations/{id}/start` — Trigger OSINT tools
- `GET /api/v1/investigations/{id}/findings` — Get findings
- `GET /api/v1/investigations/{id}/timeline` — Get timeline

**Pydantic Schemas:**
```python
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class InvestigationCreate(BaseModel):
    title: str
    query: str
    team_id: Optional[int] = None

class InvestigationResponse(BaseModel):
    id: int
    title: str
    status: str
    findings_count: int
    created_at: datetime
    updated_at: datetime
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate FastAPI CRUD endpoints for investigations with pagination, filtering by status, and relationships to findings/timeline"
```

**Estimate:** 5-6 hours

---

### Step 8: Error Handling & Middleware (Day 6-7, 3-4 hours)

**Create:**
- `src/osint_platform/api/middleware/auth.py` — JWT verification
- `src/osint_platform/api/middleware/audit.py` — Request logging
- `src/osint_platform/api/error_handlers.py` — Global exception handling

**Error Response Structure:**
```python
class ErrorResponse(BaseModel):
    error: str
    code: str
    timestamp: datetime
    path: str
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate FastAPI exception handlers for HTTP errors, JWT validation errors, and database errors"
```

**Estimate:** 3-4 hours

---

### Step 9: Configuration Management (Day 7, 2-3 hours)

**Create:**
- `src/osint_platform/config.py` — Load from YAML + env vars
- `config/osint_platform.yaml` — Default settings
- `config/.env.example` — Secrets template

**Configuration Structure:**
```yaml
database:
  url: postgresql://localhost/osint_platform
  pool_size: 20

redis:
  url: redis://localhost:6379/0

jwt:
  secret_key: ${JWT_SECRET_KEY}
  expiry_hours: 24

osint:
  default_depth: 2
  timeout: 60

logging:
  level: INFO
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate Python configuration loader that reads from YAML and environment variables"
```

**Estimate:** 2-3 hours

---

### Step 10: Testing Setup (Day 8, 3-4 hours)

**Create:**
- `tests/conftest.py` — Pytest fixtures
- `tests/test_auth.py` — Authentication tests
- `tests/test_investigations.py` — Investigation CRUD tests
- `pytest.ini` — Pytest configuration

**Basic Test Structure:**
```python
import pytest
from fastapi.testclient import TestClient
from src.osint_platform.main import app

client = TestClient(app)

@pytest.fixture
def test_user(db):
    user = User(email="test@example.com", username="testuser")
    db.add(user)
    db.commit()
    return user

def test_user_registration():
    response = client.post("/api/v1/auth/register", json={
        "email": "new@example.com",
        "password": "password123",
        "username": "newuser"
    })
    assert response.status_code == 201

def test_investigation_crud(test_user):
    # Create
    response = client.post("/api/v1/investigations", 
        json={"title": "Test", "query": "test query"},
        headers={"Authorization": f"Bearer {test_user.token}"}
    )
    assert response.status_code == 201
    
    # Read
    inv_id = response.json()["id"]
    response = client.get(f"/api/v1/investigations/{inv_id}")
    assert response.status_code == 200
```

**Command:**
```bash
ollama run qwen2.5-coder:1.5b "Generate pytest test suite with fixtures for testing FastAPI authentication and investigation CRUD endpoints"
```

**Estimate:** 3-4 hours

---

### Step 11: Documentation (Day 9, 3-4 hours)

**Create:**
- `docs/API.md` — API reference
- `docs/DATABASE.md` — Database schema documentation
- `docs/DEVELOPMENT.md` — Development setup guide
- `docs/ARCHITECTURE.md` — Architecture overview

**Estimate:** 3-4 hours

---

## Timeline Summary

| Days | Task | Hours | Model |
|------|------|-------|-------|
| 1 | Project initialization | 2 | Qwen |
| 1-2 | Database schema design | 3 | Qwen |
| 2-3 | SQLAlchemy ORM models | 5 | Qwen |
| 3 | Database migrations | 3 | Qwen |
| 4 | FastAPI app setup | 3 | Qwen |
| 4-5 | Authentication system | 5 | Qwen + Sonnet (1 call) |
| 5-6 | Investigation CRUD | 6 | Qwen |
| 6-7 | Error handling & middleware | 4 | Qwen |
| 7 | Configuration management | 3 | Qwen |
| 8 | Testing setup | 4 | Qwen |
| 9 | Documentation | 4 | Qwen |
| **Total** | **Phase 1** | **42 hours** | **Mostly Qwen, 1 Sonnet call** |

**With 3 developers:** 14 hours elapsed time (2 weeks)

---

## Success Criteria

✓ PostgreSQL database running with 12 tables  
✓ FastAPI application starts without errors  
✓ User registration and login working with JWT  
✓ Investigation CRUD endpoints functional  
✓ RBAC enforced on protected endpoints  
✓ Basic test suite passes (10+ tests)  
✓ Error handling returns proper JSON  
✓ Configuration loads from YAML + env vars  
✓ All code has type hints (mypy passes)  
✓ Documentation complete and accurate

---

## Development Workflow

### Use Ollama for Code Generation
```bash
ollama run qwen2.5-coder:1.5b "Generate [component/endpoint/model]"
```
- Cost: $0 (runs locally)
- Speed: 120 tokens/sec on RTX 5060 Ti
- Use for: 90% of implementation

### Use Claude Sonnet When Stuck
```bash
# In Claude Code:
"I'm stuck on [problem]. Should I approach it with [option A] or [option B]?"
```
- Cost: ~$0.15-0.30 per call
- Budget: 6-8 calls total = $120
- Use for: Complex decisions, security review, architecture

### Git Workflow
```bash
# Daily commits
git add .
git commit -m "Phase 1: [component] - description"
git push origin main
```

---

## Next Phase

After Phase 1 is complete (day 14):
- **Phase 2:** OSINT Tool Integration (Sherlock, Sublist3r, Amass, Holehe, PhoneInfoga)
- **Phase 3:** API Integration (30+ data sources)
- **Phase 4:** Questionnaire Engine
- **Phase 5:** Advanced Analysis
- **Phase 6:** Professional Reporting
- **Phase 7:** Enterprise Features
- **Phase 8:** Production Deployment

Total: 6 more phases × 1-1.5 weeks each = 4 more weeks (6 weeks remaining)

---

**Last Updated:** May 2026 | **Status:** Ready to Implement
