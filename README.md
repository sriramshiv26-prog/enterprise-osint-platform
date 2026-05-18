# Enterprise OSINT Platform

Autonomous Open Source Intelligence platform powered by Claude's tool-use API with 30+ integrated OSINT data sources, questionnaire-driven investigation workflows, and professional reporting.

**Timeline:** 4-6 weeks | **Budget:** $120 (Claude Sonnet) + FREE local Ollama | **Status:** Phase 1 Ready

## Quick Links
- [Phase 1 Implementation Plan](PHASE_1_PLAN.md) — Step-by-step (11 steps, 2 weeks)
- [GPU & Model Strategy](docs/GPU_STRATEGY.md) — Hybrid Ollama + Claude approach
- [Architecture](docs/ARCHITECTURE.md) — Technical design
- [OSINT Data Sources](docs/OSINT_SOURCES.md) — 30+ integrations

## Features
- ✓ Claude-powered autonomous investigation (tool-use API)
- ✓ 30+ OSINT tools integrated (Sherlock, Sublist3r, Amass, etc.)
- ✓ Legitimate dark web monitoring
- ✓ Questionnaire-driven workflow
- ✓ Multi-user with RBAC
- ✓ Advanced correlation & timeline analysis
- ✓ REST + GraphQL APIs
- ✓ Kubernetes-ready deployment

## Technology Stack
- **Backend:** Python 3.11, FastAPI, SQLAlchemy, Celery
- **Database:** PostgreSQL, Redis, Elasticsearch, Neo4j
- **Frontend:** React 18, TypeScript, TailwindCSS
- **Deployment:** Docker, Kubernetes, Helm
- **LLM:** Claude 3.5 Sonnet (Anthropic API)

## Project Structure
```
enterprise-osint-platform/
├── src/
│   ├── osint_platform/
│   │   ├── __init__.py
│   │   ├── agent/              # Claude orchestration
│   │   ├── tools/              # OSINT tool wrappers
│   │   ├── api/                # REST API endpoints
│   │   ├── db/                 # Database models
│   │   ├── auth/               # Authentication & RBAC
│   │   ├── questionnaire/      # Investigation workflow
│   │   ├── analysis/           # Correlation, timeline
│   │   └── reporting/          # Report generation
│   └── frontend/               # React app
├── tests/                       # Test suite
├── config/                      # Configuration files
├── deployments/                 # K8s, Docker configs
├── docs/                        # Documentation
└── scripts/                     # Utilities

## Getting Started
```bash
# Clone
git clone <repo>
cd enterprise-osint-platform

# Setup development environment
make setup

# Run locally
make dev

# Run tests
make test

# Deploy to Kubernetes
make deploy
```

## Documentation
- [Architecture](/docs/ARCHITECTURE.md)
- [API Reference](/docs/API.md)
- [Questionnaire System](/docs/QUESTIONNAIRE.md)
- [Tool Integration](/docs/TOOLS.md)
- [Dark Web Monitoring](/docs/DARKWEB.md)
- [RBAC & Security](/docs/SECURITY.md)

## Timeline
- **Week 1-2:** Infrastructure, Database, API framework
- **Week 2-3:** Tool integrations, API adapters
- **Week 3-4:** Questionnaire engine, Analysis
- **Week 4-6:** Reporting, Enterprise features, Deployment

## Cost Analysis
- **Development:** ~$1,600 (Hybrid Sonnet+Haiku)
- **Infrastructure:** ~$500-1000/month (AWS/GCP)
- **Per Investigation:** ~$0.60 (vs competitors: $5-50)

## Team
- 3 Senior Backend Developers
- 1 DevOps Engineer
- 1 Frontend Developer (Part-time)

## License
TBD

## Contact
[Add contact info]

---

**Last Updated:** May 2026  
**Version:** 0.1.0-alpha  
**Status:** Active Development (Phase 1)
