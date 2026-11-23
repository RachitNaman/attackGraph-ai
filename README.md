# AttackGraph AI

A cybersecurity project for exploring attack paths through a network graph and generating context-based explanations and remediation ideas.

**Stack:** Python · FastAPI · Neo4j · Qdrant · LangChain · LangGraph · Gemini · Next.js · React Flow

## What is implemented

- FastAPI routes for graph queries, traversal, retrieval and AI analysis
- Neo4j models and queries for hosts, services, vulnerabilities and their relationships
- Qdrant integration for semantic retrieval
- A LangGraph workflow for query understanding, graph traversal, context enrichment, path scoring and explanation generation
- A Next.js dashboard with an interactive sample graph and an analysis request flow

## Demo and scope

The dashboard uses a seeded sample graph. The analysis flow calls a separately configured backend. A loaded dashboard alone does not confirm that the backend or AI service is available.

This repository is an application project, not a validated security assessment tool. Sample data and generated explanations should not be treated as findings about a real network.

## Repository layout

```text
backend/
  app/          API routes, graph queries, retrieval and analysis workflow
  scripts/      Development data seed scripts
frontend/
  src/          Next.js app, dashboard, components and API client
```

Both backend and frontend source are tracked in this repository. The frontend is not a Git submodule in the reviewed version.

## Local setup

These steps describe the current source configuration. The full stack has not been smoke-tested as part of this documentation update.

### Prerequisites

- Python 3.11, matching `backend/.python-version`
- Node.js and npm compatible with the Next.js version in `frontend/package.json`
- Running Neo4j and Qdrant services
- A Gemini API key with access to the configured generation and embedding models for AI features

### Backend

From the repository root:

```sh
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

On Windows, activate with `.venv\Scripts\activate` instead.

Update `.env` with your own local database settings and API key. Keep it out of version control. Change all example secrets before any deployment. Disable optional tracing unless you intend to use it.

Important settings:

| Setting | Purpose |
|---|---|
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` | Graph database connection |
| `QDRANT_HOST`, `QDRANT_PORT`, `QDRANT_API_KEY` | Vector database connection |
| `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_EMBEDDING_MODEL` | AI generation and embeddings |
| `EMBEDDING_DIMENSIONS` | Must match the configured embedding model and vector collections |

Then start the API:

```sh
uvicorn app.main:app --reload --port 8000
```

The application connects to Neo4j and Qdrant during startup. Open `http://localhost:8000/docs` for the interactive API reference.

### Frontend

In another terminal, from the repository root:

```sh
cd frontend
npm ci
npm run dev
```

The API client defaults to `http://localhost:8000`. Set `NEXT_PUBLIC_API_URL` in `frontend/.env.local` when the backend is elsewhere, and restart the frontend after changing it. Open `http://localhost:3000`.

### Development data

Inspect `backend/scripts/seed_graph.py` and `backend/scripts/seed_qdrant.py` before running them against a local development database. They write sample data; do not run them against a database containing real or valuable data. The Qdrant seed flow requires Gemini access and may incur API charges.

## Selected API routes

The full route schemas are available in the local Swagger UI.

| Area | Example |
|---|---|
| Health | `GET /api/v1/health` |
| Graph summary | `GET /api/v1/graph/summary` |
| Reachability | `GET /api/v1/traversal/reachable/{host_id}` |
| Shortest path | `GET /api/v1/traversal/shortest-path` |
| Retrieval | `POST /api/v1/rag/analyze` |
| AI analysis | `POST /api/v1/analysis/analyze` |

## Current limitations and next steps

- The dashboard's displayed graph is seeded, rather than evidence of a live graph query.
- No test suite, CI workflow or Docker/Compose configuration was present in the reviewed public tree.
- Performance claims need a reproducible benchmark, dataset description and recorded results before being presented as verified measurements.
- Deployment security, authentication coverage and CORS policy need a separate review before real-world use.

## License

No license has been selected for this repository. A license should be added only after the owner chooses its terms.
