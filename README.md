# AttackGraph AI

AttackGraph AI is an AI-powered cyber attack path analysis platform.
It combines:
- **Neo4j** for attack graph modeling
- **Qdrant** for semantic search over CVEs / asset context / threat intel
- **Google Gemini** (via LangChain + LangGraph) for natural-language analysis and recommendations

> Note: The `frontend/` in this repository is currently a **Git submodule** (not regular source code tracked inside this repo). The backend is fully contained under `backend/`.

## What it does

- Ingest and represent assets, services, vulnerabilities, and relationships as a graph
- Compute attack paths, reachable systems, blast radius, and privilege escalation chains
- Enrich results with semantic CVE and threat intel context using a vector database
- Generate AI explanations, executive summaries, and remediation recommendations

---

## Repository layout

```
.
├── backend/                 # FastAPI backend (Neo4j + Qdrant + Gemini)
├── frontend/                # Git submodule (UI code lives in a separate repo)
└── README.md
```

---

## Backend (FastAPI)

### Tech stack

- **FastAPI** + **Uvicorn**
- **Neo4j** (graph DB)
- **Qdrant** (vector DB)
- **Gemini**: `google-generativeai` + `langchain-google-genai`
- **Orchestration**: LangChain + LangGraph
- Optional: **Redis / Celery** (dependencies included)

### Key folders

```
backend/
├── app/
│   ├── api/v1/              # Route handlers (HTTP layer)
│   ├── agents/              # LangGraph agent(s)
│   ├── core/                # Settings, logging, exceptions
│   ├── graph/               # Neo4j client + schema/constraints
│   ├── models/              # Pydantic request/response models
│   ├── prompts/             # Prompt templates
│   ├── services/            # Business logic (graph traversal, scoring, RAG)
│   └── vectorstore/         # Qdrant client + collections
├── scripts/                 # Helper scripts (ingestion/ops)
├── requirements.txt
└── .env.example
```

### App lifecycle

On startup (`backend/app/main.py`):
1. Connect to **Neo4j** and initialize schema/constraints
2. Connect to **Qdrant** and initialize collections

On shutdown:
- Cleanly disconnect from Neo4j and Qdrant

### Configuration

Create your env file:

```bash
cp backend/.env.example backend/.env
```

Most important variables:

- `GEMINI_API_KEY` — required for AI analysis endpoints
- `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`
- `QDRANT_HOST`, `QDRANT_PORT`, `QDRANT_API_KEY` (optional for local)
- `FRONTEND_URL` — used for CORS

See: `backend/.env.example` for the full list.

### Run backend locally

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt

cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs:
- Swagger: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## API overview (v1)

Base path: `/api/v1`

### Health
- `GET /health` — checks Neo4j + Qdrant connectivity

### Graph
Prefix: `/graph`
- `GET /graph/summary` — counts by node/relationship type
- `GET /graph/hosts` — paginated hosts
- `GET /graph/hosts/internet-facing` — internet-exposed hosts
- `GET /graph/hosts/{host_id}` — host detail (services + vulns)
- `GET /graph/hosts/{host_id}/blast-radius` — blast radius (simple)
- `GET /graph/attack-paths` — paths from source to target (optional)
- `GET /graph/attack-paths/to-database` — paths from internet → any DB
- `GET /graph/attack-paths/critical` — highest-risk ranked paths
- `GET /graph/risk/highest-risk-nodes` — hosts ranked by risk score
- `GET /graph/vulnerabilities/exploitable` — exploitable vulns

### Traversal
Prefix: `/traversal`
- `GET /traversal/reachable/{host_id}` — all reachable nodes within hops
- `GET /traversal/reachable/{host_id}/by-type/{node_type}` — filter reachable by type
- `GET /traversal/reachable/reverse/{target_id}` — entry points that can reach target
- `GET /traversal/shortest-path` — shortest path between two nodes
- `GET /traversal/shortest-path/all` — all equally-short paths
- `GET /traversal/vulnerable-hosts` — hosts ranked by composite risk score
- `GET /traversal/vulnerable-hosts/unpatched` — hosts with unapplied patches
- `GET /traversal/blast-radius/{host_id}` — detailed blast radius report
- `GET /traversal/escalation/chains` — privilege escalation chains
- `GET /traversal/escalation/to-root` — internet entry → root/admin paths
- `GET /traversal/escalation/service-accounts` — service-account escalation
- `GET /traversal/escalation/cross-subnet` — cross-subnet escalation

### RAG (Vector search + Graph RAG)
Prefix: `/rag`
- `POST /rag/analyze` — build Graph RAG context (paths + Qdrant enrichment)
- `GET /rag/search/cves` — semantic CVE search
- `GET /rag/search/assets` — semantic asset search
- `GET /rag/search/intel` — semantic threat intel search
- `GET /rag/search/all` — search across all vector collections
- `POST /rag/ingest/cve` — store CVE into Qdrant
- `POST /rag/ingest/intel` — store threat intel into Qdrant

### AI Analysis (LangGraph agent)
Prefix: `/analysis`
- `POST /analysis/analyze` — full AI attack-path analysis (JSON response)
- `POST /analysis/analyze/stream` — streaming analysis via SSE

---

## Frontend

`frontend/` is configured as a **Git submodule** in this repo.

To document the frontend properly here, we need one of the following:
1. The **frontend submodule repository URL** (from `.gitmodules`), or
2. You convert the submodule into actual code committed in this repo.

Once the submodule target repo is known, the README can include:
- Pages/routes and UI features
- API integration details (base URL, SSE streaming)
- Environment variables and dev scripts

---

## Troubleshooting

- **CORS errors**: ensure `FRONTEND_URL` in `backend/.env` matches the frontend origin.
- **Neo4j/Qdrant degraded health**: verify services are running and creds/hosts are correct.
- **Gemini errors**: confirm `GEMINI_API_KEY` is set and has quota.

---

## License

Add your license here.
