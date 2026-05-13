# AttackGraph AI

An intelligent attack path analysis system that combines Neo4j graph databases, Qdrant vector search, and generative AI to identify and analyze security vulnerabilities and attack paths.

## Overview

AttackGraph AI is a full-stack application designed to:
- Map network assets and vulnerabilities as a graph database
- Identify potential attack paths using AI-powered analysis
- Provide risk scoring and remediation recommendations
- Enable security teams to visualize and understand attack surfaces

## Tech Stack

### Backend
- **Framework**: FastAPI (Python)
- **Graph Database**: Neo4j
- **Vector Database**: Qdrant
- **AI/LLM**: Google Gemini API with LangChain
- **Async Tasks**: Redis (optional)

### Frontend
- **Framework**: Next.js (TypeScript)
- **Styling**: Tailwind CSS
- **UI Components**: Custom React components

### Infrastructure
- **Containerization**: Docker & Docker Compose
- **Environment Management**: Python venv

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 18+
- Git

### Setup with Docker

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd AttackGraph
   ```

2. **Configure environment**
   ```bash
   cp attackgraph-ai/backend/.env.example attackgraph-ai/backend/.env
   # Edit .env with your API keys and credentials
   ```

3. **Start services**
   ```bash
   docker-compose up -d
   ```

4. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000/docs
   - Neo4j Browser: http://localhost:7474
   - Qdrant Dashboard: http://localhost:6333/dashboard

### Local Development

#### Backend
```bash
cd attackgraph-ai/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Run server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend
```bash
cd attackgraph-ai/frontend

# Install dependencies
npm install

# Run dev server
npm run dev
```

## Project Structure

```
AttackGraph/
├── attackgraph-ai/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── agents/        # AI agent definitions
│   │   │   ├── api/           # API route handlers
│   │   │   ├── core/          # Core business logic
│   │   │   ├── graph/         # Graph database queries
│   │   │   ├── ingestion/     # Data ingestion pipelines
│   │   │   ├── models/        # Pydantic models
│   │   │   ├── prompts/       # LLM prompt templates
│   │   │   ├── services/      # Business services
│   │   │   ├── utils/         # Utility functions
│   │   │   └── vectorstore/   # Vector DB operations
│   │   ├── requirements.txt
│   │   └── .env.example
│   ├── frontend/
│   │   ├── app/               # Next.js pages
│   │   ├── public/            # Static assets
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── docs/                  # Documentation
├── docker-compose.yml
└── README.md
```

## Configuration

### Required Environment Variables
- `GEMINI_API_KEY`: Google Gemini API key (get from https://aistudio.google.com/app/apikey)
- `NEO4J_PASSWORD`: Neo4j database password
- `SECRET_KEY`: Application secret key (min 32 chars)

### Optional Environment Variables
- `LANGCHAIN_API_KEY`: LangSmith tracing (for debugging)
- `QDRANT_API_KEY`: Qdrant cloud API key (if using cloud)

See `attackgraph-ai/backend/.env.example` for all configuration options.

## API Documentation

Once the backend is running, visit http://localhost:8000/docs for interactive API documentation (Swagger UI).

### Key Endpoints
- `GET /health` - Health check
- `GET /` - Root endpoint
- API v1 endpoints under `/api/v1/`

## Development Guidelines

- Follow PEP 8 for Python code
- Use TypeScript for all frontend code
- Run linters before committing: `eslint` (frontend)
- Write tests for new features

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Commit changes: `git commit -am 'Add feature'`
3. Push to branch: `git push origin feature/your-feature`
4. Submit a pull request

## Troubleshooting

### Backend issues
- **Uvicorn error "Attribute 'app' not found"**: Ensure `app/main.py` has a FastAPI instance named `app`
- **Neo4j connection refused**: Check Neo4j container is running and credentials are correct
- **Gemini API errors**: Verify your API key is valid and has quota

### Frontend issues
- **Port 3000 already in use**: Change port or kill existing process
- **Node modules issues**: Delete `node_modules` and `package-lock.json`, then run `npm install`

## Support

For issues or questions, please open a GitHub issue or contact the development team.

## License

[Add your license here]
