# AI Cybersecurity SOC Agent

This project is a practical starter implementation of an AI SOC analyst.

It does these steps:

1. Ingest security logs through FastAPI.
2. Normalize and persist events in PostgreSQL with SQLAlchemy.
3. Detect suspicious activity using rules plus Isolation Forest.
4. Retrieve security playbook context with ChromaDB and sentence transformers.
5. Analyze incidents with a ReAct-style LangGraph agent using OpenAI or local Llama-compatible models.
6. Generate incident reports and mitigation recommendations.
7. Display events, incidents, and AI analysis in Streamlit.
8. Run with Docker Compose, Nginx, and GitHub Actions.

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open:

- API: http://localhost:8000/docs
- UI: http://localhost:8501

## Local Development

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

In another terminal:

```bash
streamlit run frontend/streamlit_app.py
```

## Example Event

```bash
curl -X POST http://localhost:8000/events \
  -H "Content-Type: application/json" \
  -d "{\"source\":\"auth.log\",\"host\":\"web-01\",\"username\":\"admin\",\"src_ip\":\"185.220.101.1\",\"event_type\":\"login_failed\",\"message\":\"Failed password for admin from 185.220.101.1 port 4444 ssh2\",\"severity\":\"medium\"}"
```
