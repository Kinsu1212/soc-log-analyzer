# SOC Log Analyzer

A full-stack SOC-style log triage application that ingests web server logs (Nginx / Apache style), runs a frozen rule-based anomaly detector, and generates an analyst-friendly report grouped by source IP.

Designed as a take-home project:
- Cloud deployable
- Fully Docker reproducible
- Includes sample logs
- Clean architecture
- Clear demo workflow

---

## Demo (Local)

Frontend:
http://localhost:3000

Backend health:
http://localhost:5001/api/health

---

## Features

- JWT authentication (login / signup)
- Log file upload and analysis
- Findings grouped by source IP
- Rule-based anomaly detection (frozen logic)
- Severity classification
- Confidence scoring
- Search + filter in report view
- Optional AI executive summary (GROQ integration)
- Dockerized full stack with PostgreSQL

---

## Detection Rules (Frozen)

The following rules are implemented and intentionally frozen:

- IP request burst detection
- Minute-based burst detection
- Repeated authentication failures
- Severity tagging (low / medium / high)
- Confidence scoring per anomaly

No further expansion was done to keep scope controlled for the take-home.

---

## Architecture

Next.js Frontend  
→ Flask API  
→ PostgreSQL  

Docker Compose orchestrates:

- frontend (Next.js)
- backend (Flask)
- db (PostgreSQL)
- persistent volume: soc_pg_data

---

## Tech Stack

Frontend:
- Next.js (App Router)
- TypeScript
- Tailwind CSS

Backend:
- Flask (App Factory pattern)
- SQLAlchemy ORM
- JWT Authentication

Database:
- PostgreSQL

DevOps:
- Docker
- Docker Compose

Optional AI:
- GROQ API (env-driven, safe to disable)

---

## Project Structure

```
soc-log-analyzer/
│
├── backend/
│   ├── app/
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── Dockerfile
│
├── sample_logs/
│
├── docker-compose.yml
├── .env.example
├── README.md
```

---

## Environment Variables

Create a `.env` file in the root by copying `.env.example`.

Required:

- POSTGRES_USER
- POSTGRES_PASSWORD
- POSTGRES_DB
- DATABASE_URL
- JWT_SECRET_KEY
- CORS_ORIGIN
- NEXT_PUBLIC_API_BASE_URL

Optional:

- GROQ_API_KEY
- GROQ_MODEL

---

## Run with Docker (Recommended)

From project root:

```bash
cp .env.example .env
docker compose up -d --build
```

Open:
http://localhost:3000

Stop:
```bash
docker compose down
```

Reset database (fresh start):
```bash
docker compose down -v
```

---

## Run Without Docker

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL="postgresql+psycopg2://USER:PASS@HOST:5432/DB"
export JWT_SECRET_KEY="your-secret"
export CORS_ORIGIN="http://localhost:3000"

flask run -p 5001
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## API Endpoints

- GET /api/health
- POST /api/auth/register
- POST /api/auth/login
- GET /api/uploads
- POST /api/uploads
- GET /api/uploads/<id>

---

## Sample Logs

Located in:

```
sample_logs/
```

Include:
- nginx_sample.log
- apache_sample.log

Each file contains mostly normal traffic with a small set of anomalies to demonstrate the detection engine.

---

## Design Decisions

- Detection logic is intentionally frozen
- SQLAlchemy ORM used for portability
- PostgreSQL used for deployment realism
- Docker ensures reproducibility
- Environment-driven configuration for production readiness

---

## Tradeoffs & Future Improvements

- Add Alembic migrations
- Add rate limiting
- Add file size validation
- Add more anomaly detectors (path traversal, SQL injection hints)
- Add CSV/PDF export
- Add pagination to report view
- Add role-based access control if needed

---

## Video Walkthrough

To be added:

Video should demonstrate:
- Architecture overview
- Detection rule explanation
- Upload workflow
- Report breakdown
- Database persistence
- Docker reproducibility
- Optional cloud deployment