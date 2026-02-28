# SOC Log Analyzer

A full-stack SOC-style log triage application that ingests web server logs (Nginx / Apache style), runs a frozen rule-based anomaly detector, and generates an LLM based analyst-friendly report grouped by source IP.

Designed as a take-home project:
- Cloud deployable
- Fully Docker reproducible
- Includes sample logs
- Clean architecture
- Clear demo workflow

---
## Demo
Live link:
https://soc-log-analyzer.vercel.app/login
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
- AI executive summary (GROQ integration)
- Dockerized full stack with PostgreSQL

---

## Detection Rules

The following detection rules are implemented and intentionally frozen:

- **IP request burst detection**: flags source IPs that generate an unusually high number of requests over the full log window.
- **Minute-based burst detection**: flags IPs that exceed a high request count within a single minute (short spike behavior).
- **Repeated authentication failures**: detects repeated failed login attempts from the same IP (brute-force style pattern).
- **Suspicious path probing**: flags IPs that request multiple known sensitive endpoints (common recon / exploit probing).
- **High server error rate (5xx spike)**: detects IPs triggering many server errors, indicating possible exploit attempts or unstable backend behavior.
- **Excessive 404 responses**: flags IPs producing many not-found responses, often tied to scanning or forced browsing.
- **High unique endpoint access**: detects IPs that hit an unusually large number of distinct paths (broad enumeration behavior).
- **Endpoint-specific 5xx concentration**: flags repeated 5xx errors concentrated on the same endpoint, suggesting targeted abuse.

Classification layer applied to each anomaly (not separate detection rules):

- **Severity tagging**: assigns `low`, `medium`, or `high` based on rule type and intensity.
- **Confidence scoring**: computes a deterministic confidence score per anomaly based on thresholds and supporting signals.

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

AI:
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

## Run With Docker

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
- A [Groq API Key](https://console.groq.com/).



1. **Clone the repository:**

   ```
   git clone (https://github.com/Kinsu1212/soc-log-analyzer)
   cd soc-log-analyzer
   ```

2. **Copy the environment variables template and fill it out:**

   ```
   cp .env.example .env
   ```
   Open .env (in the project root) and set your database credentials.
   You can choose any values for local development:

   Then open `.env` in your editor and add values for `POSTGRES_USER`, `POSTGRES_PASSWORD`, etc. If you have a GROQ API key, add it as well:

   ```
   GROQ_API_KEY=your_actual_groq_key_here
   POSTGRES_USER=soc
   POSTGRES_PASSWORD=socpass
   POSTGRES_DB=soclog
   ```

3. **Start the application:**

   ```
   docker compose up -d --build
   ```

   You can now access the frontend at `http://localhost:3000` and the backend health check at `http://localhost:5001/api/health`.
   
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
