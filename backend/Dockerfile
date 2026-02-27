FROM python:3.11-slim

WORKDIR /app

# system deps (psycopg2 needs libpq)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

EXPOSE 5001

# If your backend run command differs, tell me your current command.
CMD ["python", "-m", "flask", "--app", "app", "run", "--host=0.0.0.0", "--port=5001"]