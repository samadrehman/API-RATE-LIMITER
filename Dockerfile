FROM python:3.11-slim

# Prevents Python from buffering logs
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# System deps (keep minimal)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "app:app", "--worker-class", "gthread", "--threads", "4", "--workers", "2", "--bind", "0.0.0.0:8000"]
