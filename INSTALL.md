# Installation Guide

This repository can be deployed as a self-hosted service using Docker Compose or Kubernetes.

## Prerequisites

- Docker Engine
- Docker Compose
- kubectl (for Kubernetes)
- A Kubernetes cluster (Minikube, kind, EKS, GKE, AKS, etc.)
- Git
- Python dependencies are installed in the Docker image automatically via `requirements.txt`

---

## Docker Compose

A `docker-compose.yml` file is included for local self-hosted deployment.

### Start the application

1. Create or update the `.env` file in the repository root with secure values for:
   - `JWT_SECRET_KEY`
   - `ADMIN_TOKEN`
   - `FLASK_ENV`
   - `CORS_ORIGINS`

2. Start the services:

```bash
docker compose up --build -d
```

### Services included

- `api` → runs the Flask application on port `8000`
- `load_balancer` → optional load balancer service on port `8080`
- `mock_backends` → local mock backend servers on ports `5001`, `5002`, and `5003`

### Access the application

- API: `http://localhost:8000`
- Dashboard: `http://localhost:8000/dashboard`
- SDK demo: `http://localhost:8000/sdk`
- Load balancer dashboard: `http://localhost:8080/dashboard`

### Persistent storage

The Compose stack mounts the SQLite database to the local repository root, so request data and user state survive container restarts.

---

## Kubernetes

Kubernetes manifests are provided under the `k8s/` directory.

### Build the Docker image

For local clusters such as Minikube or kind, either build locally or push to a registry.

```bash
docker build -t api-rate-limiter:latest .
```

If using Minikube:

```bash
minikube image build -t api-rate-limiter:latest .
```

### Configure secrets

Edit `k8s/secret.yaml` and replace the placeholder values with strong secrets:

- `JWT_SECRET_KEY`
- `ADMIN_TOKEN`

### Apply the manifests

```bash
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### Verify deployment

```bash
kubectl get pods
kubectl get svc api-rate-limiter-service
```

### Access the service

If your cluster supports a LoadBalancer service, use the external IP from `kubectl get svc`.

For local clusters you can use port forwarding:

```bash
kubectl port-forward svc/api-rate-limiter-service 8000:80
```

Then open `http://localhost:8000`.

---

## Environment variables

The app reads configuration from environment variables. Common values include:

- `JWT_SECRET_KEY`
- `ADMIN_TOKEN`
- `DB_PATH`
- `FLASK_ENV`
- `IP_RATE_LIMIT`
- `IP_WINDOW`
- `TEMP_BAN_SECONDS`
- `BAN_MULTIPLIER`
- `CORS_ORIGINS`
- `ENABLE_SOCKETIO`

The Kubernetes manifests set default values in `k8s/configmap.yaml`.

---

## Notes

- `Dockerfile` builds the app image using `gunicorn`.
- `docker-compose.yml` is designed for simple self-hosted deployment and local development.
- Kubernetes manifests are intentionally minimal so they can be adapted to production clusters.
- The SQLite database is stored in mounted persistent storage by default.

---

## Optional extensions

Once the app is running, teams can extend the self-hosted deployment with:

- external PostgreSQL support
- SMTP email notifications via env vars
- secure Kubernetes secrets management
- monitoring and alerting integrations
- Helm packaging for repeatable installs
