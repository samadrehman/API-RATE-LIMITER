# API Rate Limiter

Production-style API rate limiter project with JWT auth, admin controls, SDK integration, mock backends, and an optional load balancer.

## What this project does

- Protects API endpoints with tier-based limits.
- Supports register/login/refresh authentication flow.
- Supports API key creation and usage tracking.
- Includes usage analytics endpoints and dashboard views.
- Provides admin actions for user tier upgrades and key blocking.
- Includes a browser SDK (`/sdk.js`) and demo/setup page (`/sdk`).
- Includes a standalone load balancer and geo-routing modules for advanced routing experiments.

## Usage Analytics Dashboard

Usage analytics is available through existing dashboard and metrics endpoints.

- Main dashboard: `/dashboard`
- Usage per key: `/usage?api_key=YOUR_KEY`
- Runtime metrics: `/api/metrics`
- Admin logs and audit: `/logs`, `/admin/audit`

What you can monitor:

- Current tier and per-minute limits
- Remaining requests in active window
- Request volume trends and counters
- Admin actions and operational logs

If you need a dedicated BI-style analytics UI, use these endpoints as the source and build a separate frontend panel.

## Premium / Paid section

Short answer: there is no paid billing or subscription system implemented.

- The code has tier names: `free`, `basic`, `premium`, and `enterprise`.
- These tiers are technical rate-limit levels, not a payment gateway integration.
- No Stripe/PayPal/subscription checkout logic is included in this repository.
- Tier changes are done through app logic/admin endpoints (for example `/admin/upgrade_tier`).

## Project architecture

```text
Client
  -> Main API (Flask, default :5000)
       -> SQLite or PostgreSQL schema support
       -> optional SDK endpoints and dashboard
  -> optional Load Balancer (aiohttp, default :8080)
       -> Mock backends (:5001, :5002, :5003)
```

## Full file inventory (what each file does)

| File | Purpose |
|---|---|
| `app.py` | Main Flask application. Includes auth routes, protected data routes, usage routes, admin routes, dashboard HTML, SDK routes (`/sdk`, `/sdk.js`, `/sdk/check`, `/sdk/track`), metrics, and core rate-limit logic. |
| `auth.py` | JWT auth manager module. Handles token generation, verification, refresh, revocation, decorators for protected routes, and auth endpoint initialization helpers. |
| `database.py` | Database setup/migration helper for SQLite schema and maintenance tasks (backup, schema checks, updates). |
| `geo_router.py` | Geographic routing utilities. Resolves IP geolocation and selects nearest datacenter/backends. Useful with multi-region routing setups. |
| `load_balancer.py` | Async load balancer service with multiple balancing strategies (round robin, least connections, weighted, IP hash, adaptive), health checks, and dashboard/stats endpoints. |
| `log_manager.py` | Logging and abuse-detection utilities used by system components. Supports request logging, suspicious pattern detection, and log file management. |
| `mock_backends.py` | Runs mock backend Flask servers for local testing of routing and load-balancing behavior. |
| `run_system.py` | One-command orchestrator for local end-to-end startup (checks deps, starts components, monitors processes, graceful shutdown). |
| `ssl_setup.py` | SSL/TLS helper for generating self-signed certs and production SSL guidance/validation. |
| `setup_postgress.sql` | PostgreSQL schema/setup script (database, users, tables, indexes). Note: filename is intentionally `postgress` in this repo. |
| `requirements.txt` | Python dependency list for API app, auth/security, async networking, optional DB/metrics/testing/dev tooling. |
| `Dockerfile` | Container build definition. Installs dependencies and runs app with gunicorn on port 8000. |
| `railway.toml` | Railway deployment config using nixpacks and gunicorn start command. |
| `static/demo.html` | Browser demo page for connecting and testing SDK behavior against the backend. |
| `static/ratelimiter-sdk.js` | Client-side SDK that checks limits before requests, tracks calls, and can show usage widgets/errors. |
| `README.md` | Project documentation (this file). |
| `API_DOCUMENTATION.md` | Dedicated API reference with endpoint-by-endpoint details and examples. |
| `EMAIL_NOTIFICATIONS.md` | Email notification feature spec, event model, and integration guidance. |

## Separate API documentation

The complete API reference is available in `API_DOCUMENTATION.md`.

- It contains endpoint groups, auth modes, expected payloads, error model, and quick examples.

## Quick start

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Start full local system (recommended)

```bash
python run_system.py --dev --skip-db
```

Typical local ports:

- Main API: `http://localhost:5000`
- Load balancer: `http://localhost:8080`
- Mock backends: `http://localhost:5001`, `:5002`, `:5003`

### 3) Open useful pages

- API dashboard/docs: `http://localhost:5000/dashboard`
- SDK setup/demo page: `http://localhost:5000/sdk`
- Load balancer dashboard: `http://localhost:8080/dashboard`

## Manual startup (alternative)

Run each component in separate terminals:

```bash
python mock_backends.py
python load_balancer.py
python app.py
```

## Main endpoints

### Core API (`:5000`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API info/health-style summary JSON |
| GET | `/dashboard` | Human-readable dashboard/docs page |
| GET | `/data?api_key=KEY` | Protected sample data endpoint |
| GET | `/usage?api_key=KEY` | Current usage and limits for API key |
| GET | `/api/metrics` | Runtime metrics |
| GET | `/sdk` | SDK setup/demo page |
| GET | `/sdk.js` | Browser SDK script |
| POST | `/sdk/check` | SDK pre-request allow/deny check |
| POST | `/sdk/track` | SDK request tracking endpoint |

### Authentication (`:5000`)

| Method | Endpoint |
|---|---|
| POST | `/auth/register` |
| POST | `/auth/login` |
| POST | `/auth/refresh` |
| POST | `/auth/logout` |
| GET | `/auth/me` |
| POST | `/auth/create_api_key` (JWT required) |

### Admin (`:5000`)

Admin endpoints require `Authorization: Bearer <ADMIN_TOKEN>`.

| Method | Endpoint |
|---|---|
| GET | `/admin/users` |
| POST | `/admin/upgrade_tier` |
| POST | `/admin/block_key` |
| POST | `/admin/unblock_key` |
| GET | `/logs` |
| GET | `/admin/audit` |

### Load balancer (`:8080`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/dashboard` | Load balancer UI |
| GET | `/stats` | Backend/cache/load stats |
| POST | `/change_strategy` | Switch balancing strategy |
| ANY | `/{path:.*}` | Proxy requests to selected backend |

## Tier limits

Configured in application logic:

- `free`: 5 requests/minute
- `basic`: 20 requests/minute
- `premium`: 100 requests/minute
- `enterprise`: 1000 requests/minute

These are technical limits and not connected to a payment processor by default.

## Database notes

- Default local storage is SQLite (`ratelimiter.db`).
- PostgreSQL schema/bootstrap SQL is available in `setup_postgress.sql`.

Helpful DB commands:

```bash
python database.py
python database.py check
python database.py verify
```

## Deployment notes

- Docker: use `Dockerfile` (gunicorn serves `app:app` on port 8000).
- Railway: see `railway.toml` for build/start settings.

## Email notifications

Email notifications are implemented and configurable.

- Feature spec: `EMAIL_NOTIFICATIONS.md`
- Current code status: SMTP notifier is live with async, fail-safe delivery
- Implemented events include tier changes, abuse alerts, block/unblock actions, key bans, and rate-limit spikes

Required env vars to enable:

- `EMAIL_NOTIFICATIONS_ENABLED=true`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `EMAIL_FROM`, `ALERT_EMAIL_TO`
- Optional: `SMTP_USE_TLS`, `SMTP_USE_SSL`, `SMTP_TIMEOUT_SECONDS`, `EMAIL_EVENT_COOLDOWN_SECONDS`

This lets you add notifications safely without changing existing API behavior first.

## Environment variables (common)

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

## Troubleshooting

- If a port is busy, stop old processes or change the port config.
- If SDK behavior seems old, confirm you are loading `/sdk.js` from the current running app.
- If auth fails, verify `Authorization: Bearer <token>` format and JWT secret consistency.
- If load balancer fails, verify mock backends are running on ports `5001-5003`.


