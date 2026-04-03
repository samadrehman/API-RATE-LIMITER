# API Rate Limiter + Load Balancer

 API infrastructure with:

- Rate limiting (tier-based + per-IP controls)
- JWT authentication and token refresh
- Admin controls (tier upgrades, block/unblock, logs, audit)
- Browser SDK (`/sdk.js`) and SDK setup page (`/sdk`)
- Load balancer with strategy switching and health checks
- Mock backends for local end-to-end testing

## Current Architecture

```text
Client
  -> Rate Limiter (Flask, :5000)
      -> optional: Load Balancer (aiohttp, :8080)
          -> Backend servers (:5001, :5002, :5003)
```

## What Is In This Repo

- `app.py`: Main rate limiter API + auth + admin + dashboard + SDK routes
- `auth.py`: JWT auth manager utilities
- `load_balancer.py`: Async load balancer + dashboard + strategy control
- `mock_backends.py`: Local backend simulators
- `run_system.py`: One-command orchestrator
- `database.py`: SQLite migration/check helper
- `static/demo.html`: SDK setup/demo web page (served at `/sdk`)
- `static/ratelimiter-sdk.js`: Browser SDK (served at `/sdk.js`)

## Quick Start

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Start everything (recommended)

```bash
python run_system.py --dev --skip-db
```

This starts:

- Main app on `http://localhost:5000`
- Load balancer on `http://localhost:8080`
- Mock backends on `http://localhost:5001..5003`

### 3) Open UIs

- Rate limiter dashboard: `http://localhost:5000/dashboard`
- SDK setup/demo page: `http://localhost:5000/sdk`
- Load balancer dashboard: `http://localhost:8080/dashboard`

## Manual Startup (Alternative)

Start in separate terminals:

```bash
python mock_backends.py
python load_balancer.py
python app.py
```

## API Overview

### Rate Limiter (`:5000`)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Service info JSON |
| GET | `/dashboard` | Human-friendly docs/dashboard |
| GET | `/health` | Health check |
| GET | `/api/metrics` | Realtime counters |
| GET | `/data?api_key=KEY` | Protected example endpoint |
| GET | `/usage?api_key=KEY` | Usage/limit status |
| GET | `/sdk` | SDK web setup page |
| GET | `/sdk.js` | Browser SDK script |
| POST | `/sdk/check` | SDK preflight check |
| POST | `/sdk/track` | SDK request tracking |

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

### Load Balancer (`:8080`)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/dashboard` | Load balancer UI |
| GET | `/stats` | Current backend/cache stats |
| POST | `/change_strategy` | Switch strategy |
| ANY | `/{path:.*}` | Proxy traffic to selected backend |

## Auth Flow Example

### Register

```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password",
    "tier": "free"
  }'
```

### Login

```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password"
  }'
```

Token expiry defaults:

- Access token: 1 hour
- Refresh token: 7 days

### Create API key (JWT)

```bash
curl -X POST http://localhost:5000/auth/create_api_key \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## SDK Usage

### Option A: Use SDK setup page

Open `http://localhost:5000/sdk` and use the UI guide.

### Option B: Script integration

```html
<script src="http://localhost:5000/sdk.js"></script>
<script>
  RateLimiter.init({
    apiKey: 'YOUR_API_KEY',
    backendUrl: 'http://localhost:5000',
    showWidget: true,
    showGuideButton: true
  });
</script>
```

### Optional: Route traffic via your gateway

```javascript
RateLimiter.init({
  apiKey: 'YOUR_API_KEY',
  backendUrl: 'http://localhost:5000',
  routeTrafficTo: 'http://localhost:5000'
});
```

Notes:

- `backendUrl` is for SDK control endpoints (`/sdk/check`, `/sdk/track`, `/usage`).
- `routeTrafficTo` rewrites outgoing request URLs to your chosen base URL.

## Database Notes

Default development database is SQLite (`ratelimiter.db`).

Use helper commands:

```bash
python database.py          # migrate/update schema
python database.py check    # inspect schema
python database.py verify   # integrity checks
```

PostgreSQL setup script exists at `setup_postgress.sql` for environments where you want to prepare a PostgreSQL schema manually.

## Configuration

Common environment variables:

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

### Port already in use

- Stop existing processes or change ports before startup.

### SDK page loads but SDK script is old

- Use `GET /sdk.js` from this app instance (it serves `static/ratelimiter-sdk.js`).

### Database schema errors

```bash
python database.py
```

### JWT errors

- Ensure `Authorization` header uses `Bearer <token>`.
- Verify secret key is consistent for all app instances.

### Load balancer returns backend errors

- Confirm mock backends are running on `:5001..5003`.
- Check LB stats at `http://localhost:8080/stats`.


