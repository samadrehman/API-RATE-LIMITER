# Advanced Rate Limiter + Load Balancer System

A production-grade API infrastructure combining:
- **Rate Limiting** with real-time monitoring
- **Load Balancing** with multiple strategies
- **Caching Layer** for performance optimization
- **Health Monitoring** with automatic failover
- **Request Queuing** for handling spikes
- **Real-time Dashboards** for both systems
- **JWT Authentication** for secure token-based access
- **Geographic Routing** for optimal latency and compliance

---

## Architecture Overview

```
Internet → Load Balancer (port 8080) → Backend Servers (5001, 5002, 5003)
                ↓
          Rate Limiter
          Cache Layer
          Health Checks
          Geo Routing
          JWT Auth
```

---

## Project Status

### COMPLETED FEATURES

#### Core Infrastructure
- [x] Rate limiting with tiered access (free, basic, premium, enterprise)
- [x] Multiple load balancing strategies (round-robin, least connections, weighted, IP hash, adaptive)
- [x] In-memory caching with TTL
- [x] Health monitoring with automatic failover
- [x] Request queuing for traffic spikes
- [x] Circuit breaker pattern
- [x] Database connection pooling
- [x] Real-time WebSocket dashboards
- [x] Per-IP rate limiting
- [x] Admin operations (block/unblock, tier upgrades)

#### Security & Authentication (Week 1-2)
- [x] JWT token-based authentication
- [x] Token refresh mechanism
- [x] User registration and login endpoints
- [x] Cryptographically signed tokens
- [x] Token expiration (access: 1 hour, refresh: 7 days)
- [x] Backward compatibility with API key migration
- [x] Protected endpoints with `@require_jwt` decorator

#### Geographic Routing (Week 1-2)
- [x] IP geolocation resolution
- [x] Distance-based datacenter selection
- [x] Multiple datacenter support
- [x] Haversine distance calculation
- [x] Regional routing (US, EU, Asia Pacific, etc.)
- [x] Geo-statistics tracking
- [x] Response headers with datacenter info

### IN PROGRESS

#### Monitoring & Observability (Week 3)
- [ ] Prometheus metrics export
- [ ] Grafana dashboard integration
- [ ] Custom metrics for rate limiting
- [ ] Backend performance metrics
- [ ] Cache hit/miss tracking
- [ ] Geographic routing analytics

#### Containerization (Week 4)
- [ ] Docker containers for all services
- [ ] Docker Compose orchestration
- [ ] Multi-container networking
- [ ] Volume persistence
- [ ] Environment configuration

### PLANNED ENHANCEMENTS

#### Distributed Systems (Week 5-6)
- [ ] Redis for distributed rate limiting
- [ ] PostgreSQL for production database
- [ ] Distributed caching across instances
- [ ] Session synchronization
- [ ] Multi-instance deployment

#### Production Readiness (Week 7-8)
- [ ] HTTPS/TLS support
- [ ] API key rotation mechanism
- [ ] Password hashing with bcrypt
- [ ] Secure admin endpoints
- [ ] Environment variable management
- [ ] Database migrations with Alembic

#### Advanced Features (Future)
- [ ] Kubernetes deployment manifests
- [ ] Message queue integration (RabbitMQ/Kafka)
- [ ] DDoS protection enhancements
- [ ] Bot detection
- [ ] IP whitelisting/blacklisting
- [ ] OAuth2 authentication
- [ ] Multi-region geographic distribution
- [ ] CDN integration
- [ ] Log aggregation (ELK stack)
- [ ] Error tracking (Sentry)

---

## Setup Instructions

### 1. Install Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt
```

### 2. Start the Systems

**Terminal 1: Start Backend Servers**
```bash
python mock_backends.py
```
This starts 3 backend servers on ports 5001, 5002, 5003

**Terminal 2: Start Load Balancer**
```bash
python load_balancer.py
```
Load balancer runs on port 8080

**Terminal 3: Start Rate Limiter**
```bash
python app.py
```
Rate limiter runs on port 5000

---

## Features & Implementation Details

### 1. Load Balancing Strategies

#### Round Robin
- Distributes requests evenly across all backends
- Simple and predictable

#### Least Connections
- Routes to backend with fewest active connections
- Best for long-running requests

#### Weighted Round Robin
- Backends with higher weights get more traffic
- Useful for different server capacities

#### IP Hash (Sticky Sessions)
- Same client IP always goes to same backend
- Maintains session affinity

#### Least Response Time
- Routes to fastest backend
- Optimizes for performance

#### Adaptive (Smart)
- Considers multiple factors:
  - Active connections
  - Response time
  - Failure rate
- Dynamically adjusts to conditions

### 2. Health Monitoring
- Automatic health checks every 10 seconds
- Unhealthy backends removed from rotation
- Automatic recovery when backend comes back

### 3. Caching Layer
- In-memory cache with TTL (Time To Live)
- Cache hit/miss tracking
- Reduces backend load by ~30-50%

### 4. Rate Limiting
- Per-IP rate limiting (100 requests/minute)
- Tiered limits based on user subscription
- Prevents abuse and DDoS
- Automatic retry-after headers
- Progressive ban system with multipliers

### 5. Request Queuing
- Priority queue for handling traffic spikes
- Prevents backend overload
- Graceful degradation under load

### 6. Circuit Breaker Pattern
- Fails fast when backend is down
- Automatic retry logic
- Prevents cascade failures

### 7. Connection Pooling
- Reuses database connections
- Reduces overhead
- Better performance

### 8. Real-time Metrics
- WebSocket-based live updates
- Beautiful dashboards
- Historical data tracking

### 9. JWT Authentication
- Cryptographically signed tokens
- Self-contained (stateless)
- Automatic expiration
- Refresh token mechanism
- User metadata in tokens (tier, permissions)
- Backward compatible with API keys

### 10. Geographic Routing
- IP geolocation using multiple providers
- Distance-based datacenter selection
- Support for multiple regions (US, EU, Asia)
- Reduced latency for global users
- Data residency compliance ready

---

## Access Points

### Load Balancer
- **Dashboard**: http://localhost:8080/dashboard
- **Stats API**: http://localhost:8080/stats
- **Geo Stats**: http://localhost:8080/geo/stats
- **Proxy Endpoint**: http://localhost:8080/data?api_key=YOUR_KEY

### Rate Limiter
- **Dashboard**: http://localhost:5000/dashboard
- **Usage API**: http://localhost:5000/usage?api_key=YOUR_KEY
- **Data Endpoint**: http://localhost:5000/data?api_key=YOUR_KEY (legacy)
- **JWT Data Endpoint**: http://localhost:5000/api/v2/data (with Bearer token)

### Authentication Endpoints
- **Register**: POST http://localhost:5000/auth/register
- **Login**: POST http://localhost:5000/auth/login
- **Refresh Token**: POST http://localhost:5000/auth/refresh
- **User Info**: GET http://localhost:5000/auth/me
- **Logout**: POST http://localhost:5000/auth/logout

### Backend Servers
- **Backend 1**: http://localhost:5001
- **Backend 2**: http://localhost:5002
- **Backend 3**: http://localhost:5003

---

## Running Tests

### Test Load Balancer
```bash
python test_loadbalancer.py
```

This tests:
- Basic proxying
- Load distribution
- Different strategies
- Caching
- Concurrent requests
- Rate limiting
- Health checks
- Sticky sessions

### Test Rate Limiter
```bash
python test_enhanced.py
```

This tests:
- Rate limiting logic
- Tier upgrades
- IP limiting
- Admin operations
- Real-time monitoring

### Test JWT Authentication
```bash
python test_jwt.py
```

This tests:
- User registration
- Token generation
- Protected endpoints
- Token refresh
- API key migration

---

## Example Usage

### JWT Authentication Flow

#### Register New User
```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password",
    "tier": "premium"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 3600,
  "user_id": "abc123",
  "tier": "premium"
}
```

#### Access Protected Endpoint
```bash
curl http://localhost:5000/api/v2/data \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### Refresh Access Token
```bash
curl -X POST http://localhost:5000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

### Load Balancer Operations

#### Change Load Balancing Strategy
```bash
curl -X POST http://localhost:8080/change_strategy \
  -H "Content-Type: application/json" \
  -d '{"strategy": "least_connections"}'
```

#### Make a Proxied Request
```bash
curl "http://localhost:8080/data?api_key=my_key"
```

#### Check Statistics
```bash
curl http://localhost:8080/stats
```

#### Check Geographic Routing Stats
```bash
curl http://localhost:8080/geo/stats
```

### Admin Operations

#### Upgrade Rate Limit Tier
```bash
curl -X POST http://localhost:5000/admin/upgrade_tier \
  -H "Content-Type: application/json" \
  -d '{"api_key": "my_key", "tier": "premium"}'
```

#### Block API Key
```bash
curl -X POST http://localhost:5000/admin/block_key \
  -H "Content-Type: application/json" \
  -d '{"api_key": "malicious_key"}'
```

---

## Dashboard Features

### Load Balancer Dashboard
- Live backend status
- Request distribution
- Strategy selector
- Performance metrics
- Health status
- Geographic routing statistics

### Rate Limiter Dashboard
- Real-time request stream
- Success/failure rates
- Active API keys
- Request charts
- Recent logs
- JWT token activity

---

## Configuration

### Load Balancer (`load_balancer.py`)

```python
# Rate limiting
self.rate_limit = 50  # requests per minute

# Cache TTL
self.cache = CacheLayer(default_ttl=30)  # seconds

# Health check interval
self.health_check_interval = 10  # seconds

# Backend servers
self.lb.add_backend("localhost", 5001, weight=2)
self.lb.add_backend("localhost", 5002, weight=1)

# Geographic routing
self.geo_router = GeoRouter()
```

### Rate Limiter (`app.py`)

```python
# Tier limits
RATE_LIMITS = {
    'free': {'requests': 5, 'window': 60},
    'basic': {'requests': 20, 'window': 60},
    'premium': {'requests': 100, 'window': 60},
    'enterprise': {'requests': 1000, 'window': 60}
}

# IP rate limit
RATE_LIMIT_IP = 100  # per minute

# Ban settings
TEMP_BAN_SECONDS = 300  # 5 minutes
BAN_MULTIPLIER = 2  # escalation
```

### JWT Configuration (`auth.py`)

```python
# Token expiration
access_token_expiry = 3600  # 1 hour
refresh_token_expiry = 604800  # 7 days

# Algorithm
algorithm = 'HS256'

# Secret key (use environment variable in production)
secret_key = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
```

---

## Performance Benchmarks

With 3 backends and optimal configuration:

- **Throughput**: ~500-1000 requests/second
- **Latency**: <50ms (with cache hits)
- **Cache Hit Rate**: 30-50%
- **Failover Time**: <10 seconds
- **Max Concurrent**: 1000+ connections
- **JWT Verification**: <1ms per request
- **Geo Lookup**: <5ms (cached), <50ms (uncached)

---

## Production Deployment Checklist

### Security
- [x] Rate limiting per IP
- [x] JWT token-based authentication
- [x] Token expiration
- [ ] HTTPS/TLS
- [ ] Secure admin endpoints
- [ ] Password hashing (bcrypt)
- [ ] API key rotation
- [ ] Environment variable management

### Scalability
- [x] Connection pooling
- [x] Async operations
- [x] Geographic routing
- [ ] Redis for distributed cache
- [ ] Message queue (RabbitMQ/Kafka)
- [ ] Horizontal scaling support
- [ ] Database replication

### Monitoring
- [x] Real-time dashboards
- [x] Health checks
- [x] Geographic routing metrics
- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] Error tracking (Sentry)
- [ ] Log aggregation (ELK stack)

### High Availability
- [x] Automatic failover
- [x] Health monitoring
- [x] Circuit breaker pattern
- [ ] Multiple load balancer instances
- [ ] Database replication
- [ ] Multi-region deployment

---

## File Structure

```
API-RATE-LIMITER/
├── app.py                    # Rate limiter server with JWT support
├── load_balancer.py          # Load balancer with geo-routing
├── auth.py                   # JWT authentication system
├── geo_router.py            # Geographic routing engine
├── mock_backends.py         # Backend server simulators
├── fix_database.py          # Database migration utility
├── test_enhanced.py         # Rate limiter tests
├── test_loadbalancer.py     # Load balancer tests
├── test_jwt.py              # JWT authentication tests
├── requirements.txt         # Python dependencies
├── GUIDE.md                 # Original setup guide
├── UPGRADE_GUIDE.md         # JWT & Geo routing integration guide
└── README.md                # This file
```

---

## API Endpoints Reference

### Load Balancer Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Interactive dashboard |
| GET | `/stats` | JSON statistics |
| GET | `/geo/stats` | Geographic routing statistics |
| POST | `/change_strategy` | Change LB strategy |
| ANY | `/*` | Proxied to backends |

### Rate Limiter Endpoints (Legacy)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Real-time dashboard |
| GET | `/data` | Protected endpoint (deprecated) |
| GET | `/usage` | Check usage limits |
| GET | `/admin/users` | List all users |
| POST | `/admin/upgrade_tier` | Upgrade user tier |
| POST | `/admin/block_key` | Block API key |
| POST | `/admin/unblock_key` | Unblock API key |
| GET | `/logs` | View recent logs |

### Authentication Endpoints (New)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login and get tokens |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout and revoke token |
| GET | `/auth/me` | Get current user info |

### Protected API Endpoints (JWT Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v2/data` | Get protected data |
| GET | `/api/v2/premium` | Premium tier only |

---

## Troubleshooting

### Backend servers won't start
```bash
# Check if ports are available
lsof -i :5001
lsof -i :5002
lsof -i :5003

# Kill processes if needed
kill -9 <PID>
```

### Load balancer shows no healthy backends
```bash
# Verify backends are running
curl http://localhost:5001/health
curl http://localhost:5002/health
curl http://localhost:5003/health
```

### Database locked errors
```bash
# Stop all instances and delete database
rm ratelimiter.db
python app.py  # Recreates database
```

### WebSocket not connecting
- Check firewall settings
- Ensure CORS is enabled
- Verify port 8080/5000 is accessible

### JWT token errors
- Verify token format: `Authorization: Bearer <token>`
- Check token expiration
- Ensure JWT_SECRET_KEY is consistent across instances
- Verify token signature

### Geographic routing not working
- Check internet connection for GeoIP API
- Verify IP is not localhost/private
- Review geo routing logs
- Confirm datacenters are configured

---

## Learning Resources

This project demonstrates:

1. **Reverse Proxy Pattern**
2. **Load Balancing Algorithms**
3. **Circuit Breaker Pattern**
4. **Caching Strategies**
5. **Rate Limiting Techniques**
6. **Health Check Mechanisms**
7. **WebSocket Real-time Updates**
8. **Async/Await Programming**
9. **Database Connection Pooling**
10. **Microservices Architecture**
11. **JWT Authentication**
12. **Geographic Routing**
13. **Token-based Security**
14. **IP Geolocation**
15. **Stateless Architecture**

---

## Development Roadmap

### Week 1-2: Security & Routing (COMPLETED)
- JWT authentication system
- Geographic routing engine
- Token management
- API migration support

### Week 3: Monitoring (IN PROGRESS)
- Prometheus metrics integration
- Grafana dashboard setup
- Custom metric exporters
- Alert configuration

### Week 4: Containerization
- Docker container creation
- Docker Compose orchestration
- Multi-service networking
- Volume management

### Week 5-6: Distributed Systems
- Redis integration
- PostgreSQL migration
- Distributed rate limiting
- Session synchronization

### Week 7-8: Production Hardening
- SSL/TLS implementation
- Security enhancements
- Performance optimization
- Load testing

### Future Enhancements
- Kubernetes deployment
- Message queue integration
- Multi-region support
- Advanced analytics

---

## Contributing

This is a learning project showcasing enterprise patterns. Contributions welcome:
- Fork and experiment
- Add new features
- Submit pull requests
- Share improvements
- Report issues

---

## License

MIT License - Feel free to use for learning and production projects.

---

## Support

For issues and questions:
- Check the troubleshooting section
- Review the integration guides
- Open an issue on GitHub
- Contact the maintainers

---

**Last Updated**: Week 2 - JWT Authentication & Geographic Routing Implementation