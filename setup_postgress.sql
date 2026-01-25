CREATE DATABASE ratelimiter_db;

CREATE USER ratelimiter_user WITH PASSWORD 'your_secure_password_here';

GRANT ALL PRIVILEGES ON DATABASE ratelimiter_db TO ratelimiter_user;

-- Connect to the database
\c ratelimiter_db

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO ratelimiter_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ratelimiter_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ratelimiter_user;

-- SCHEMA CREATION

-- Users table with enhanced quota tracking
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    api_key VARCHAR(255) UNIQUE NOT NULL,
    tier VARCHAR(50) DEFAULT 'free',
    
    request_count INTEGER DEFAULT 0,
    daily_requests INTEGER DEFAULT 0,
    window_start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    daily_reset_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    blocked BOOLEAN DEFAULT FALSE,
    banned_until TIMESTAMP,
    ban_count INTEGER DEFAULT 0,
    
    total_requests INTEGER DEFAULT 0,
    total_data_transferred BIGINT DEFAULT 0,
    
    last_login TIMESTAMP,
    oauth_provider VARCHAR(50),
    oauth_id VARCHAR(255),
    refresh_token TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    country VARCHAR(2),
    region VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    api_key VARCHAR(255),
    endpoint VARCHAR(255),
    method VARCHAR(10),
    status_code INTEGER,
    
    ip VARCHAR(45),
    user_agent TEXT,
    
    geo_country VARCHAR(2),
    geo_region VARCHAR(50),
    geo_city VARCHAR(100),
    
    backend_server VARCHAR(255),
    backend_response_time_ms INTEGER,
    
    response_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT FALSE,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    request_size INTEGER,
    response_size INTEGER
);

CREATE TABLE IF NOT EXISTS analytics (
    id SERIAL PRIMARY KEY,
    metric_type VARCHAR(100) NOT NULL,
    metric_value NUMERIC,
    metadata JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    period VARCHAR(20) -- hourly, daily, weekly
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS geo_routing (
    id SERIAL PRIMARY KEY,
    region VARCHAR(50) UNIQUE NOT NULL,
    datacenter_name VARCHAR(100),
    backend_urls TEXT[], -- PostgreSQL array
    latitude NUMERIC,
    longitude NUMERIC,
    enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 1
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_api_key ON users(api_key);
CREATE INDEX idx_users_tier ON users(tier);
CREATE INDEX idx_users_oauth ON users(oauth_provider, oauth_id);

CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_api_key ON logs(api_key);
CREATE INDEX idx_logs_status ON logs(status_code);
CREATE INDEX idx_logs_geo_region ON logs(geo_region);
CREATE INDEX idx_logs_