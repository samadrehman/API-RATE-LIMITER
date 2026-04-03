"""
JWT Authentication Manager for API Rate Limiter

This module provides comprehensive JWT-based authentication and authorization with:
- Secure token generation with configurable expiration
- Access token and refresh token management
- Token verification and validation
- Token revocation with blacklist support
- Tier-based authorization decorator
- Flask route integration for auth endpoints
- Migration utilities from API key to JWT

Security Features:
- Cryptographically secure token generation
- Configurable token expiration times
- Token type validation (access vs refresh)
- Tier hierarchy enforcement
- Secure password hashing integration points
- Token blacklist for revocation
- Protection against timing attacks

Key Components:
- JWTAuthManager: Main authentication manager class
- Token generation and verification
- Flask decorators for endpoint protection
- Auth endpoints (register, login, refresh, logout)
- User tier management

Usage:
    jwt_manager = JWTAuthManager(secret_key='your-secret-key')
    app.config['JWT_MANAGER'] = jwt_manager
    jwt_manager.init_auth_endpoints(app)
    
    @app.route('/protected')
    @jwt_manager.require_jwt(tier_required='premium')
    def protected_route():
        return jsonify({'data': 'protected'})

Last Updated: 2026
"""

import sys
import base64
import json
import hmac
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Set
from threading import Lock

from flask import Flask, request, jsonify, current_app


def _is_free_threaded_python() -> bool:
    abiflags = getattr(sys, "abiflags", "")
    if "t" in abiflags:
        return True
    if hasattr(sys, "_is_gil_enabled"):
        try:
            return not sys._is_gil_enabled()  # type: ignore[attr-defined]
        except Exception:
            pass
    exe = (sys.executable or "").lower()
    return exe.endswith("t.exe")


class JWTError(Exception):
    pass


class ExpiredSignatureError(JWTError):
    pass


class InvalidTokenError(JWTError):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _jwt_json_default(value):
    if isinstance(value, datetime):
        return int(value.timestamp())
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _jwt_encode_hs256(payload: dict, secret_key: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), default=_jwt_json_default).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def _jwt_decode_hs256(token: str, secret_key: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as e:
        raise InvalidTokenError("Invalid JWT format") from e

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise InvalidTokenError("Invalid JWT encoding") from e

    if header.get("alg") != "HS256":
        raise InvalidTokenError("Unsupported JWT algorithm")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        given = _b64url_decode(sig_b64)
    except Exception as e:
        raise InvalidTokenError("Invalid JWT signature encoding") from e

    if not hmac.compare_digest(expected, given):
        raise InvalidTokenError("Invalid JWT signature")

    exp = payload.get("exp")
    if exp is not None and int(time.time()) > int(exp):
        raise ExpiredSignatureError("Token expired")

    return payload


_PYJWT = None
if not _is_free_threaded_python():
    try:
        import jwt as _PYJWT  # type: ignore
    except Exception:
        _PYJWT = None


def jwt_encode(payload: dict, secret_key: str, algorithm: str = "HS256") -> str:
    if algorithm != "HS256":
        raise InvalidTokenError("Only HS256 is supported")
    if _PYJWT is not None:
        return _PYJWT.encode(payload, secret_key, algorithm=algorithm)
    return _jwt_encode_hs256(payload, secret_key)


def jwt_decode(token: str, secret_key: str, algorithms=None) -> dict:
    algorithms = algorithms or ["HS256"]
    if "HS256" not in algorithms:
        raise InvalidTokenError("Only HS256 is supported")

    if _PYJWT is not None:
        try:
            return _PYJWT.decode(token, secret_key, algorithms=["HS256"])
        except Exception as e:
            name = type(e).__name__
            if name == "ExpiredSignatureError":
                raise ExpiredSignatureError(str(e)) from e
            raise InvalidTokenError(str(e)) from e

    return _jwt_decode_hs256(token, secret_key)




class JWTAuthManager:
 
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = 'HS256'):
        """
        Initialize JWT manager with secure defaults
        
        Args:
            secret_key: Secret key for JWT signing (generates secure random if None)
            algorithm: JWT signing algorithm (default: HS256)
        """
        # Use provided key or generate secure random key
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        
        # Validate secret key strength
        if len(self.secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters for security")
        
        # Token expiration times in seconds
        self.access_token_expiry = 3600      # 1 hour
        self.refresh_token_expiry = 604800   # 7 days (not 600 seconds!)
        
        # Token blacklist for revocation (in production, use Redis)
        self._token_blacklist: Set[str] = set()
        self._blacklist_lock = Lock()
        
        # Security logging
        print(f"✅ JWT Manager initialized")
        print(f"🔑 Secret key: {self.secret_key[:8]}...***KEEP SECRET***")
        print(f"🔐 Algorithm: {self.algorithm}")
        print(f"⏱️  Refresh token expiry: {self.refresh_token_expiry}s")
    
    def generate_tokens(
        self,
        user_id: str,
        tier: str = 'free',
        metadata: Optional[Dict] = None
    ) -> Dict:

        # Validate inputs
        if not user_id or not isinstance(user_id, str):
            raise ValueError("user_id must be a non-empty string")
        
        valid_tiers = ['free', 'basic', 'premium', 'enterprise']
        if tier not in valid_tiers:
            raise ValueError(f"tier must be one of {valid_tiers}")
        
        now_ts = int(time.time())
        
        # Access token payload
        access_payload = {
            'user_id': user_id,
            'tier': tier,
            'iat': now_ts,  # Issued at
            'exp': now_ts + self.access_token_expiry,
            'type': 'access',
            'metadata': metadata or {},
            'jti': secrets.token_hex(16),  # Unique token ID for revocation
        }
        
        # Refresh token payload (minimal data for security)
        refresh_payload = {
            'user_id': user_id,
            'iat': now_ts,
            'exp': now_ts + self.refresh_token_expiry,
            'type': 'refresh',
            'jti': secrets.token_hex(16),
        }
        
        # Generate tokens
        access_token = jwt_encode(access_payload, self.secret_key, algorithm=self.algorithm)
        
        refresh_token = jwt_encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'refresh_token_expiry': self.refresh_token_expiry,
            'token_type': 'Bearer',
            'user_id': user_id,
            'tier': tier,
            'metadata': metadata or {}
        }
    
    def verify_token(self, token: str, token_type: str = 'access') -> Dict:

        if not token or not isinstance(token, str):
            raise InvalidTokenError("Token must be a non-empty string")
        
        try:
            # Decode and verify token
            payload = jwt_decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Verify token type matches expected
            if payload.get('type') != token_type:
                raise InvalidTokenError(
                    f"Invalid token type. Expected '{token_type}', got '{payload.get('type')}'"
                )
            
            # Check if token is blacklisted (revoked)
            jti = payload.get('jti')
            if jti and self._is_token_blacklisted(jti):
                raise ValueError(f"Token has been revoked")
            
            return payload

        except ExpiredSignatureError as e:
            raise ExpiredSignatureError(f"Token expired: {str(e)}")
        except InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> Dict:

        # Verify refresh token
        payload = self.verify_token(refresh_token, token_type='refresh')
        user_id = payload.get('user_id')
        
        if not user_id:
            raise InvalidTokenError("Refresh token missing user_id")
        
        # Generate new token pair (preserve tier from original if stored in DB)
        # In production, fetch user tier from database
        return self.generate_tokens(user_id, tier='free')
    
    def revoke_token(self, token: str) -> None:

        try:
            payload = self.verify_token(token)
            jti = payload.get('jti')
            
            if jti:
                with self._blacklist_lock:
                    self._token_blacklist.add(jti)
                print(f"✅ Token revoked: {jti}")
            else:
                print(f"⚠️  Token has no JTI, cannot revoke reliably")
                
        except (InvalidTokenError, ExpiredSignatureError) as e:
            print(f"⚠️  Cannot revoke invalid/expired token: {str(e)}")
    
    def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if token JTI is in blacklist"""
        with self._blacklist_lock:
            return jti in self._token_blacklist
    
    def clear_blacklist(self) -> None:
        """Clear token blacklist (admin function)"""
        with self._blacklist_lock:
            count = len(self._token_blacklist)
            self._token_blacklist.clear()
            print(f"🗑️  Cleared {count} tokens from blacklist")
    
    def require_jwt(self, tier_required: Optional[str] = None):

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract token from Authorization header
                auth_header = request.headers.get('Authorization', '')
                
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({
                        'error': 'Unauthorized',
                        'message': 'Missing or invalid Authorization header',
                        'format': 'Authorization: Bearer <token>'
                    }), 401
                
                # Parse token from header
                parts = auth_header.split()
                if len(parts) != 2:
                    return jsonify({
                        'error': 'Unauthorized',
                        'message': 'Invalid Authorization header format',
                        'format': 'Authorization: Bearer <token>'
                    }), 401
                
                token = parts[1]
                
                # Get JWT manager from app config
                jwt_manager = current_app.config.get('JWT_MANAGER')
                if not jwt_manager:
                    return jsonify({
                        'error': 'Server configuration error',
                        'message': 'JWT manager not configured'
                    }), 500
                
                try:
                    # Verify token
                    payload = jwt_manager.verify_token(token)
                    user_tier = payload.get('tier', 'free')
                    
                    # Check tier requirement if specified
                    if tier_required:
                        tier_hierarchy = ['free', 'basic', 'premium', 'enterprise']
                        
                        if tier_required not in tier_hierarchy:
                            return jsonify({
                                'error': 'Server configuration error',
                                'message': f'Invalid tier requirement: {tier_required}'
                            }), 500
                        
                        # Check if user tier meets requirement
                        if (tier_hierarchy.index(user_tier) <
                            tier_hierarchy.index(tier_required)):
                            return jsonify({
                                'error': 'Insufficient tier',
                                'message': f'This endpoint requires {tier_required} tier or higher',
                                'required': tier_required,
                                'current': user_tier
                            }), 403
                    
                    # Attach user info to request context
                    request.user_id = payload['user_id']
                    request.user_tier = user_tier
                    request.jwt_payload = payload
                    
                    return func(*args, **kwargs)
                    
                except ExpiredSignatureError:
                    return jsonify({
                        'error': 'Token expired',
                        'message': 'Your token has expired. Please refresh or login again.'
                    }), 401
                    
                except InvalidTokenError as e:
                    return jsonify({
                        'error': 'Invalid token',
                        'message': str(e)
                    }), 401
                    
                except ValueError as e:
                    return jsonify({
                        'error': 'Token revoked',
                        'message': str(e)
                    }), 401
            
            return wrapper
        return decorator
    
    def init_auth_endpoints(self, app: Flask) -> None:

        @app.route('/auth/register', methods=['POST'])
        def register():
            
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'JSON body required'}), 400
            
            email = data.get('email')
            password = data.get('password')
            tier = data.get('tier', 'free')
            
            if not email or not isinstance(email, str):
                return jsonify({'error': 'Valid email required'}), 400
            
            if not password or not isinstance(password, str):
                return jsonify({'error': 'Valid password required'}), 400
            
            if len(password) < 8:
                return jsonify({'error': 'Password must be at least 8 characters'}), 400
            
            valid_tiers = ['free', 'basic', 'premium', 'enterprise']
            if tier not in valid_tiers:
                return jsonify({'error': f'Tier must be one of {valid_tiers}'}), 400
            
            user_id = hashlib.sha256(email.encode('utf-8')).hexdigest()[:16]
          
            jwt_manager = current_app.config.get('JWT_MANAGER')
            if not jwt_manager:
                return jsonify({'error': 'Server configuration error'}), 500
            
            tokens = jwt_manager.generate_tokens(
                user_id=user_id,
                tier=tier,
                metadata={'email': email}
            )
            
            return jsonify(tokens), 201
        
        @app.route('/auth/login', methods=['POST'])
        def login():
            """Login user and return tokens"""
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'JSON body required'}), 400
            
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return jsonify({'error': 'Email and password required'}), 400
            
            
            user_id = hashlib.sha256(email.encode('utf-8')).hexdigest()[:16]
            
            jwt_manager = current_app.config.get('JWT_MANAGER')
            if not jwt_manager:
                return jsonify({'error': 'Server configuration error'}), 500
            
            
            tokens = jwt_manager.generate_tokens(
                user_id=user_id,
                tier='free',
                metadata={'email': email}
            )
            
            return jsonify(tokens)
        
        @app.route('/auth/refresh', methods=['POST'])
        def refresh():
            """Refresh access token using refresh token"""
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'JSON body required'}), 400
            
            refresh_token = data.get('refresh_token')
            
            if not refresh_token:
                return jsonify({'error': 'Refresh token required'}), 400
            
            # Get JWT manager
            jwt_manager = current_app.config.get('JWT_MANAGER')
            if not jwt_manager:
                return jsonify({'error': 'Server configuration error'}), 500
            
            try:
                tokens = jwt_manager.refresh_access_token(refresh_token)
                return jsonify(tokens)
            except (InvalidTokenError, ExpiredSignatureError, ValueError) as e:
                return jsonify({'error': str(e)}), 401
        
        @app.route('/auth/logout', methods=['POST'])
        @self.require_jwt()
        def logout():
            """Logout user and revoke token"""
            auth_header = request.headers.get('Authorization', '')
            token = auth_header.split()[1]
            
            # Get JWT manager
            jwt_manager = current_app.config.get('JWT_MANAGER')
            if not jwt_manager:
                return jsonify({'error': 'Server configuration error'}), 500
            
            jwt_manager.revoke_token(token)
            
            return jsonify({'message': 'Logged out successfully'})
        
        @app.route('/auth/me', methods=['GET'])
        @self.require_jwt()
        def get_user_info():
            """Get current user information"""
            return jsonify({
                'user_id': request.user_id,
                'tier': request.user_tier,
                'token_info': request.jwt_payload
            })
        
        print("✅ Auth endpoints initialized:")
        print("   POST /auth/register - Register new user")
        print("   POST /auth/login - Login and get tokens")
        print("   POST /auth/refresh - Refresh access token")
        print("   POST /auth/logout - Logout and revoke token")
        print("   GET /auth/me - Get current user info")

def migrate_api_key_to_jwt(
    api_key: str,
    jwt_manager: JWTAuthManager,
    tier: str = 'free'
) -> Dict:
   
    if not api_key or not isinstance(api_key, str):
        raise ValueError("api_key must be a non-empty string")
    
    # Generate deterministic user_id from API key
    user_id = hashlib.sha256(api_key.encode('utf-8')).hexdigest()[:16]
    
    # Generate JWT tokens
    return jwt_manager.generate_tokens(user_id, tier)


def create_jwt_manager(app: Flask, secret_key: Optional[str] = None) -> JWTAuthManager:

    jwt_manager = JWTAuthManager(secret_key=secret_key)
    app.config['JWT_MANAGER'] = jwt_manager
    jwt_manager.init_auth_endpoints(app)
    return jwt_manager