from curses import wrapper
from typing import Generator
import jwt 
import time 
from datetime import datetime, timedelta
from functools import wraps
from flask import app, request, jsonify, current_app
import secrets
import hashlib

from matplotlib import font_manager


class JWTAuthManager:
    def __init__(self,secret_key=None, algorithm='HS256'):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm

        #Token exp time in sec
        self.access_token_expirty = 3600 # 1 h
        self.refresh_token_expirty = 600 

        print(f" JWT Secret: {self.secret_key[:16]}...(KEEP THIS SECREY!)")
        print(f" JWT Algorithm: {self.algorithm}")

    def generate_tokens(self,user_id:str,tier:str = 'free',metadata:dict=None) ->dict:
        now = datetime.utcnow()
        access_payload ={
            'user_id':user_id,
            'tier':tier,
            'iat':now,
            'exp':now + timedelta(seconds=self.access_token_expirty),
            'type':'access',
            'metadata':metadata,
            'jti':secrets.token_hex(16),
        }

        refresh_payload ={
            'user_id':user_id,
            'iat':now,
            'exp':now + timedelta(seconds=self.refresh_token_expirty),
            'type':'refresh',
            'jti':secrets.token_hex(16),
        }

        access_token =jwt.encode(
            access_payload,
            self.secret_key,
            algorithm=self.algorithm
        )

        refresh_token =jwt.encode(
            refresh_payload,
            self.secret_key,
            algorithm=self.algorithm
        )

        return {
            'access_token':access_token,
            'refresh_token':refresh_token,
            'access_token_expirty':self.access_token_expirty,
            'refresh_token_expirty':self.refresh_token_expirty,
            'token_type':'Bearer',
            'user_id':user_id,
            'tier':tier,
            'metadata':metadata,
        }
    
    def verify_token(self, token: str, token_type: str = 'access') -> dict:
        try: 
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            if payload.get('type') != token_type:
                raise jwt.InvalidTokenError(f"Invalid token type")
            return payload
        except jwt.ExpiredSignatureError as e:
            raise jwt.ExpiredSignatureError(f"Token expired: {str(e)}")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> dict:
        payload = self.verify_token(refresh_token, token_type='refresh')
        user_id = payload.get('user_id')

        return self.generate_tokens(user_id,tier='Free')
    
    def revoke_toekn(self,token:str):
        payload = self.verify_token(token)
        jti = payload['jti']

        print(f"Token revoked :{jti}")


    def require_jwt(self, tier_required:str=None):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({
                        'error': 'Unauthorized header',
                        'message': 'format: Authorization: Bearer <token>'
                    }), 401
                
                parts = auth_header.split()
                if len(parts) != 2:
                    return jsonify({
                        'error': 'Unauthorized header',
                        'message': 'format: Authorization: Bearer <token>'
                    }), 401
                
                token = parts[1]
                jwt_manager = current_app.config['JWT_MANAGER']

                try:
                    payload = jwt_manager.verify_token(token)
                    user_tier = payload.get('tier', 'free')
                    
                    if tier_required and user_tier != tier_required:
                        tier_hierarchy = ['free', 'basic', 'premium', 'enterprise']
                        if (tier_hierarchy.index(user_tier) <
                            tier_hierarchy.index(tier_required)):
                            return jsonify({
                                'error': 'Insufficient tier',
                                'required': tier_required,
                                'current': user_tier
                            }), 403
                    
                    request.user_id = payload['user_id']
                    request.user_tier = user_tier
                    request.jwt_payload = payload
                    
                    return func(*args, **kwargs)
                    
                except (jwt.InvalidTokenError, ValueError) as e:
                    return jsonify({
                        'error': 'Invalid token',
                        'message': str(e)
                    }), 401
            
            return wrapper
        return decorator
    

    def init_auth_endpoints(self, app):
        @app.route('/auth/register', methods=['POST'])
        def register():
            data = request.json or {}
            email = data.get('email')
            password = data.get('password')
            tier = data.get('tier', 'free')
            
            if not email or not password:
                return jsonify({'error': 'Email and password required'}), 400
            
            user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
            
            jwt_manager = current_app.config['JWT_MANAGER']
            tokens = jwt_manager.generate_tokens(
                user_id=user_id,
                tier=tier,
                metadata={'email': email}
            )
            
            return jsonify(tokens), 201
    
    @app.route('/auth/login', methods=['POST'])
    def login():
        data = request.json or {}
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        # In production: Verify password from database
        # user = db.users.find_one({'email': email})
        # if not user or not bcrypt.checkpw(password, user['password_hash']):
        #     return jsonify({'error': 'Invalid credentials'}), 401
        
        # For demo: generate user_id from email
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        
        # Generate tokens
        tokens = font_manager.generate_tokens(
            user_id=user_id,
            tier='free',
            metadata={'email': email}
        )
        
        return jsonify(tokens)
    
    @app.route('/auth/refresh', methods=['POST'])
    def refresh():
    
        data = request.json or {}
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token required'}), 400
        
        try:
            tokens = font_manager.refresh_access_token(refresh_token)
            return jsonify(tokens)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
    
    @app.route('/auth/logout', methods=['POST'])
    @require_jwt()
    def logout():
        token = request.headers.get('Authorization').split()[1]
        
        font_manager.revoke_token(token)
        
        return jsonify({'message': 'Logged out successfully'})
    
    @app.route('/auth/me')
    @require_jwt()
    def get_user_info():
  
        return jsonify({
            'user_id': request.user_id,
            'tier': request.user_tier,
            'token_info': request.jwt_payload
        })

def migrate_api_key_to_jwt(api_key: str, tier: str = 'free') -> dict:

    user_id = hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return font_manager.generate_tokens(user_id, tier)

                    



                

        

        




      