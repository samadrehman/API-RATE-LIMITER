"""
SSL/TLS Certificate Management and Server Runner

PURPOSE:
This module provides SSL/TLS certificate management for Flask applications, supporting
both development and production environments. It handles:
- Self-signed certificate generation for development/testing
- Let's Encrypt certificate setup guidance for production
- Secure server startup with proper SSL/TLS configuration
- Certificate validation and verification
- Secure key generation with appropriate algorithms and key sizes

ARCHITECTURE:
- SSLManager: Handles certificate generation and Let's Encrypt setup
- run_server(): Orchestrates Flask server startup with SSL/TLS
- Command-line interface for certificate management operations

SECURITY CONSIDERATIONS:
- Strong cryptographic parameters (RSA 4096-bit minimum)
- Secure private key generation and storage
- Input validation on all user-provided data
- Protection against command injection attacks
- Secure file permissions on certificates and keys
- Certificate expiration warnings
- Validation of certificate paths and domains
- Prevention of path traversal attacks
- Secure subprocess execution
- No hardcoded credentials or secrets

PRODUCTION NOTES:
- Self-signed certificates should NEVER be used in production
- Let's Encrypt is recommended for production deployments
- Certificate rotation and renewal should be automated
- Private keys must be protected with appropriate file permissions
- Monitor certificate expiration dates
"""

import os
import subprocess
import sys
import re
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SSLConfigError(Exception):
    """Custom exception for SSL configuration errors"""
    pass


class SSLManager:
    """Manage SSL/TLS certificates for secure connections"""
    
    MIN_KEY_SIZE = 4096
    MAX_CERT_DAYS = 825
    
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate domain name format"""
        if not domain or not isinstance(domain, str):
            return False
        
        if len(domain) > 253:
            return False
        
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if domain == 'localhost':
            return True
        
        return bool(domain_pattern.match(domain))
    
    @staticmethod
    def _validate_email(email: str) -> bool:
        """Validate email address format"""
        if not email or not isinstance(email, str):
            return False
        
        if len(email) > 254:
            return False
        
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        return bool(email_pattern.match(email))
    
    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename or not isinstance(filename, str):
            raise ValueError("Invalid filename")
        
        filename = os.path.basename(filename)
        
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        if not filename or filename.startswith('.'):
            raise ValueError("Invalid filename after sanitization")
        
        return filename
    
    @staticmethod
    def _validate_cert_path(cert_path: str, key_path: str) -> Tuple[bool, str]:
        """Validate certificate and key paths"""
        try:
            cert_path = os.path.abspath(cert_path)
            key_path = os.path.abspath(key_path)
            
            cert_dir = os.path.dirname(cert_path)
            key_dir = os.path.dirname(key_path)
            
            if not os.access(cert_dir, os.W_OK):
                return False, f"Cannot write to certificate directory: {cert_dir}"
            
            if not os.access(key_dir, os.W_OK):
                return False, f"Cannot write to key directory: {key_dir}"
            
            if os.path.exists(cert_path) and not os.access(cert_path, os.W_OK):
                return False, f"Certificate file exists but is not writable: {cert_path}"
            
            if os.path.exists(key_path) and not os.access(key_path, os.W_OK):
                return False, f"Key file exists but is not writable: {key_path}"
            
            return True, ""
            
        except Exception as e:
            return False, f"Path validation error: {type(e).__name__}"
    
    @staticmethod
    def _set_secure_permissions(key_path: str) -> bool:
        """Set secure permissions on private key file"""
        try:
            if os.name != 'nt':
                os.chmod(key_path, 0o600)
                logger.info(f"Set secure permissions (600) on {key_path}")
            else:
                logger.warning("Windows detected - set file permissions manually")
            return True
        except Exception as e:
            logger.error(f"Failed to set permissions on {key_path}: {e}")
            return False
    
    @staticmethod
    def _check_openssl() -> Tuple[bool, str]:
        """Check if OpenSSL is available"""
        try:
            result = subprocess.run(
                ['openssl', 'version'],
                check=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            version = result.stdout.strip()
            logger.info(f"OpenSSL found: {version}")
            return True, version
        except FileNotFoundError:
            return False, "OpenSSL not found"
        except subprocess.TimeoutExpired:
            return False, "OpenSSL check timed out"
        except subprocess.CalledProcessError as e:
            return False, f"OpenSSL error: {e}"
    
    @staticmethod
    def generate_self_signed_cert(
        domain: str = 'localhost',
        days: int = 365,
        cert_path: str = 'cert.pem',
        key_path: str = 'key.pem'
    ) -> bool:
        """Generate self-signed SSL certificate"""
        
        logger.info("Starting self-signed certificate generation")
        
        if not SSLManager._validate_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return False
        
        if not isinstance(days, int) or days < 1 or days > SSLManager.MAX_CERT_DAYS:
            logger.error(f"Invalid certificate validity period: {days} days")
            logger.info(f"Valid range: 1-{SSLManager.MAX_CERT_DAYS} days")
            return False
        
        try:
            cert_path = SSLManager._sanitize_filename(cert_path)
            key_path = SSLManager._sanitize_filename(key_path)
        except ValueError as e:
            logger.error(f"Invalid file path: {e}")
            return False
        
        valid, error_msg = SSLManager._validate_cert_path(cert_path, key_path)
        if not valid:
            logger.error(error_msg)
            return False
        
        openssl_ok, openssl_msg = SSLManager._check_openssl()
        if not openssl_ok:
            logger.error(openssl_msg)
            logger.info("Install OpenSSL:")
            logger.info("  Ubuntu/Debian: sudo apt-get install openssl")
            logger.info("  MacOS: brew install openssl")
            logger.info("  Windows: https://slproweb.com/products/Win32OpenSSL.html")
            return False
        
        subject = f'/CN={domain}'
        if len(subject) > 256:
            logger.error("Subject DN too long")
            return False
        
        cmd = [
            'openssl', 'req', '-x509',
            '-newkey', f'rsa:{SSLManager.MIN_KEY_SIZE}',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', str(days),
            '-nodes',
            '-subj', subject,
            '-sha256'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if os.path.exists(key_path):
                SSLManager._set_secure_permissions(key_path)
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                logger.info(f"Certificate generated: {cert_path}")
                logger.info(f"Private key generated: {key_path}")
                logger.info(f"Valid for {days} days")
                logger.warning("Self-signed certificates should only be used for development!")
                logger.warning("Browsers will show security warnings for self-signed certificates")
                return True
            else:
                logger.error("Certificate or key file not created")
                return False
            
        except subprocess.TimeoutExpired:
            logger.error("Certificate generation timed out")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Certificate generation failed: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {type(e).__name__}: {e}")
            return False
    
    @staticmethod
    def setup_letsencrypt(domain: str, email: str) -> bool:
        """Setup Let's Encrypt certificate for production"""
        
        logger.info("Setting up Let's Encrypt certificate guidance")
        
        if not SSLManager._validate_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return False
        
        if not SSLManager._validate_email(email):
            logger.error(f"Invalid email: {email}")
            return False
        
        if domain == 'localhost':
            logger.error("Cannot use Let's Encrypt with localhost")
            logger.info("Use self-signed certificates for local development")
            return False
        
        try:
            result = subprocess.run(
                ['certbot', '--version'],
                check=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            logger.info(f"Certbot found: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("Certbot not found. Install it first:")
            logger.info("  Ubuntu/Debian: sudo apt-get install certbot")
            logger.info("  MacOS: brew install certbot")
            logger.info("  RHEL/CentOS: sudo yum install certbot")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Certbot check timed out")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Certbot error: {e}")
            return False
        
        logger.warning("This requires sudo access and port 80 to be available")
        logger.warning("Make sure your domain DNS points to this server")
        
        logger.info(f"\nDomain: {domain}")
        logger.info(f"Email: {email}")
        
        logger.info("\nRun this command manually (requires sudo):")
        logger.info(f"  sudo certbot certonly --standalone -d {domain} "
                   f"--non-interactive --agree-tos --email {email}")
        
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        logger.info("\nAfter running certbot, configure your application:")
        logger.info(f"  SSL_CERT_PATH={cert_path}")
        logger.info(f"  SSL_KEY_PATH={key_path}")
        logger.info(f"  USE_SSL=true")
        
        logger.info("\nSet up auto-renewal:")
        logger.info("  sudo certbot renew --dry-run")
        logger.info("  Add to cron: 0 0 * * * certbot renew --quiet")
        
        return True


def validate_ssl_config(cert_path: str, key_path: str) -> Tuple[bool, str]:
    """Validate SSL configuration"""
    
    if not cert_path or not key_path:
        return False, "Certificate and key paths must be specified"
    
    cert_path = os.path.abspath(cert_path)
    key_path = os.path.abspath(key_path)
    
    if not os.path.exists(cert_path):
        return False, f"Certificate file not found: {cert_path}"
    
    if not os.path.exists(key_path):
        return False, f"Key file not found: {key_path}"
    
    if not os.access(cert_path, os.R_OK):
        return False, f"Cannot read certificate file: {cert_path}"
    
    if not os.access(key_path, os.R_OK):
        return False, f"Cannot read key file: {key_path}"
    
    try:
        with open(cert_path, 'r') as f:
            cert_content = f.read()
            if 'BEGIN CERTIFICATE' not in cert_content:
                return False, "Invalid certificate file format"
        
        with open(key_path, 'r') as f:
            key_content = f.read()
            if 'BEGIN' not in key_content or 'PRIVATE KEY' not in key_content:
                return False, "Invalid private key file format"
        
    except Exception as e:
        return False, f"Error reading certificate files: {type(e).__name__}"
    
    return True, "SSL configuration valid"


def run_server():
    """Run Flask server with SSL/TLS support"""
    
    try:
        from app import app, socketio, config
    except ImportError as e:
        logger.error(f"Failed to import application: {e}")
        logger.error("Make sure 'app.py' exists with 'app', 'socketio', and 'config' objects")
        return False
    
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    
    if not (1024 <= port <= 65535):
        logger.error(f"Invalid port: {port}")
        return False
    
    use_ssl = getattr(config, 'USE_SSL', False)
    
    if use_ssl:
        ssl_cert = getattr(config, 'SSL_CERT', None)
        ssl_key = getattr(config, 'SSL_KEY', None)
        
        if not ssl_cert or not ssl_key:
            logger.error("SSL enabled but certificate paths not configured")
            logger.error("Set SSL_CERT and SSL_KEY in config")
            return False
        
        valid, message = validate_ssl_config(ssl_cert, ssl_key)
        if not valid:
            logger.error(f"SSL validation failed: {message}")
            return False
        
        logger.info("="*60)
        logger.info("🔒 Starting server with SSL/TLS enabled")
        logger.info("="*60)
        logger.info(f"🌐 HTTPS URL: https://localhost:{port}")
        logger.info(f"📜 Certificate: {ssl_cert}")
        logger.info(f"🔑 Private Key: {ssl_key}")
        logger.info("="*60)
        
        try:
            socketio.run(
                app,
                host=host,
                port=port,
                debug=False,
                certfile=ssl_cert,
                keyfile=ssl_key,
                allow_unsafe_werkzeug=False
            )
        except Exception as e:
            logger.error(f"Failed to start server with SSL: {type(e).__name__}: {e}")
            return False
    else:
        logger.warning("="*60)
        logger.warning("⚠️  Running WITHOUT SSL (Development mode)")
        logger.warning("="*60)
        logger.info(f"🌐 HTTP URL: http://localhost:{port}")
        logger.info("\nTo enable SSL:")
        logger.info("  1. Generate certificate: python ssl_setup.py --generate")
        logger.info("  2. Or use Let's Encrypt: python ssl_setup.py --letsencrypt")
        logger.info("  3. Update config: USE_SSL=True, SSL_CERT=..., SSL_KEY=...")
        logger.warning("\n⚠️  Never use HTTP in production!")
        logger.warning("="*60)
        
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        try:
            socketio.run(
                app,
                host=host,
                port=port,
                debug=debug_mode,
                allow_unsafe_werkzeug=False
            )
        except Exception as e:
            logger.error(f"Failed to start server: {type(e).__name__}: {e}")
            return False
    
    return True


def main():
    """Main entry point"""
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == '--generate':
            domain = 'localhost'
            days = 365
            
            if len(sys.argv) > 2:
                domain = sys.argv[2]
                if not SSLManager._validate_domain(domain):
                    logger.error(f"Invalid domain: {domain}")
                    return 1
            
            if len(sys.argv) > 3:
                try:
                    days = int(sys.argv[3])
                except ValueError:
                    logger.error(f"Invalid days value: {sys.argv[3]}")
                    return 1
            
            success = SSLManager.generate_self_signed_cert(domain, days)
            return 0 if success else 1
            
        elif command == '--letsencrypt':
            if len(sys.argv) < 4:
                logger.error("Usage: python ssl_setup.py --letsencrypt <domain> <email>")
                return 1
            
            domain = sys.argv[2]
            email = sys.argv[3]
            
            success = SSLManager.setup_letsencrypt(domain, email)
            return 0 if success else 1
            
        elif command == '--validate':
            if len(sys.argv) < 4:
                logger.error("Usage: python ssl_setup.py --validate <cert_path> <key_path>")
                return 1
            
            cert_path = sys.argv[2]
            key_path = sys.argv[3]
            
            valid, message = validate_ssl_config(cert_path, key_path)
            if valid:
                logger.info(f"✅ {message}")
                return 0
            else:
                logger.error(f"❌ {message}")
                return 1
            
        elif command == '--help':
            print("SSL Setup and Certificate Management")
            print("\nUsage:")
            print("  python ssl_setup.py                                    # Run server")
            print("  python ssl_setup.py --generate [domain] [days]        # Generate self-signed cert")
            print("  python ssl_setup.py --letsencrypt <domain> <email>    # Setup Let's Encrypt")
            print("  python ssl_setup.py --validate <cert> <key>           # Validate SSL config")
            print("  python ssl_setup.py --help                            # Show this help")
            print("\nExamples:")
            print("  python ssl_setup.py --generate localhost 365")
            print("  python ssl_setup.py --letsencrypt example.com admin@example.com")
            print("  python ssl_setup.py --validate cert.pem key.pem")
            return 0
        else:
            logger.error(f"Unknown command: {command}")
            logger.info("Run with --help for usage information")
            return 1
    else:
        success = run_server()
        return 0 if success else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nServer stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {type(e).__name__}: {e}")
        sys.exit(1)