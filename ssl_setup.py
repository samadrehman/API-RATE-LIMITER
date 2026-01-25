import os
import subprocess
from datetime import datetime, timedelta
from app import app, socketio, config

class SSLManager:
    """Manage SSL/TLS certificates for secure connections"""
    
    @staticmethod
    def generate_self_signed_cert(domain='localhost', days=365):
        print("🔐 Generating self-signed SSL certificate...")
        
        cert_path = 'cert.pem'
        key_path = 'key.pem'
        
        # Generate private key and certificate
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', str(days),
            '-nodes',
            '-subj', f'/CN={domain}'
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✅ Certificate generated: {cert_path}")
            print(f"✅ Private key generated: {key_path}")
            print(f"⚠️  Valid for {days} days")
            print("⚠️  Self-signed certificates should only be used for development!")
            return True
        except FileNotFoundError:
            print("❌ OpenSSL not found. Install it first:")
            print("   Ubuntu/Debian: sudo apt-get install openssl")
            print("   MacOS: brew install openssl")
            print("   Windows: Download from https://slproweb.com/products/Win32OpenSSL.html")
            return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Certificate generation failed: {e}")
            return False
    
    @staticmethod
    def setup_letsencrypt(domain, email):
        """Setup Let's Encrypt certificate for production"""
        print("🔐 Setting up Let's Encrypt certificate...")
        print(f"Domain: {domain}")
        print(f"Email: {email}")
        
        # Check if certbot is installed
        try:
            subprocess.run(['certbot', '--version'], check=True, capture_output=True)
        except FileNotFoundError:
            print("❌ Certbot not found. Install it first:")
            print("   Ubuntu/Debian: sudo apt-get install certbot")
            print("   MacOS: brew install certbot")
            return False
        
        # Generate certificate
        cmd = [
            'sudo', 'certbot', 'certonly',
            '--standalone',
            '-d', domain,
            '--non-interactive',
            '--agree-tos',
            '--email', email
        ]
        
        print("\n⚠️  This requires sudo access and port 80 to be available")
        print(f"Run this command manually:\n{' '.join(cmd)}")
        
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        print(f"\nAfter running certbot, update your .env:")
        print(f"SSL_CERT_PATH={cert_path}")
        print(f"SSL_KEY_PATH={key_path}")
        
        return True

def run_server():
    """Run Flask server with SSL/TLS support"""
    
    host = '0.0.0.0'
    port = 5000
    
    if config.USE_SSL:
        print("="*60)
        print("🔒 Starting server with SSL/TLS enabled")
        print("="*60)
        print(f"🌐 HTTPS URL: https://localhost:{port}")
        print(f"📜 Certificate: {config.SSL_CERT}")
        print(f"🔑 Private Key: {config.SSL_KEY}")
        print("="*60)
        
        # Run with SSL context
        socketio.run(
            app,
            host=host,
            port=port,
            debug=False,
            certfile=config.SSL_CERT,
            keyfile=config.SSL_KEY,
            allow_unsafe_werkzeug=True
        )
    else:
        print("="*60)
        print("⚠️  Running WITHOUT SSL (Development mode)")
        print("="*60)
        print(f"🌐 HTTP URL: http://localhost:{port}")
        print("\nTo enable SSL:")
        print("  1. Generate certificate: python ssl_setup.py --generate")
        print("  2. Or use Let's Encrypt: python ssl_setup.py --letsencrypt")
        print("="*60)
        
        socketio.run(
            app,
            host=host,
            port=port,
            debug=True,
            allow_unsafe_werkzeug=True
        )


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if '--generate' in sys.argv:
            SSLManager.generate_self_signed_cert()
        elif '--letsencrypt' in sys.argv:
            domain = input("Enter your domain: ")
            email = input("Enter your email: ")
            SSLManager.setup_letsencrypt(domain, email)
        else:
            print("Usage:")
            print("  python ssl_setup.py --generate          # Generate self-signed cert")
            print("  python ssl_setup.py --letsencrypt       # Setup Let's Encrypt")
    else:
        run_server()