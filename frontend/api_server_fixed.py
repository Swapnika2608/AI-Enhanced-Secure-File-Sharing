"""
FastAPI Server for Blindsend Frontend
Provides REST API endpoints for secure file sharing with AI security
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import psycopg
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import json
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import rate limiter
try:
    from rate_limiter import rate_limit_dependency
    RATE_LIMITING_ENABLED = True
except ImportError:
    print("⚠️ Rate limiter not available - running without rate limiting")
    RATE_LIMITING_ENABLED = False
    async def rate_limit_dependency(request: Request):
        return True

# File upload limits
MAX_FILE_SIZE_MB = int(os.environ.get('MAX_FILE_SIZE_MB', 100))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

def utc_now():
    """Get current UTC time - use this for all database storage"""
    return datetime.now(timezone.utc)

def to_india_time(utc_datetime):
    """Convert UTC datetime to India time for display"""
    if utc_datetime is None:
        return None
    if utc_datetime.tzinfo is None:
        utc_datetime = utc_datetime.replace(tzinfo=timezone.utc)
    india_tz = timezone(timedelta(hours=5, minutes=30))
    return utc_datetime.astimezone(india_tz).isoformat()

# Add AI security path
sys.path.append('ai_security')
sys.path.append('../ai_security')
try:
    from config import DB_CONFIG
    # Fix database config for psycopg2
    if 'dbname' in DB_CONFIG:
        DB_CONFIG['database'] = DB_CONFIG.pop('dbname')
except ImportError:
    # Use environment variables for production (Render)
    # Try DATABASE_URL first (Render format), then individual vars
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Parse DATABASE_URL format: postgresql://user:password@host:port/database
        import urllib.parse
        parsed = urllib.parse.urlparse(database_url)
        DB_CONFIG = {
            'host': parsed.hostname,
            'port': parsed.port or 5432,
            'dbname': parsed.path[1:],  # Remove leading /
            'user': parsed.username,
            'password': parsed.password
        }
    else:
        # CRITICAL: No fallback credentials - fail fast if not configured
        db_password = os.environ.get('DB_PASSWORD')
        if not db_password:
            raise ValueError("DB_PASSWORD environment variable is required. Set it in .env file.")
        
        DB_CONFIG = {
            'host': os.environ.get('DB_HOST', 'localhost'),
            'port': int(os.environ.get('DB_PORT', 5432)),
            'dbname': os.environ.get('DB_NAME', 'blindsend_test'),
            'user': os.environ.get('DB_USER', 'postgres'),
            'password': db_password
        }
# AI imports
try:
    from ai_security_engine import AISecurityEngine
    from feature_engineering import FeatureEngineer
    from risk_scoring import RiskScorer
    from anomaly_detection import AnomalyDetector
    AI_IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"AI imports failed: {e}")
    AI_IMPORTS_AVAILABLE = False

import requests
from datetime import timezone, timedelta
import resend

resend.api_key = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "onboarding@resend.dev")

def send_security_alert_email(user_email: str, alert_message: str, link_id: str):
    """Send security alert email using Resend API"""
    try:
        if not resend.api_key:
            print("⚠️ RESEND_API_KEY not set - skipping email")
            return False

        params: resend.Emails.SendParams = {
            "from": f"BlindSend Security <{FROM_EMAIL}>",
            "to": [user_email],
            "subject": "🚨 BlindSend Security Alert - Suspicious Activity Detected",
            "html": f"""
                <h2>🚨 Security Alert</h2>
                <p>{alert_message.replace(chr(10), '<br>')}</p>
                <p><strong>Link ID:</strong> {link_id}</p>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <hr>
                <p style="color: gray; font-size: 12px;">This is an automated alert from BlindSend.</p>
            """
        }

        response = resend.Emails.send(params)
        print(f"✅ Security alert email sent to {user_email}, id: {response.id}")
        return True

    except Exception as e:
        print(f"❌ Failed to send security alert email: {e}")
        return False

def get_client_ip(request: Request) -> str:
    """Get real client IP address"""
    # Check for forwarded headers first
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Fallback to client host
    return request.client.host if request.client else "127.0.0.1"

def get_location_from_ip(ip_address: str) -> str:
    """Get city/country from IP address"""
    if ip_address in ["127.0.0.1", "localhost", "::1"]:
        return "Local"
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                city = data.get("city", "")
                country = data.get("country", "")
                return f"{city}, {country}" if city and country else country or "Unknown"
    except:
        pass
    return "Unknown"

app = FastAPI(title="AI Enhanced Secure File Sharing API", version="1.0.0")
security = HTTPBearer()

# Initialize AI Security Engine
ai_engine = None
if AI_IMPORTS_AVAILABLE:
    try:
        # Ensure models directory exists
        os.makedirs("models", exist_ok=True)
        ai_engine = AISecurityEngine(DB_CONFIG)
        print("AI Security Engine initialized successfully")
    except Exception as e:
        print(f"AI Security Engine initialization failed: {e}")
else:
    print("AI Security Engine disabled - imports not available")

# CORS middleware - SECURE: Restrict to specific origins
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Serve static files - handle both local and production paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Upload directory - always relative to this file
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Debug: Print paths
print(f"BASE_DIR: {BASE_DIR}")
print(f"STATIC_DIR: {STATIC_DIR}")
print(f"Static dir exists: {os.path.isdir(STATIC_DIR)}")
print(f"Current working directory: {os.getcwd()}")
print(f"Files in current dir: {os.listdir('.') if os.path.exists('.') else 'N/A'}")

# Try multiple static directory locations
static_locations = [
    STATIC_DIR,
    "/opt/render/project/src/frontend/static",
    "frontend/static",
    "static",
    "./static"
]

for static_path in static_locations:
    if os.path.isdir(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")
        print(f"Mounted static files from: {static_path}")
        STATIC_DIR = static_path  # Update STATIC_DIR to the working path
        break
else:
    print("No static directory found in any location")

@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    try:
        return FileResponse(os.path.join(BASE_DIR, "favicon.ico"))
    except:
        # Return a simple response if favicon not found
        return HTMLResponse("")

# JWT settings - CRITICAL: No fallback secret
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET or JWT_SECRET == 'your-secret-key-change-in-production':
    raise ValueError("JWT_SECRET environment variable must be set to a secure random string. Generate with: python -c 'import secrets; print(secrets.token_urlsafe(64))'")
JWT_ALGORITHM = "HS256"

def get_db():
    """Database connection"""
    try:
        # Use dbname for psycopg3 (not database)
        db_config = DB_CONFIG.copy()
        if 'database' in db_config:
            db_config['dbname'] = db_config.pop('database')
        
        # Debug: Print connection details (without password)
        conn = psycopg.connect(**db_config)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        print(f"DB_CONFIG: {DB_CONFIG}")
        return None

def create_jwt_token(user_id: int, email: str) -> str:
    """Create JWT token for user"""
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": utc_now() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve main page"""
    try:
        # Production paths for Render
        production_paths = [
            "/opt/render/project/src/frontend/static/index.html",
            "frontend/static/index.html",
            "static/index.html",
            "./static/index.html"
        ]
        
        # Try production paths first
        for path in production_paths:
            try:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8") as f:
                        return HTMLResponse(f.read())
            except Exception as e:
                print(f"Failed to read {path}: {e}")
                continue
        
        # Try the computed static dir path
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
                
        # If no file found, return fallback
        raise FileNotFoundError("No index.html found")
        
    except FileNotFoundError:
        return HTMLResponse("""
        <!DOCTYPE html>
        <html><head><title>BlindSend</title></head><body>
        <h1>🔐 BlindSend - End-to-End Encrypted File Sharing</h1>
        <p>Server is running successfully!</p>
        <p>Main application not found. Please ensure static/index.html exists.</p>
        <p><a href="/admin/files">View uploaded files</a></p>
        <p><a href="/init-db">Initialize database</a></p>
        </body></html>
        """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "message": "BlindSend API is running",
        "ai_engine": "disabled" if not ai_engine else "enabled"
    }

@app.post("/upload")
async def upload_file_simple(file: UploadFile = File(...)):
    """Simple upload endpoint for encrypted files"""
    try:
        # Create upload directory
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Generate unique file ID
        file_id = str(uuid.uuid4())
        file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")
        
        # Save encrypted file (server never sees plaintext)
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        return {
            "file_id": file_id,
            "download_url": f"/download/{file_id}",
            "message": "Encrypted file uploaded successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/{file_id}", response_class=HTMLResponse)
async def download_page(file_id: str):
    """Serve download page with decryption capability"""
    try:
        # Try multiple paths for download.html
        download_paths = [
            os.path.join(STATIC_DIR, "download.html"),
            "/opt/render/project/src/frontend/static/download.html",
            "frontend/static/download.html",
            "static/download.html",
            "./static/download.html"
        ]
        
        for download_path in download_paths:
            try:
                if os.path.exists(download_path):
                    with open(download_path, "r", encoding="utf-8") as f:
                        return HTMLResponse(f.read())
            except Exception as e:
                print(f"Failed to read {download_path}: {e}")
                continue
                
        # Fallback HTML if no download.html found
        raise FileNotFoundError("download.html not found")
        
    except FileNotFoundError:
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html><head><title>BlindSend Download</title></head><body style="font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px;">
        <h1>🔒 BlindSend - Encrypted File Download</h1>
        <p>File ID: {file_id}</p>
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <strong>⚠️ This file is encrypted.</strong><br>
            You need both the decryption key and password (if set) to access it.
        </div>
        <form id="download-form">
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Your Name:</label>
                <input type="text" id="user-name" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
            </div>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">File Password (if required):</label>
                <input type="password" id="file-password" placeholder="Leave empty if no password" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
            </div>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; font-weight: bold;">Decryption Key (Required):</label>
                <input type="text" id="decryption-key" placeholder="Paste the 44-character decryption key" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
                <small style="color: #666; font-size: 12px;">This should be provided separately from the download link</small>
            </div>
            <button type="submit" style="background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; width: 100%;">🔓 Download & Decrypt File</button>
        </form>
        <div id="alerts"></div>
        <script>
            document.getElementById('download-form').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const userName = document.getElementById('user-name').value;
                const filePassword = document.getElementById('file-password').value;
                const decryptionKey = document.getElementById('decryption-key').value;
                
                if (!userName || !decryptionKey) {{
                    alert('Please fill in your name and decryption key');
                    return;
                }}
                
                if (decryptionKey.length !== 44) {{
                    alert('Invalid decryption key format. Key should be 44 characters long.');
                    return;
                }}
                
                try {{
                    const downloadUrl = `/api/files/download/{file_id}?user_name=${{encodeURIComponent(userName)}}${{filePassword ? '&password=' + encodeURIComponent(filePassword) : ''}}`;
                    const response = await fetch(downloadUrl);
                    
                    if (!response.ok) {{
                        const errorData = await response.json().catch(() => ({{ detail: 'Download failed' }}));
                        alert('❌ ' + (errorData.detail || 'Download failed'));
                        return;
                    }}
                    
                    const encryptedData = await response.arrayBuffer();
                    const keyData = Uint8Array.from(atob(decryptionKey), c => c.charCodeAt(0));
                    const cryptoKey = await crypto.subtle.importKey('raw', keyData, {{ name: 'AES-GCM' }}, false, ['decrypt']);
                    const iv = new Uint8Array(encryptedData.slice(0, 12));
                    const encrypted = new Uint8Array(encryptedData.slice(12));
                    const decrypted = await crypto.subtle.decrypt({{ name: 'AES-GCM', iv: iv }}, cryptoKey, encrypted);
                }} catch (decryptError) {{
                    // Report decryption failure to server for security tracking
                    fetch(`/api/files/report-decrypt-failure/{file_id}`, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ user_name: userName }})
                    }}).catch(() => {{}});
                    
                    alert('❌ Decryption failed - Invalid decryption key');
                    return;
                }}
                    
                    // Get original filename from the server response
                    let filename = 'decrypted_file';
                    
                    // Try to get filename from Content-Disposition header
                    const contentDisposition = response.headers.get('content-disposition');
                    if (contentDisposition) {{
                        const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                        if (filenameMatch && filenameMatch[1]) {{
                            filename = filenameMatch[1].replace(/["']/g, '');
                            // Remove .encrypted extension if present
                            if (filename.endsWith('.encrypted')) {{
                                filename = filename.slice(0, -10);
                            }}
                        }}
                    }}
                    
                    // If no filename from headers, try to extract from file ID or use default
                    if (filename === 'decrypted_file') {{
                        filename = 'file_{file_id}';
                    }}
                    
                    const blob = new Blob([decrypted]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    
                    alert('🎉 File downloaded and decrypted successfully!');
                }} catch (error) {{
                    alert('❌ Download/Decryption failed: ' + error.message);
                }}
            }});
        </script>
        </body></html>
        """)

@app.get("/admin/files")
async def list_server_files():
    """List all encrypted files on server (admin only)"""
    try:
        files = []
        if os.path.exists(UPLOAD_DIR):
            for filename in os.listdir(UPLOAD_DIR):
                file_path = os.path.join(UPLOAD_DIR, filename)
                file_size = os.path.getsize(file_path)
                file_id = filename.split("_")[0]
                original_name = "_".join(filename.split("_")[1:])
                
                files.append({
                    "file_id": file_id,
                    "encrypted_filename": filename,
                    "original_name": original_name,
                    "size_bytes": file_size,
                    "size_mb": round(file_size / 1024 / 1024, 2)
                })
        
        return {
            "total_files": len(files),
            "files": files,
            "note": "All files are encrypted - server cannot read content"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/init-db")
async def init_database():
    """Initialize database tables"""
    try:
        conn = get_db()
        if not conn:
            return {"error": "Database connection failed", "message": "Please check your database configuration"}
            
        with conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create other required tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_links (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    link_id VARCHAR(255) UNIQUE NOT NULL,
                    link_type VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS link_access_controls (
                    id SERIAL PRIMARY KEY,
                    link_id VARCHAR(255) UNIQUE NOT NULL,
                    max_downloads INTEGER DEFAULT 10,
                    custom_expires_at TIMESTAMP,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    password_hash VARCHAR(255)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_attempts (
                    id SERIAL PRIMARY KEY,
                    link_id VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(45),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    access_type VARCHAR(50),
                    success BOOLEAN,
                    risk_score FLOAT,
                    user_name VARCHAR(255)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    alert_type VARCHAR(100),
                    severity VARCHAR(50),
                    message TEXT,
                    link_id VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(100),
                    link_id VARCHAR(255),
                    ip_address VARCHAR(45),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN,
                    metadata JSONB
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN,
                    ip_address VARCHAR(45)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    session_id VARCHAR(255) UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    user_agent TEXT,
                    device_fingerprint VARCHAR(255),
                    ip_address VARCHAR(45)
                )
            """)
            
            conn.commit()
            
            return {"message": "Database initialized successfully", "status": "success"}
            
    except Exception as e:
        return {"error": f"Database initialization failed: {str(e)}", "status": "failed"}

@app.post("/api/auth/register")
async def register(request: Request, email: str = Form(...), password: str = Form(...), _rate_limit: bool = Depends(rate_limit_dependency)):
    """Register new user with rate limiting"""
    try:
        print(f"Registration attempt for: {email}")
        conn = get_db()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        try:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            print(f"Password hashed successfully")
            
            # Create user
            cursor.execute("""
                INSERT INTO users (email, password_hash, is_active, created_at)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (email, password_hash, True, utc_now()))
            
            user_id = cursor.fetchone()[0]
            conn.commit()
            print(f"User created with ID: {user_id}")
            
            # Create JWT token
            token = create_jwt_token(user_id, email)
            print(f"JWT token created")
            
            return {"token": token, "user_id": user_id, "email": email}
        finally:
            conn.close()
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), _rate_limit: bool = Depends(rate_limit_dependency)):
    """User login with security monitoring and rate limiting"""
    try:
        print(f"Login attempt for: {email}")
        conn = get_db()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection failed")
        
        try:
            cursor = conn.cursor()
            
            # Get user
            cursor.execute("SELECT id, password_hash FROM users WHERE email = %s AND is_active = true", (email,))
            user = cursor.fetchone()
            print(f"User found: {user is not None}")
            
            # Log login attempt
            success = False
            if user and bcrypt.checkpw(password.encode(), user[1].encode()):
                success = True
                user_id = user[0]
                print(f"Password verified for user {user_id}")
            
            cursor.execute("""
                INSERT INTO login_attempts (email, timestamp, success, ip_address)
                VALUES (%s, %s, %s, %s)
            """, (email, utc_now(), success, "127.0.0.1"))
            
            if not success:
                conn.commit()
                print(f"Login failed for {email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Create session
            session_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_id, created_at, last_activity, is_active, user_agent, device_fingerprint, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, session_id, utc_now(), utc_now(), True, "web-browser", "web-device", "127.0.0.1"))
            
            conn.commit()
            
            # Create JWT token
            token = create_jwt_token(user_id, email)
            print(f"Login successful for {email}")
            
            return {"token": token, "user_id": user_id, "email": email}
        finally:
            conn.close()
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    max_downloads: int = Form(default=10),
    expires_hours: int = Form(default=168),
    password: Optional[str] = Form(default=None),
    user_data: dict = Depends(verify_token),
    _rate_limit: bool = Depends(rate_limit_dependency)
):
    """Upload file with security controls and file size limits"""
    try:
        # Check file size before reading
        content = await file.read()
        file_size = len(content)
        
        if file_size > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE_MB}MB"
            )
        
        if file_size == 0:
            raise HTTPException(status_code=400, detail="Empty file not allowed")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        link_id = str(uuid.uuid4())
        file_path = os.path.join(UPLOAD_DIR, f"{link_id}_{file.filename}")
        
        with open(file_path, "wb") as f:
            f.write(content)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO user_links (user_id, link_id, link_type, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user_data["user_id"], link_id, 'file_share', utc_now()))
            
            expires_at = utc_now() + timedelta(hours=expires_hours)
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None
            cursor.execute("""
                INSERT INTO link_access_controls (link_id, max_downloads, custom_expires_at, is_revoked, password_hash)
                VALUES (%s, %s, %s, %s, %s)
            """, (link_id, max_downloads, expires_at, False, password_hash))
            
            cursor.execute("""
                INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                "file_upload", link_id, "127.0.0.1", utc_now(), True,
                json.dumps({
                    "filename": file.filename,
                    "file_size": len(content),
                    "max_downloads": max_downloads,
                    "expires_hours": expires_hours
                })
            ))
            
            conn.commit()
        
        return {
            "link_id": link_id,
            "download_url": f"/download/{link_id}",
            "expires_at": expires_at.isoformat(),
            "max_downloads": max_downloads
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/report-decrypt-failure/{link_id}")
async def report_decrypt_failure(link_id: str, request: Request):
    """Report decryption failure for security tracking"""
    try:
        data = await request.json()
        user_name = data.get('user_name', 'Anonymous')
        failure_type = data.get('failure_type', 'decryption')  # 'password', 'decryption', or 'both'
        client_ip = get_client_ip(request)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check ALL failures across both endpoints BEFORE logging this one
            cursor.execute("""
                SELECT COUNT(*) FROM access_attempts 
                WHERE link_id = %s AND user_name = %s AND success = false 
                AND timestamp > NOW() - INTERVAL '1 hour'
            """, (link_id, user_name))
            previous_failed_count = cursor.fetchone()[0]
            
            # Log the failure with specific type - use consistent naming
            if failure_type == 'decryption':
                access_type = 'decryption_failure'
            elif failure_type == 'password':
                access_type = 'password_failure'
            elif failure_type == 'both':
                access_type = 'both_failure'
            else:
                access_type = f"{failure_type}_failure"
            cursor.execute("""
                INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (link_id, client_ip, utc_now(), access_type, False, 0.9, user_name))
            
            # Total count including current failure
            total_failed_count = previous_failed_count + 1
            
            print(f"🔍 DEBUG: User '{user_name}' has {total_failed_count} total failures for link {link_id}")
            print(f"🔍 DEBUG: Threshold check: {total_failed_count} >= 3 = {total_failed_count >= 3}")
            
            if total_failed_count >= 3 and total_failed_count % 3 == 0:
                print(f"🚨 ALERT THRESHOLD REACHED: {total_failed_count} failures")
                cursor.execute("SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s", (link_id,))
                owner_result = cursor.fetchone()
                if owner_result:
                    owner_id = owner_result[0]
                    cursor.execute("SELECT email FROM users WHERE id = %s", (owner_id,))
                    owner_email_result = cursor.fetchone()
                    if owner_email_result:
                        owner_email = owner_email_result[0]

                        cursor.execute("""
                            SELECT access_type, COUNT(*) FROM access_attempts 
                            WHERE link_id = %s AND user_name = %s AND success = false 
                            AND timestamp > NOW() - INTERVAL '1 hour'
                            GROUP BY access_type
                        """, (link_id, user_name))
                        failure_breakdown = dict(cursor.fetchall())
                        password_fails = failure_breakdown.get('password_failure', 0)
                        decrypt_fails = failure_breakdown.get('decryption_failure', 0)
                        if access_type == 'decryption_failure':
                            decrypt_fails += 1

                            alert_msg = f"🚨 SECURITY ALERT: User '{user_name}' made {total_failed_count} failed attempts on your file in the last 1 hour"
                        cursor.execute("""
                            INSERT INTO security_alerts (user_id, alert_type, severity, message, link_id, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (owner_id, "suspicious_access_attempts", "high", alert_msg, link_id, utc_now()))
                        try:
                            email_sent = send_security_alert_email(owner_email, alert_msg, link_id)
                            print(f"Security alert created for user {owner_id}, email sent: {email_sent}")
                        except Exception as email_error:
                            print(f"❌ Email send failed: {email_error}")
                    else:
                        print(f"⏳ Alert already sent for link {link_id} in last hour, skipping")
            
            conn.commit()
            return {"status": "logged", "total_failures": total_failed_count}
            
    except Exception as e:
        print(f"Error logging decrypt failure: {e}")
        return {"status": "error", "error": str(e)}

@app.get("/api/files/download/{link_id}")
async def download_file(link_id: str, request: Request, password: Optional[str] = None, user_name: Optional[str] = None, _rate_limit: bool = Depends(rate_limit_dependency)):
    """Download file with access monitoring and rate limiting"""
    if not user_name:
        raise HTTPException(status_code=400, detail="User name is required")
    
    client_ip = get_client_ip(request)
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT lac.max_downloads, lac.custom_expires_at, lac.is_revoked, lac.password_hash,
                       COUNT(CASE WHEN aa.success = true THEN 1 END) as download_count
                FROM link_access_controls lac
                LEFT JOIN access_attempts aa ON lac.link_id = aa.link_id AND aa.access_type = 'download'
                WHERE lac.link_id = %s
                GROUP BY lac.link_id, lac.max_downloads, lac.custom_expires_at, lac.is_revoked, lac.password_hash
            """, (link_id,))
            
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="File not found")
            
            max_downloads, expires_at, is_revoked, password_hash, download_count = result
            
            if password_hash and (not password or not bcrypt.checkpw(password.encode(), password_hash.encode())):
                # Count BEFORE inserting
                cursor.execute("""
                    SELECT COUNT(*) FROM access_attempts
                    WHERE link_id = %s AND user_name = %s AND success = false
                    AND timestamp > NOW() - INTERVAL '1 hour'
                """, (link_id, user_name))
                total_failed_count = cursor.fetchone()[0] + 1
                print(f"🔍 PASSWORD FAIL: User '{user_name}' total_failed_count={total_failed_count}, mod={total_failed_count % 3}")

                cursor.execute("""
                    INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (link_id, client_ip, utc_now(), "password_failure", False, 0.8, user_name))

                if total_failed_count >= 3 and total_failed_count % 3 == 0:
                    cursor.execute("SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s", (link_id,))
                    owner_result = cursor.fetchone()
                    if owner_result:
                        owner_id = owner_result[0]
                        cursor.execute("SELECT email FROM users WHERE id = %s", (owner_id,))
                        owner_email_result = cursor.fetchone()
                        if owner_email_result:
                            owner_email = owner_email_result[0]
                            alert_msg = f"🚨 SECURITY ALERT: User '{user_name}' made {total_failed_count} failed attempts on your file in the last 1 hour"
                            cursor.execute("""
                                INSERT INTO security_alerts (user_id, alert_type, severity, message, link_id, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (owner_id, "suspicious_access_attempts", "high", alert_msg, link_id, utc_now()))
                            send_security_alert_email(owner_email, alert_msg, link_id)
                            print(f"🚨 Alert sent to {owner_email} after {total_failed_count} total failures")

                conn.commit()
                raise HTTPException(status_code=401, detail="Invalid password")
            
            if is_revoked:
                raise HTTPException(status_code=403, detail="Access revoked")
            
            if expires_at and datetime.now() > expires_at:
                raise HTTPException(status_code=403, detail="Link expired")
            
            if download_count >= max_downloads:
                raise HTTPException(status_code=403, detail="Download limit exceeded")
            
            cursor.execute("""
                INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (link_id, client_ip, utc_now(), "download", True, 0.1, user_name))
            
            conn.commit()
            
            for filename in os.listdir(UPLOAD_DIR):
                if filename.startswith(f"{link_id}_"):
                    original_filename = filename.split("_", 1)[1]
                    if original_filename.endswith('.encrypted'):
                        original_filename = original_filename[:-10]
                    
                    from urllib.parse import quote
                    return FileResponse(
                        os.path.join(UPLOAD_DIR, filename),
                        filename=original_filename,
                        media_type='application/octet-stream',
                        headers={
                            'Content-Disposition': f'attachment; filename="{quote(original_filename)}"'
                        }
                    )
            
            raise HTTPException(status_code=404, detail="File not found on disk")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/revoke/{link_id}")
async def revoke_access(link_id: str, user_data: dict = Depends(verify_token)):
    """Revoke access to a file"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s", (link_id,))
            result = cursor.fetchone()
            if not result or result[0] != user_data["user_id"]:
                raise HTTPException(status_code=403, detail="Not authorized")
            
            cursor.execute("UPDATE link_access_controls SET is_revoked = true WHERE link_id = %s", (link_id,))
            conn.commit()
            return {"message": "Access revoked successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/user/activity")
async def get_user_activity(
    page: int = 1, 
    limit: int = 10,
    file_page: int = 1,
    file_limit: int = 10,
    user_data: dict = Depends(verify_token)
):
    """Get user activity with full pagination and analytics"""
    try:
        offset = (page - 1) * limit
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            uploads = []
            downloads = []
            alerts = []
            
            print(f"Getting activity for user_id: {user_data['user_id']}")
            
            try:
                # Get uploads with pagination
                cursor.execute("""
                    SELECT ae.timestamp, ae.metadata, ae.link_id
                    FROM audit_events ae
                    WHERE ae.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    ) AND ae.event_type = 'file_upload'
                    ORDER BY ae.timestamp DESC LIMIT %s OFFSET %s
                """, (user_data["user_id"], limit, offset))
                
                rows = cursor.fetchall()
                
                for row in rows:
                    metadata = row[1] if isinstance(row[1], dict) else (json.loads(row[1]) if row[1] else {})
                    upload_data = {
                        "timestamp": to_india_time(row[0]),
                        "filename": metadata.get("filename", "unknown"),
                        "link_id": row[2]
                    }
                    uploads.append(upload_data)
                
                # Get total upload count
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM audit_events ae
                    WHERE ae.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    ) AND ae.event_type = 'file_upload'
                """, (user_data["user_id"],))
                total_uploads = cursor.fetchone()[0]
                    
            except Exception as e:
                print(f"Error getting uploads: {e}")
                import traceback
                traceback.print_exc()
                total_uploads = 0
            
            try:
                # Get downloads with pagination - include ALL access attempts (success and failures)
                cursor.execute("""
                    SELECT aa.timestamp, aa.ip_address, aa.link_id, aa.success, aa.user_name, aa.access_type
                    FROM access_attempts aa
                    WHERE aa.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    )
                    ORDER BY aa.timestamp DESC LIMIT %s OFFSET %s
                """, (user_data["user_id"], limit, offset))
                
                for row in cursor.fetchall():
                    location = get_location_from_ip(row[1])
                    downloads.append({
                        "timestamp": to_india_time(row[0]),
                        "ip_address": row[1],
                        "link_id": row[2],
                        "success": row[3],
                        "user_name": row[4] or "Anonymous",
                        "location": location,
                        "access_type": row[5]
                    })
                
                # Get total download count - include ALL access attempts
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM access_attempts aa
                    WHERE aa.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    )
                """, (user_data["user_id"],))
                total_downloads = cursor.fetchone()[0]
                
            except Exception as e:
                print(f"Error getting downloads: {e}")
                total_downloads = 0
                
            # Get analytics with pagination for file statistics
            analytics = {}
            try:
                file_offset = (file_page - 1) * file_limit
                
                # Total downloads per file with filename (paginated) - include ALL access attempts
                cursor.execute("""
                    SELECT ul.link_id, 
                           COUNT(CASE WHEN aa.access_type = 'download' AND aa.success = true THEN 1 END) as download_count,
                           COUNT(CASE WHEN aa.success = false THEN 1 END) as failed_attempts,
                           ae.metadata, ae.timestamp
                    FROM user_links ul
                    LEFT JOIN access_attempts aa ON ul.link_id = aa.link_id
                    LEFT JOIN audit_events ae ON ul.link_id = ae.link_id AND ae.event_type = 'file_upload'
                    WHERE ul.user_id = %s
                    GROUP BY ul.link_id, ae.metadata, ae.timestamp
                    ORDER BY ae.timestamp DESC
                    LIMIT %s OFFSET %s
                """, (user_data["user_id"], file_limit, file_offset))
                
                file_stats = []
                for row in cursor.fetchall():
                    metadata = row[3] if isinstance(row[3], dict) else (json.loads(row[3]) if row[3] else {})
                    filename = metadata.get("filename", "Unknown")
                    file_stat = {
                        "link_id": row[0],
                        "filename": filename,
                        "total_downloads": row[1] or 0,
                        "failed_attempts": row[2] or 0,
                        "upload_date": row[4].isoformat() if row[4] else None
                    }
                    file_stats.append(file_stat)
                
                analytics["file_statistics"] = file_stats
                
                # Get total file count for pagination
                cursor.execute("""
                    SELECT COUNT(DISTINCT ul.link_id) as total_files
                    FROM user_links ul
                    WHERE ul.user_id = %s AND ul.link_type = 'file_share'
                """, (user_data["user_id"],))
                
                total_files = cursor.fetchone()[0] or 0
                analytics["total_files_count"] = total_files
                
                # Unique visitors (by name and IP combination)
                cursor.execute("""
                    SELECT COUNT(DISTINCT COALESCE(aa.user_name, 'Anonymous') || '_' || aa.ip_address) as unique_visitors
                    FROM access_attempts aa
                    WHERE aa.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    ) AND aa.success = true
                """, (user_data["user_id"],))
                
                unique_visitors = cursor.fetchone()[0] or 0
                analytics["unique_visitors"] = unique_visitors
                
                # Total files shared by user
                analytics["total_files_shared"] = total_files
                
            except Exception as e:
                print(f"Error getting analytics: {e}")
            
            # Get security alerts
            try:
                cursor.execute("""
                    SELECT alert_type, message, created_at, severity
                    FROM security_alerts 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC LIMIT 10
                """, (user_data["user_id"],))
                
                for row in cursor.fetchall():
                    alerts.append({
                        "type": row[0],
                        "message": row[1],
                        "timestamp": row[2].isoformat() if row[2] else None,
                        "severity": row[3]
                    })
            except Exception as e:
                print(f"Error getting security alerts: {e}")
            
            return {
                "user_id": user_data["user_id"],
                "email": user_data["email"],
                "recent_uploads": uploads,
                "recent_downloads": downloads,
                "security_alerts": alerts,
                "analytics": analytics,
                "pagination": {
                    "current_page": page,
                    "limit": limit,
                    "total_uploads": total_uploads,
                    "total_downloads": total_downloads,
                    "total_upload_pages": (total_uploads + limit - 1) // limit,
                    "total_download_pages": (total_downloads + limit - 1) // limit,
                    "file_page": file_page,
                    "file_limit": file_limit,
                    "total_files": analytics.get("total_files_count", 0),
                    "total_file_pages": (analytics.get("total_files_count", 0) + file_limit - 1) // file_limit
                }
            }
            
    except Exception as e:
        print(f"Activity endpoint error: {e}")
        return {
            "user_id": user_data["user_id"],
            "email": user_data["email"],
            "recent_uploads": [],
            "recent_downloads": [],
            "security_alerts": [],
            "analytics": {}
        }

@app.get("/api/ai/security-dashboard")
async def ai_security_dashboard(user_data: dict = Depends(verify_token)):
    """AI-powered security dashboard with threat analysis"""
    try:
        if not ai_engine:
            raise HTTPException(status_code=503, detail="AI Security Engine not available")
        
        # Get AI risk assessment for user
        risk_assessment = ai_engine.assess_single_user(user_data["user_id"])
        
        # Get system-wide security report
        security_report = ai_engine.generate_security_report(hours_back=24)
        
        # Get AI system status
        ai_status = ai_engine.get_system_status()
        
        return {
            "user_risk_assessment": risk_assessment,
            "system_security_report": security_report,
            "ai_system_status": ai_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI dashboard error: {str(e)}")

@app.post("/api/ai/initialize")
@app.get("/api/ai/initialize")
async def initialize_ai_system(retrain_models: bool = False):
    """Initialize or retrain AI security models"""
    try:
        global ai_engine
        
        if not AI_IMPORTS_AVAILABLE:
            return {"error": "AI components not available", "status": "failed"}
        
        if not ai_engine:
            ai_engine = AISecurityEngine(DB_CONFIG)
        
        # Initialize the AI system
        success = ai_engine.initialize_system(retrain_models=retrain_models)
        
        if success:
            # Start monitoring if not already running
            if not ai_engine.is_running:
                ai_engine.start_monitoring()
            
            return {
                "message": "AI Security Engine initialized successfully",
                "models_trained": ai_engine.models_trained,
                "monitoring_active": ai_engine.is_running,
                "system_status": ai_engine.get_system_status()
            }
        else:
            return {"error": "Failed to initialize AI system", "status": "failed"}
            
    except Exception as e:
        return {"error": f"AI initialization error: {str(e)}", "status": "failed"}

@app.get("/api/ai/status")
async def ai_status():
    """Get AI system status"""
    return {
        "ai_imports_available": AI_IMPORTS_AVAILABLE,
        "ai_engine_initialized": ai_engine is not None,
        "models_trained": ai_engine.models_trained if ai_engine else False,
        "monitoring_active": ai_engine.is_running if ai_engine else False,
        "system_status": ai_engine.get_system_status() if ai_engine else None
    }

@app.get("/api/ai/threat-analysis/{user_id}")
async def get_user_threat_analysis(user_id: int, admin_data: dict = Depends(verify_token)):
    """Get detailed AI threat analysis for a specific user (admin only)"""
    try:
        if not ai_engine or not ai_engine.models_trained:
            raise HTTPException(status_code=503, detail="AI Security Engine not ready")
        
        # Perform comprehensive threat analysis
        risk_assessment = ai_engine.assess_single_user(user_id)
        
        if not risk_assessment:
            raise HTTPException(status_code=404, detail="User not found or insufficient data")
        
        return {
            "user_id": user_id,
            "threat_analysis": risk_assessment,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat analysis error: {str(e)}")

@app.get("/api/debug/failures/{link_id}")
async def debug_failures(link_id: str):
    """Debug endpoint to check what failure types are being stored"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check all access attempts for this link
            cursor.execute("""
                SELECT access_type, success, user_name, timestamp 
                FROM access_attempts 
                WHERE link_id = %s 
                ORDER BY timestamp DESC LIMIT 20
            """, (link_id,))
            
            attempts = cursor.fetchall()
            
            # Get failure breakdown
            cursor.execute("""
                SELECT access_type, COUNT(*) 
                FROM access_attempts 
                WHERE link_id = %s AND success = false 
                GROUP BY access_type
            """, (link_id,))
            
            breakdown = dict(cursor.fetchall())
            
            return {
                "link_id": link_id,
                "recent_attempts": [{
                    "access_type": attempt[0],
                    "success": attempt[1],
                    "user_name": attempt[2],
                    "timestamp": attempt[3].isoformat() if attempt[3] else None
                } for attempt in attempts],
                "failure_breakdown": breakdown,
                "total_failures": sum(breakdown.values())
            }
            
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/debug/security")
async def debug_security():
    """Debug endpoint to check security alerts and access attempts"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check security alerts
            cursor.execute("SELECT COUNT(*) FROM security_alerts")
            alerts_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 5")
            recent_alerts = cursor.fetchall()
            
            # Check access attempts
            cursor.execute("SELECT COUNT(*) FROM access_attempts")
            attempts_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT * FROM access_attempts ORDER BY timestamp DESC LIMIT 5")
            recent_attempts = cursor.fetchall()
            
            # Check users
            cursor.execute("SELECT COUNT(*) FROM users")
            users_count = cursor.fetchone()[0]
            
            return {
                "security_alerts": {
                    "count": alerts_count,
                    "recent": [dict(zip(["id", "user_id", "alert_type", "severity", "message", "link_id", "created_at"], alert)) for alert in recent_alerts]
                },
                "access_attempts": {
                    "count": attempts_count,
                    "recent": [dict(zip(["id", "link_id", "ip_address", "timestamp", "access_type", "success", "risk_score", "user_name"], attempt)) for attempt in recent_attempts]
                },
                "users_count": users_count,
                "database_connection": "working",
                "timestamp": datetime.now().isoformat()
            }
            
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn
    PORT = int(os.environ.get('PORT', 5000))
    print("="*70)
    print("🔐 BLINDSEND - AI-ENHANCED SECURE FILE SHARING")
    print("="*70)
    print(f"✅ Server starting on http://localhost:{PORT}")
    print(f"✅ Rate limiting: {RATE_LIMITING_ENABLED}")
    print(f"✅ Max file size: {MAX_FILE_SIZE_MB}MB")
    print(f"✅ CORS origins: {ALLOWED_ORIGINS}")
    print(f"✅ AI Security: {'Enabled' if ai_engine else 'Disabled'}")
    print("="*70)
    print(f"\n🌐 Access your application at: http://localhost:{PORT}")
    print(f"📊 Health check: http://localhost:{PORT}/health")
    print(f"🔧 Initialize DB: http://localhost:{PORT}/init-db")
    print("\n" + "="*70)
    
    uvicorn.run(app, host="0.0.0.0", port=PORT)
