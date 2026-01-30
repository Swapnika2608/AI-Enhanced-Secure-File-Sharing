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
from datetime import datetime, timedelta
from typing import Optional, List
import json
import os
import sys

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
        DB_CONFIG = {
            'host': os.environ.get('DB_HOST', 'localhost'),
            'port': int(os.environ.get('DB_PORT', 5432)),
            'dbname': os.environ.get('DB_NAME', 'blindsend_test'),
            'user': os.environ.get('DB_USER', 'postgres'),
            'password': os.environ.get('DB_PASSWORD', 'Swapnika2608')
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

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

def send_security_alert_email(user_email: str, alert_message: str, link_id: str):
    """Send security alert email to user"""
    try:
        # Gmail SMTP configuration (you can change this)
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "veerlapatiswapnika26@gmail.com"  # Your Gmail
        sender_password = "qnuu jrvv qovg gxsl"  # Your app password
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = user_email
        msg['Subject'] = "🚨 Security Alert - Blindsend"
        
        body = f"""
        Security Alert for your file sharing link!
        
        Alert: {alert_message}
        Link ID: {link_id}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        If this wasn't you, consider revoking the link immediately.
        
        - Blindsend Security Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        
        print(f"Security alert email sent to {user_email}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Keep open for now, restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Debug: Print paths
print(f"BASE_DIR: {BASE_DIR}")
print(f"STATIC_DIR: {STATIC_DIR}")
print(f"Static dir exists: {os.path.isdir(STATIC_DIR)}")

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    print(f"Mounted static files from: {STATIC_DIR}")
else:
    print(f"Static directory not found: {STATIC_DIR}")

@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    try:
        return FileResponse(os.path.join(BASE_DIR, "favicon.ico"))
    except:
        # Return a simple response if favicon not found
        return HTMLResponse("")

# JWT settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"

def get_db():
    """Database connection"""
    try:
        # Use dbname for psycopg3 (not database)
        db_config = DB_CONFIG.copy()
        if 'database' in db_config:
            db_config['dbname'] = db_config.pop('database')
        
        # Debug: Print connection details (without password)
        debug_config = db_config.copy()
        debug_config['password'] = '***'
        print(f"Attempting DB connection with: {debug_config}")
        
        conn = psycopg.connect(**db_config)
        print("Database connection successful!")
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
        "exp": datetime.utcnow() + timedelta(hours=24)
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
        # Try the correct path since we know static dir exists
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
        
        # Fallback paths
        static_paths = [
            "static/index.html",
            "frontend/static/index.html", 
            "./static/index.html"
        ]
        
        for path in static_paths:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return HTMLResponse(f.read())
            except FileNotFoundError:
                continue
                
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
        os.makedirs("uploads", exist_ok=True)
        
        # Generate unique file ID
        file_id = str(uuid.uuid4())
        file_path = f"uploads/{file_id}_{file.filename}"
        
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
        download_path = os.path.join(STATIC_DIR, "download.html")
        with open(download_path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
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
        if os.path.exists("uploads"):
            for filename in os.listdir("uploads"):
                file_path = f"uploads/{filename}"
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
async def register(email: str = Form(...), password: str = Form(...)):
    """Register new user"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            # Create user
            cursor.execute("""
                INSERT INTO users (email, password_hash, is_active, created_at)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (email, password_hash, True, datetime.now()))
            
            user_id = cursor.fetchone()[0]
            conn.commit()
            
            # Create JWT token
            token = create_jwt_token(user_id, email)
            
            return {"token": token, "user_id": user_id, "email": email}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/login")
async def login(email: str = Form(...), password: str = Form(...)):
    """User login with security monitoring"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get user
            cursor.execute("SELECT id, password_hash FROM users WHERE email = %s AND is_active = true", (email,))
            user = cursor.fetchone()
            
            # Log login attempt
            success = False
            if user and bcrypt.checkpw(password.encode(), user[1].encode()):
                success = True
                user_id = user[0]
            
            cursor.execute("""
                INSERT INTO login_attempts (email, timestamp, success, ip_address)
                VALUES (%s, %s, %s, %s)
            """, (email, datetime.now(), success, "127.0.0.1"))
            
            if not success:
                conn.commit()
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Create session
            session_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_id, created_at, last_activity, is_active, user_agent, device_fingerprint, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, session_id, datetime.now(), datetime.now(), True, "web-browser", "web-device", "127.0.0.1"))
            
            conn.commit()
            
            # Create JWT token
            token = create_jwt_token(user_id, email)
            
            return {"token": token, "user_id": user_id, "email": email}
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    max_downloads: int = Form(default=10),
    expires_hours: int = Form(default=168),
    password: Optional[str] = Form(default=None),
    user_data: dict = Depends(verify_token)
):
    """Upload file with security controls"""
    try:
        os.makedirs("uploads", exist_ok=True)
        link_id = str(uuid.uuid4())
        file_path = f"uploads/{link_id}_{file.filename}"
        
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO user_links (user_id, link_id, link_type, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user_data["user_id"], link_id, 'file_share', datetime.now()))
            
            expires_at = datetime.now() + timedelta(hours=expires_hours)
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None
            cursor.execute("""
                INSERT INTO link_access_controls (link_id, max_downloads, custom_expires_at, is_revoked, password_hash)
                VALUES (%s, %s, %s, %s, %s)
            """, (link_id, max_downloads, expires_at, False, password_hash))
            
            cursor.execute("""
                INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                "file_upload", link_id, "127.0.0.1", datetime.now(), True,
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

@app.get("/api/files/download/{link_id}")
async def download_file(link_id: str, request: Request, password: Optional[str] = None, user_name: Optional[str] = None):
    """Download file with access monitoring"""
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
                cursor.execute("""
                    INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (link_id, client_ip, datetime.now(), "download", False, 0.8, user_name))
                conn.commit()
                raise HTTPException(status_code=401, detail="Invalid password")
            
            if is_revoked:
                raise HTTPException(status_code=403, detail="Access revoked")
            
            if expires_at and datetime.now() > expires_at:
                raise HTTPException(status_code=403, detail="Link expired")
            
            if download_count >= max_downloads:
                raise HTTPException(status_code=403, detail="Download limit exceeded")
            
            # Check for multiple failed attempts and create security alert
            if password_hash and password and not bcrypt.checkpw(password.encode(), password_hash.encode()):
                cursor.execute("""
                    SELECT COUNT(*) FROM access_attempts 
                    WHERE link_id = %s AND user_name = %s AND success = false 
                    AND timestamp > NOW() - INTERVAL '1 hour'
                """, (link_id, user_name))
                
                failed_count = cursor.fetchone()[0]
                if failed_count > 3:
                    # Get file owner
                    cursor.execute("SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s", (link_id,))
                    owner_result = cursor.fetchone()
                    
                    if owner_result:
                        owner_id = owner_result[0]
                        cursor.execute("SELECT email FROM users WHERE id = %s", (owner_id,))
                        owner_email_result = cursor.fetchone()
                        
                        if owner_email_result:
                            owner_email = owner_email_result[0]
                            alert_msg = f"User '{user_name}' made {failed_count} failed password attempts on your file"
                            
                            cursor.execute("""
                                INSERT INTO security_alerts (user_id, alert_type, severity, message, link_id, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (owner_id, "suspicious_access", "medium", alert_msg, link_id, datetime.now()))
                            
                            send_security_alert_email(owner_email, alert_msg, link_id)
            
            cursor.execute("""
                INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (link_id, client_ip, datetime.now(), "download", True, 0.1, user_name))
            
            # AI-powered risk assessment
            if ai_engine and ai_engine.models_trained:
                try:
                    # Get file owner for risk assessment
                    cursor.execute("SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s", (link_id,))
                    owner_result = cursor.fetchone()
                    
                    if owner_result:
                        owner_id = owner_result[0]
                        
                        # Perform AI risk assessment
                        risk_assessment = ai_engine.assess_single_user(
                            user_id=owner_id,
                            context={
                                'download_ip': client_ip,
                                'download_user': user_name,
                                'link_id': link_id,
                                'access_time': datetime.now().isoformat()
                            }
                        )
                        
                        if risk_assessment and risk_assessment['risk_level'] in ['high', 'critical']:
                            # Generate automated security responses
                            responses = ai_engine.response_system.process_threat_detection(risk_assessment)
                            ai_engine.response_system.execute_responses(responses)
                            
                            print(f"HIGH-RISK download detected for user {owner_id}: {risk_assessment['risk_level']}")
                            
                except Exception as e:
                    print(f"AI risk assessment failed: {e}")
            
            conn.commit()
            
            for filename in os.listdir("uploads"):
                if filename.startswith(f"{link_id}_"):
                    return FileResponse(f"uploads/{filename}", filename=filename.split("_", 1)[1])
            
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
            
            print(f"Getting activity for user_id: {user_data['user_id']}, page: {page}, limit: {limit}")
            
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
                print(f"Found {len(rows)} upload records")
                
                for row in rows:
                    metadata = row[1] if isinstance(row[1], dict) else (json.loads(row[1]) if row[1] else {})
                    upload_data = {
                        "timestamp": row[0].isoformat(),
                        "filename": metadata.get("filename", "unknown"),
                        "link_id": row[2]
                    }
                    uploads.append(upload_data)
                    print(f"Added upload: {upload_data}")
                
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
                # Get downloads with pagination
                cursor.execute("""
                    SELECT aa.timestamp, aa.ip_address, aa.link_id, aa.success, aa.user_name
                    FROM access_attempts aa
                    WHERE aa.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    ) AND aa.access_type = 'download'
                    ORDER BY aa.timestamp DESC LIMIT %s OFFSET %s
                """, (user_data["user_id"], limit, offset))
                
                for row in cursor.fetchall():
                    location = get_location_from_ip(row[1])
                    downloads.append({
                        "timestamp": row[0].isoformat(),
                        "ip_address": row[1],
                        "link_id": row[2],
                        "success": row[3],
                        "user_name": row[4] or "Anonymous",
                        "location": location
                    })
                
                # Get total download count
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM access_attempts aa
                    WHERE aa.link_id IN (
                        SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                    ) AND aa.access_type = 'download'
                """, (user_data["user_id"],))
                total_downloads = cursor.fetchone()[0]
                
            except Exception as e:
                print(f"Error getting downloads: {e}")
                total_downloads = 0
                
            # Get analytics with pagination for file statistics
            analytics = {}
            try:
                file_offset = (file_page - 1) * file_limit
                
                # Total downloads per file with filename (paginated)
                cursor.execute("""
                    SELECT ul.link_id, COUNT(aa.id) as download_count,
                           SUM(CASE WHEN aa.success = false THEN 1 ELSE 0 END) as failed_attempts,
                           ae.metadata, ae.timestamp
                    FROM user_links ul
                    LEFT JOIN access_attempts aa ON ul.link_id = aa.link_id AND aa.access_type = 'download'
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
                    print(f"File stat: {file_stat}")
                
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
                        "timestamp": row[2].isoformat(),
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
            
        cursor.execute("""
                INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (link_id, client_ip, datetime.now(), "download", True, 0.1, user_name))
            
        conn.commit()
            
        for filename in os.listdir("uploads"):
                if filename.startswith(f"{link_id}_"):
                    return FileResponse(f"uploads/{filename}", filename=filename.split("_", 1)[1])
            
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
async def get_user_activity(user_data: dict = Depends(verify_token)):
    """Get user activity"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT ae.timestamp, ae.metadata, ae.link_id
                FROM audit_events ae
                WHERE ae.link_id IN (
                    SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                ) AND ae.event_type = 'file_upload'
                ORDER BY ae.timestamp DESC LIMIT 10
            """, (user_data["user_id"],))
            
            uploads = []
            for row in cursor.fetchall():
                metadata = row[1] if isinstance(row[1], dict) else (json.loads(row[1]) if row[1] else {})
                uploads.append({
                    "timestamp": row[0].isoformat(),
                    "filename": metadata.get("filename", "unknown"),
                    "link_id": row[2]
                })
            
            cursor.execute("""
                SELECT aa.timestamp, aa.ip_address, aa.link_id, aa.success, aa.user_name
                FROM access_attempts aa
                WHERE aa.link_id IN (
                    SELECT ul.link_id FROM user_links ul WHERE ul.user_id = %s
                ) AND aa.access_type = 'download'
                ORDER BY aa.timestamp DESC LIMIT 10
            """, (user_data["user_id"],))
            
            downloads = []
            for row in cursor.fetchall():
                downloads.append({
                    "timestamp": row[0].isoformat(),
                    "ip_address": row[1],
                    "link_id": row[2],
                    "success": row[3],
                    "user_name": row[4] or "Anonymous",
                    "location": get_location_from_ip(row[1])
                })
            
            return {
                "user_id": user_data["user_id"],
                "email": user_data["email"],
                "recent_uploads": uploads,
                "recent_downloads": downloads
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="localhost", port=port)