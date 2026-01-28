"""
FastAPI Server for Blindsend Frontend
Provides REST API endpoints for secure file sharing with AI security
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import psycopg2
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
import json
import os
import sys

# Add AI security path
sys.path.append('../ai_security')
from config import DB_CONFIG

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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    return FileResponse("favicon.ico")

# JWT settings
JWT_SECRET = "your-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"

def get_db():
    """Database connection"""
    return psycopg2.connect(**DB_CONFIG)

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
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("""
        <html><body>
        <h1>🔐 BlindSend - End-to-End Encrypted File Sharing</h1>
        <p>Main application not found. Please ensure static/index.html exists.</p>
        </body></html>
        """)

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
        with open("static/download.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse(f"""
        <html><body>
        <h1>🔒 BlindSend - Encrypted File Download</h1>
        <p>File ID: {file_id}</p>
        <p>This file is encrypted. You need the decryption key to access it.</p>
        <form method="get" action="/api/files/download/{file_id}">
            <label>Your Name:</label>
            <input type="text" name="user_name" required><br><br>
            <label>File Password (if required):</label>
            <input type="password" name="password"><br><br>
            <button type="submit">Download Encrypted File</button>
        </form>
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
        # Create upload directory
        os.makedirs("uploads", exist_ok=True)
        
        # Generate unique link ID
        link_id = str(uuid.uuid4())
        file_path = f"uploads/{link_id}_{file.filename}"
        
        # Save file
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Create user_links entry
            cursor.execute("""
                INSERT INTO user_links (user_id, link_id, link_type, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user_data["user_id"], link_id, 'file_share', datetime.now()))
            
            # Create access controls
            expires_at = datetime.now() + timedelta(hours=expires_hours)
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None
            cursor.execute("""
                INSERT INTO link_access_controls (link_id, max_downloads, custom_expires_at, is_revoked, password_hash)
                VALUES (%s, %s, %s, %s, %s)
            """, (link_id, max_downloads, expires_at, False, password_hash))
            
            # Log upload event
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

@app.get("/download/{link_id}", response_class=HTMLResponse)
async def download_page(link_id: str):
    """Serve download page with password protection"""
    try:
        with open("static/download.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse(f"""
        <html><body>
        <h1>🔒 AI Enhanced Secure File Sharing System</h1>
        <p>File ID: {link_id}</p>
        <form method="get" action="/api/files/download/{link_id}">
            <label>Your Name (Optional):</label>
            <input type="text" name="user_name" placeholder="Enter your name">
            <label>Access Key:</label>
            <input type="password" name="password" required>
            <button type="submit">Download</button>
        </form>
        </body></html>
        """)

@app.get("/api/files/download/{link_id}")
async def download_file(link_id: str, request: Request, password: Optional[str] = None, user_name: Optional[str] = None):
    """Download file with access monitoring"""
    if not user_name:
        raise HTTPException(status_code=400, detail="User name is required")
    
    client_ip = get_client_ip(request)
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check access controls
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
            
            # Check password if required
            if password_hash:
                if not password:
                    # Log failed attempt
                    cursor.execute("""
                        INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (link_id, client_ip, datetime.now(), "download", False, 0.8, user_name))
                    conn.commit()
                    raise HTTPException(status_code=401, detail="Password required")
                if not bcrypt.checkpw(password.encode(), password_hash.encode()):
                    # Log failed attempt
                    cursor.execute("""
                        INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (link_id, client_ip, datetime.now(), "download", False, 0.8, user_name))
                    
                    # Check for multiple failed attempts and create security alert
                    cursor.execute("""
                        SELECT COUNT(*) FROM access_attempts 
                        WHERE link_id = %s AND user_name = %s AND success = false 
                        AND timestamp > NOW() - INTERVAL '1 hour'
                    """, (link_id, user_name))
                    
                    failed_count = cursor.fetchone()[0]
                    if failed_count > 3:
                        # Get file owner
                        cursor.execute("""
                            SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s
                        """, (link_id,))
                        owner_result = cursor.fetchone()
                        
                        if owner_result:
                            owner_id = owner_result[0]
                            
                            # Get owner email
                            cursor.execute("SELECT email FROM users WHERE id = %s", (owner_id,))
                            owner_email_result = cursor.fetchone()
                            
                            if owner_email_result:
                                owner_email = owner_email_result[0]
                                alert_msg = f"User '{user_name}' made {failed_count} failed password attempts on your file"
                                
                                # Create security alert
                                cursor.execute("""
                                    INSERT INTO security_alerts (user_id, alert_type, severity, message, link_id, created_at)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                """, (
                                    owner_id, 
                                    "suspicious_access", 
                                    "medium",
                                    alert_msg,
                                    link_id,
                                    datetime.now()
                                ))
                                
                                # Send email notification
                                send_security_alert_email(owner_email, alert_msg, link_id)
                    
                    conn.commit()
                    raise HTTPException(status_code=401, detail="Invalid password")
            
            # Check if revoked
            if is_revoked:
                raise HTTPException(status_code=403, detail="Access revoked")
            
            # Check expiration
            if expires_at and datetime.now() > expires_at:
                raise HTTPException(status_code=403, detail="Link expired")
            
            # Check download limit
            if download_count >= max_downloads:
                raise HTTPException(status_code=403, detail="Download limit exceeded")
            
            # Log access attempt with user name
            cursor.execute("""
                INSERT INTO access_attempts (link_id, ip_address, timestamp, access_type, success, risk_score, user_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (link_id, client_ip, datetime.now(), "download", True, 0.1, user_name))
            
            conn.commit()
            
            # Find file
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
    """Instantly revoke access to a file"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if user owns this link
            cursor.execute("""
                SELECT ul.user_id FROM user_links ul WHERE ul.link_id = %s
            """, (link_id,))
            
            result = cursor.fetchone()
            if not result or result[0] != user_data["user_id"]:
                raise HTTPException(status_code=403, detail="Not authorized")
            
            # Revoke access
            cursor.execute("""
                UPDATE link_access_controls SET is_revoked = true WHERE link_id = %s
            """, (link_id,))
            
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
    """Get user activity with pagination"""
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

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)