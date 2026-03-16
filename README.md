# AI-ENHANCED SECURE FILE ENCRYPTION AND SHARING SYSTEM

> **Next-generation secure file sharing with AI-powered threat detection**

BlindSend combines AES-256 encryption with ensemble machine learning models to provide enterprise-grade secure file sharing with real-time behavioral threat detection.

## ✨ Key Features

### 🔐 **Zero-Knowledge Security**
- **AES-256 client-side encryption** - Files encrypted in browser before upload
- **Zero-knowledge architecture** - Server never accesses plaintext data
- **JWT authentication** - Secure token-based user sessions
- **Password-protected links** - Optional additional layer of security
- **Access controls** - Download limits and expiration times

### 🤖 **AI-Powered Protection**
- **Ensemble anomaly detection** - Isolation Forest, One-Class SVM, and LSTM Autoencoder
- **Behavioral analysis** - 15+ user behavioral features tracked
- **Risk scoring** - Multi-factor threat assessment (0-100 scale)
- **Automated responses** - Real-time threat mitigation
- **Security alerts** - Email notifications for suspicious activity

### 🚀 **User Experience**
- **Modern web interface** - Drag & drop file uploads
- **Instant sharing** - Generate secure download links
- **Activity dashboard** - Track uploads, downloads, and security events
- **Rate limiting** - DDoS protection (60 req/min, 1000 req/hour)
- **File size limits** - Configurable upload restrictions

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Modern web browser

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Swapnika2608/ai-enhanced-secure-file-sharing.git
   cd blindsend
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r ai_security/requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   # Create .env file
   JWT_SECRET=your-secure-secret-key
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=blindsend_test
   DB_USER=postgres
   DB_PASSWORD=your-password
   MAX_FILE_SIZE_MB=100
   ```

4. **Initialize database**
   ```bash
   # Visit http://localhost:5000/init-db after starting server
   ```

5. **Launch the application**
   ```bash
   python frontend/api_server_fixed.py
   ```

6. **Access the interface**
   ```
   Open http://localhost:5000 in your browser
   ```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Client    │───▶│  FastAPI Server  │───▶│  AI Security    │
│  (AES-256 GCM)  │    │   (REST API)     │    │    Engine       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Browser Crypto  │    │   PostgreSQL     │    │ Ensemble ML     │
│   Web Crypto    │    │   (8 Tables)     │    │ (IF+SVM+LSTM)   │
│      API        │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Components

- **Frontend**: FastAPI + Uvicorn server with HTML/JS client
- **AI Security Engine**: Ensemble ML models (Isolation Forest, One-Class SVM, LSTM Autoencoder)
- **Encryption Layer**: AES-256-GCM client-side encryption using Web Crypto API
- **Database**: PostgreSQL with 8 tables (users, sessions, links, access_attempts, security_alerts, etc.)
- **Rate Limiting**: Custom middleware for DDoS protection
- **Authentication**: JWT-based token authentication with bcrypt password hashing

## 🔒 Security Model

### Encryption Process
1. **File Selection** → User selects files via drag & drop
2. **Client Encryption** → AES-256-GCM encryption in browser using Web Crypto API
3. **Secure Upload** → Encrypted data sent to server via HTTPS
4. **Link Generation** → UUID-based secure sharing URLs
5. **Key Management** → Encryption key stored client-side only (44-char base64)
6. **AI Monitoring** → Real-time behavioral threat analysis

### AI Security Features
- **Anomaly Detection**: 3 ML algorithms (Isolation Forest, One-Class SVM, LSTM Autoencoder)
- **Feature Engineering**: 15+ behavioral metrics (login patterns, IP diversity, failed attempts, etc.)
- **Risk Scoring**: Multi-factor assessment with confidence levels
- **Automated Responses**: Account suspension, IP blocking, step-up authentication
- **Security Alerts**: Email notifications after 3+ failed access attempts
- **Audit Logging**: Complete access history with IP geolocation

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login (returns JWT token)

### File Operations
- `POST /api/files/upload` - Upload encrypted file (requires JWT)
- `GET /api/files/download/{link_id}` - Download file
- `POST /api/files/revoke/{link_id}` - Revoke file access
- `POST /api/files/report-decrypt-failure/{link_id}` - Report failed decryption

### User Dashboard
- `GET /api/user/activity` - Get user activity with pagination

### AI Security
- `GET /api/ai/status` - AI system status
- `POST /api/ai/initialize` - Initialize/retrain AI models
- `GET /api/ai/security-dashboard` - AI threat analysis dashboard
- `GET /api/ai/threat-analysis/{user_id}` - Detailed user threat analysis

### System
- `GET /health` - Health check
- `GET /init-db` - Initialize database tables

## 🛠️ Development

### Project Structure
```
blindsend/
├── frontend/                    # Web interface & API server
│   ├── static/                  # HTML/JS client files
│   │   ├── index.html          # Main upload interface
│   │   └── download.html       # Download & decrypt page
│   ├── uploads/                # Encrypted file storage
│   ├── api_server_fixed.py     # FastAPI REST API server
│   └── rate_limiter.py         # Rate limiting middleware
├── ai_security/                # AI security engine
│   ├── models/                 # Trained ML models
│   ├── ai_security_engine.py   # Main orchestration engine
│   ├── anomaly_detection.py    # Ensemble ML models (IF, SVM, LSTM)
│   ├── feature_engineering.py  # Behavioral feature extraction
│   ├── risk_scoring.py         # Multi-factor risk assessment
│   ├── automated_responses.py  # Threat response system
│   └── config.py               # Database configuration
├── requirements.txt            # Python dependencies
└── README.md
```

### Database Schema (8 Tables)
- `users` - User accounts and credentials
- `user_sessions` - Active user sessions with device fingerprinting
- `user_links` - File sharing links
- `link_access_controls` - Download limits, expiration, passwords
- `access_attempts` - All download/decrypt attempts (success & failures)
- `security_alerts` - AI-generated security alerts
- `audit_events` - Complete audit trail
- `login_attempts` - Authentication history

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 🔧 Configuration

### Environment Variables
```bash
# Server configuration
PORT=5000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5000

# Security
JWT_SECRET=your-secure-random-secret-key
MAX_FILE_SIZE_MB=100

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=blindsend_test
DB_USER=postgres
DB_PASSWORD=your-password

# Email alerts (Resend API)
RESEND_API_KEY=re_xxxxxxxxxxxxxxxx
```

## 📈 Performance & Limits

- **Max File Size**: 100MB (configurable)
- **Encryption**: AES-256-GCM with Web Crypto API hardware acceleration
- **Rate Limiting**: 60 requests/minute, 1000 requests/hour per IP
- **AI Processing**: Real-time anomaly detection with ensemble voting
- **Database**: PostgreSQL with indexed queries for fast lookups
- **Session Management**: JWT tokens with 24-hour expiration

## 🔬 Technologies Used

### Backend
- **FastAPI** - Modern async web framework
- **Uvicorn** - ASGI server
- **PostgreSQL** - Relational database
- **psycopg3** - PostgreSQL adapter
- **PyJWT** - JWT token handling
- **bcrypt** - Password hashing

### AI/ML Stack
- **scikit-learn** - Isolation Forest, One-Class SVM
- **TensorFlow/Keras** - LSTM Autoencoder
- **pandas** - Data manipulation
- **numpy** - Numerical computing
- **joblib** - Model serialization

### Frontend
- **Web Crypto API** - Client-side encryption
- **Vanilla JavaScript** - No framework dependencies
- **HTML5** - Modern web standards

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**⚡ Built with zero-knowledge security and AI-powered threat detection**
