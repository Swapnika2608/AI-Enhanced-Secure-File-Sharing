# AI-ENHANCED SECURE FILE ENCRYPTION AND SHARING SYSTEM

> **Next-generation secure file sharing with AI-powered threat detection**

BlindSend AI combines military-grade encryption with intelligent security monitoring to provide the most secure file sharing experience available.

## ✨ Key Features

### 🔐 **Zero-Knowledge Security**
- **End-to-end encryption** - Files encrypted before leaving your device
- **Client-side processing** - Server never sees your data
- **Secure link generation** - Cryptographically secure sharing URLs

### 🤖 **AI-Powered Protection**
- **Real-time anomaly detection** - ML models monitor for threats
- **Behavioral analysis** - Detects suspicious upload patterns
- **Risk scoring** - Automated threat assessment
- **Smart alerts** - Intelligent notification system

### 🚀 **User Experience**
- **Drag & drop interface** - Intuitive file uploads
- **Instant sharing** - Generate secure links immediately
- **Cross-platform** - Works on any device with a browser
- **No registration** - Start sharing files instantly

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Modern web browser

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Swapnika2608/ai-enhanced-secure-file-sharing.git
   cd blindsend
   ```

2. **Install dependencies**
   ```bash
   pip install -r frontend/requirements.txt
   pip install -r ai_security/requirements.txt
   ```

3. **Launch the application**
   ```bash
   python frontend/api_server_fixed.py
   ```

4. **Access the interface**
   ```
   Open http://localhost:5000 in your browser
   ```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Client    │───▶│   Flask Server   │───▶│  AI Security    │
│  (Encryption)   │    │   (API Layer)    │    │    Engine       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Client Storage  │    │ Encrypted Files  │    │ ML Models &     │
│   (Browser)     │    │   (Local Disk)   │    │  Analytics      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Components

- **Frontend**: Flask-based web server with HTML/JS client
- **AI Security Engine**: Machine learning threat detection system
- **Encryption Layer**: AES-256 client-side encryption
- **Storage**: Local encrypted file storage with secure cleanup

## 🔒 Security Model

### Encryption Process
1. **File Selection** → User selects files via drag & drop
2. **Client Encryption** → AES-256 encryption in browser
3. **Secure Upload** → Encrypted data sent to server
4. **Link Generation** → Cryptographically secure sharing URL
5. **AI Monitoring** → Real-time threat analysis

### AI Security Features
- **Anomaly Detection**: Identifies unusual file patterns
- **Behavioral Analysis**: Monitors user interaction patterns
- **Risk Assessment**: Automated threat scoring (0-100)
- **Response System**: Automatic threat mitigation

## 📊 Usage Examples

### Basic File Sharing
```bash
# Start the server
python frontend/api_server_fixed.py

# Upload files via web interface
# Share generated secure links
```

### API Integration
```python
import requests

# Upload encrypted file
response = requests.post('http://localhost:5000/upload', 
                        files={'file': encrypted_file_data})
share_link = response.json()['download_url']
```

## 🛠️ Development

### Project Structure
```
blindsend/
├── frontend/           # Web interface & API server
│   ├── static/         # HTML templates
│   ├── uploads/        # Encrypted file storage
│   └── api_server_fixed.py
├── ai_security/        # AI security engine
│   ├── models/         # ML model storage
│   ├── ai_security_engine.py
│   └── anomaly_detection.py
└── README.md
```

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
FLASK_HOST=localhost
FLASK_PORT=5000
FLASK_DEBUG=False

# AI Security settings
AI_MONITORING_ENABLED=True
RISK_THRESHOLD=75
ALERT_NOTIFICATIONS=True
```

## 📈 Performance

- **Upload Speed**: Up to 100MB/s (local network)
- **Encryption**: AES-256 hardware acceleration
- **AI Processing**: <100ms threat analysis
- **Storage**: Automatic cleanup after 7 days


## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**⚡ Built with security and privacy in mind**