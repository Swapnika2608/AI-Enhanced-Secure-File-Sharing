# AI Security Engine Configuration
# Update these settings to match your environment

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': '5432',
    'database': 'blindsend_test',
    'user': 'postgres',
    'password': 'Swapnika2608'  # CHANGE THIS to your PostgreSQL password
}

# Email Configuration (Optional - for admin notifications)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'use_tls': True,
    'from_email': 'security@yourcompany.com',
    'admin_email': 'admin@yourcompany.com',
    'username': 'your_email@gmail.com',
    'password': 'your_app_password'
}

# AI Engine Settings
AI_SETTINGS = {
    'monitoring_interval': 300,  # 5 minutes
    'alert_cooldown': 3600,     # 1 hour
    'contamination_rate': 0.1,  # 10% expected anomalies
    'risk_thresholds': {
        'low': 0.3,
        'medium': 0.5,
        'high': 0.7,
        'critical': 0.9
    }
}