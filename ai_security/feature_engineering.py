"""
Feature Engineering Module for AI Security Engine
Extracts behavioral patterns from Phase 1 audit data for ML analysis
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import psycopg
from typing import Dict, List, Tuple, Optional
import json
from dataclasses import dataclass
from sklearn.preprocessing import StandardScaler, LabelEncoder
import hashlib

@dataclass
class UserBehaviorFeatures:
    """User behavior feature set for ML analysis"""
    user_id: int
    email: str
    
    # Temporal patterns
    avg_login_hour: float
    login_frequency_daily: float
    session_duration_avg: float
    weekend_activity_ratio: float
    
    # Access patterns  
    files_accessed_per_session: float
    unique_ips_count: int
    geographic_locations_count: int
    device_consistency_score: float
    
    # Security indicators
    failed_login_ratio: float
    suspicious_activity_count: int
    risk_score_avg: float
    
    # Recent activity (last 7 days)
    recent_login_count: int
    recent_access_count: int
    recent_risk_events: int

class FeatureEngineer:
    """Extracts ML features from PostgreSQL audit data"""
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
    
    def connect_db(self):
        """Connect to PostgreSQL database"""
        db_config = self.db_config.copy()
        # psycopg3 uses 'dbname', handle both 'database' and 'dbname'
        if 'database' in db_config:
            db_config['dbname'] = db_config.pop('database')
        return psycopg.connect(**db_config)
    
    def extract_user_features(self, user_id: int, days_back: int = 30) -> UserBehaviorFeatures:
        """Extract comprehensive behavioral features for a user"""
        
        with self.connect_db() as conn:
            # Get user basic info
            user_info = self._get_user_info(conn, user_id)
            
            # Extract temporal patterns
            temporal_features = self._extract_temporal_patterns(conn, user_id, days_back)
            
            # Extract access patterns
            access_features = self._extract_access_patterns(conn, user_id, days_back)
            
            # Extract security indicators
            security_features = self._extract_security_indicators(conn, user_id, days_back)
            
            # Extract recent activity
            recent_features = self._extract_recent_activity(conn, user_id, 7)
            
            return UserBehaviorFeatures(
                user_id=user_id,
                email=user_info['email'],
                **temporal_features,
                **access_features,
                **security_features,
                **recent_features
            )
    
    def _get_user_info(self, conn, user_id: int) -> Dict:
        """Get basic user information"""
        query = "SELECT email FROM users WHERE id = %s"
        df = pd.read_sql(query, conn, params=[user_id])
        return df.iloc[0].to_dict() if not df.empty else {'email': 'unknown'}
    
    def _extract_temporal_patterns(self, conn, user_id: int, days_back: int) -> Dict:
        """Extract time-based behavioral patterns"""
        
        # Login time patterns
        login_query = """
        SELECT EXTRACT(HOUR FROM timestamp) as hour,
               EXTRACT(DOW FROM timestamp) as day_of_week,
               timestamp
        FROM login_attempts 
        WHERE email = (SELECT email FROM users WHERE id = %s)
          AND success = true 
          AND timestamp > NOW() - INTERVAL '%s days'
        """
        
        login_df = pd.read_sql(login_query, conn, params=[user_id, days_back])
        
        if login_df.empty:
            return {
                'avg_login_hour': 12.0,
                'login_frequency_daily': 0.0,
                'session_duration_avg': 0.0,
                'weekend_activity_ratio': 0.0
            }
        
        # Session duration patterns
        session_query = """
        SELECT created_at, last_activity,
               EXTRACT(EPOCH FROM (last_activity - created_at))/3600 as duration_hours
        FROM user_sessions 
        WHERE user_id = %s 
          AND created_at > NOW() - INTERVAL '%s days'
        """
        
        session_df = pd.read_sql(session_query, conn, params=[user_id, days_back])
        
        return {
            'avg_login_hour': float(login_df['hour'].mean()) if not login_df.empty else 12.0,
            'login_frequency_daily': len(login_df) / max(days_back, 1),
            'session_duration_avg': float(session_df['duration_hours'].mean()) if not session_df.empty else 0.0,
            'weekend_activity_ratio': len(login_df[login_df['day_of_week'].isin([0, 6])]) / max(len(login_df), 1)
        }
    
    def _extract_access_patterns(self, conn, user_id: int, days_back: int) -> Dict:
        """Extract file access behavioral patterns"""
        
        # Access attempts for user's links
        access_query = """
        SELECT aa.ip_address, aa.timestamp, aa.access_type,
               ul.link_id
        FROM access_attempts aa
        JOIN user_links ul ON aa.link_id = ul.link_id
        WHERE ul.user_id = %s 
          AND aa.timestamp > NOW() - INTERVAL '%s days'
        """
        
        access_df = pd.read_sql(access_query, conn, params=[user_id, days_back])
        
        if access_df.empty:
            return {
                'files_accessed_per_session': 0.0,
                'unique_ips_count': 0,
                'geographic_locations_count': 0,
                'device_consistency_score': 1.0
            }
        
        # Device fingerprinting from user sessions
        device_query = """
        SELECT user_agent, device_fingerprint
        FROM user_sessions 
        WHERE user_id = %s 
          AND created_at > NOW() - INTERVAL '%s days'
        """
        
        device_df = pd.read_sql(device_query, conn, params=[user_id, days_back])
        
        unique_ips = access_df['ip_address'].nunique()
        unique_locations = unique_ips  # Use unique IPs as location proxy
        
        # Device consistency score (higher = more consistent)
        device_consistency = 1.0
        if not device_df.empty:
            unique_devices = device_df['device_fingerprint'].nunique()
            device_consistency = 1.0 / max(unique_devices, 1)
        
        return {
            'files_accessed_per_session': len(access_df) / max(len(device_df), 1),
            'unique_ips_count': unique_ips,
            'geographic_locations_count': unique_locations,
            'device_consistency_score': device_consistency
        }
    
    def _extract_security_indicators(self, conn, user_id: int, days_back: int) -> Dict:
        """Extract security-related behavioral indicators"""
        
        # Failed login ratio
        login_query = """
        SELECT success, COUNT(*) as count
        FROM login_attempts 
        WHERE email = (SELECT email FROM users WHERE id = %s)
          AND timestamp > NOW() - INTERVAL '%s days'
        GROUP BY success
        """
        
        login_df = pd.read_sql(login_query, conn, params=[user_id, days_back])
        
        failed_logins = login_df[login_df['success'] == False]['count'].sum() if not login_df.empty else 0
        total_logins = login_df['count'].sum() if not login_df.empty else 1
        failed_ratio = failed_logins / max(total_logins, 1)
        
        # Risk score analysis
        risk_query = """
        SELECT aa.risk_score, ae.event_type
        FROM access_attempts aa
        JOIN user_links ul ON aa.link_id = ul.link_id
        LEFT JOIN audit_events ae ON ae.link_id = aa.link_id 
            AND ae.event_type = 'suspicious_activity'
        WHERE ul.user_id = %s 
          AND aa.timestamp > NOW() - INTERVAL '%s days'
        """
        
        risk_df = pd.read_sql(risk_query, conn, params=[user_id, days_back])
        
        avg_risk_score = risk_df['risk_score'].mean() if not risk_df.empty else 0.0
        suspicious_count = len(risk_df[risk_df['event_type'] == 'suspicious_activity'])
        
        return {
            'failed_login_ratio': failed_ratio,
            'suspicious_activity_count': suspicious_count,
            'risk_score_avg': float(avg_risk_score) if not pd.isna(avg_risk_score) else 0.0
        }
    
    def _extract_recent_activity(self, conn, user_id: int, days_back: int) -> Dict:
        """Extract recent activity indicators"""
        
        # Recent login count
        recent_logins_query = """
        SELECT COUNT(*) as count
        FROM login_attempts 
        WHERE email = (SELECT email FROM users WHERE id = %s)
          AND success = true
          AND timestamp > NOW() - INTERVAL '%s days'
        """
        
        recent_logins = pd.read_sql(recent_logins_query, conn, params=[user_id, days_back])
        
        # Recent access count
        recent_access_query = """
        SELECT COUNT(*) as count
        FROM access_attempts aa
        JOIN user_links ul ON aa.link_id = ul.link_id
        WHERE ul.user_id = %s 
          AND aa.timestamp > NOW() - INTERVAL '%s days'
        """
        
        recent_access = pd.read_sql(recent_access_query, conn, params=[user_id, days_back])
        
        # Recent high-risk events
        recent_risk_query = """
        SELECT COUNT(*) as count
        FROM access_attempts aa
        JOIN user_links ul ON aa.link_id = ul.link_id
        WHERE ul.user_id = %s 
          AND aa.risk_score > 0.7
          AND aa.timestamp > NOW() - INTERVAL '%s days'
        """
        
        recent_risk = pd.read_sql(recent_risk_query, conn, params=[user_id, days_back])
        
        return {
            'recent_login_count': int(recent_logins.iloc[0]['count']),
            'recent_access_count': int(recent_access.iloc[0]['count']),
            'recent_risk_events': int(recent_risk.iloc[0]['count'])
        }
    
    def create_device_fingerprint(self, user_agent: str, ip_address: str, 
                                 additional_data: Dict = None) -> str:
        """Create device fingerprint for tracking"""
        
        fingerprint_data = {
            'user_agent': user_agent,
            'ip_class': '.'.join(ip_address.split('.')[:3]) + '.x',  # IP class for privacy
        }
        
        if additional_data:
            fingerprint_data.update(additional_data)
        
        # Create hash of combined data
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
    
    def extract_all_users_features(self, days_back: int = 30) -> pd.DataFrame:
        """Extract features for all users in the system"""
        
        with self.connect_db() as conn:
            # Get all user IDs
            users_query = "SELECT id FROM users WHERE is_active = true"
            users_df = pd.read_sql(users_query, conn)
            
            features_list = []
            for user_id in users_df['id']:
                try:
                    features = self.extract_user_features(user_id, days_back)
                    features_dict = {
                        'user_id': features.user_id,
                        'email': features.email,
                        'avg_login_hour': features.avg_login_hour,
                        'login_frequency_daily': features.login_frequency_daily,
                        'session_duration_avg': features.session_duration_avg,
                        'weekend_activity_ratio': features.weekend_activity_ratio,
                        'files_accessed_per_session': features.files_accessed_per_session,
                        'unique_ips_count': features.unique_ips_count,
                        'geographic_locations_count': features.geographic_locations_count,
                        'device_consistency_score': features.device_consistency_score,
                        'failed_login_ratio': features.failed_login_ratio,
                        'suspicious_activity_count': features.suspicious_activity_count,
                        'risk_score_avg': features.risk_score_avg,
                        'recent_login_count': features.recent_login_count,
                        'recent_access_count': features.recent_access_count,
                        'recent_risk_events': features.recent_risk_events
                    }
                    features_list.append(features_dict)
                except Exception as e:
                    print(f"Error extracting features for user {user_id}: {e}")
                    continue
            
            return pd.DataFrame(features_list)

# Example usage and configuration
if __name__ == "__main__":
    # Database configuration
    db_config = {
        'host': 'localhost',
        'port': '5432',
        'database': 'blindsend_test',
        'user': 'postgres',
        'password': 'your_actual_password_here'  # Replace with your PostgreSQL password
    }
    
    # Initialize feature engineer
    feature_engineer = FeatureEngineer(db_config)
    
    # Extract features for all users
    print("Extracting behavioral features for all users...")
    features_df = feature_engineer.extract_all_users_features(days_back=30)
    
    print(f"Extracted features for {len(features_df)} users")
    print("\nFeature summary:")
    print(features_df.describe())
    
    # Save features for ML training
    features_df.to_csv('user_behavioral_features.csv', index=False)
    print("\nFeatures saved to user_behavioral_features.csv")