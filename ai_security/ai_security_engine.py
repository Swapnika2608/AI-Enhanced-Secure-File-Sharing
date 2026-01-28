"""
Main AI Security Engine
Orchestrates all AI security components for real-time threat detection and response
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from feature_engineering import FeatureEngineer
from anomaly_detection import AnomalyDetector, RealTimeAnomalyDetector
from risk_scoring import RiskScorer, RiskLevel
from automated_responses import AutomatedResponseSystem

class AISecurityEngine:
    """Main AI Security Engine that coordinates all security components"""
    
    def __init__(self, db_config: Dict[str, str], email_config: Dict[str, str] = None):
        self.db_config = db_config
        self.email_config = email_config
        
        # Initialize components
        self.feature_engineer = FeatureEngineer(db_config)
        self.anomaly_detector = AnomalyDetector()
        self.risk_scorer = RiskScorer()
        self.response_system = AutomatedResponseSystem(db_config, email_config)
        self.realtime_detector = None
        
        # Engine state
        self.is_running = False
        self.models_trained = False
        self.monitoring_thread = None
        
        # Configuration
        self.monitoring_interval = 300  # 5 minutes
        self.batch_size = 100
        self.alert_cooldown = 3600  # 1 hour cooldown between alerts for same user
        
        # Alert tracking
        self.recent_alerts = {}
        
    def initialize_system(self, retrain_models: bool = True) -> bool:
        """Initialize the AI security system"""
        
        print("🚀 Initializing AI Security Engine...")
        
        try:
            # Step 1: Extract features for all users
            print("📊 Extracting user behavioral features...")
            features_df = self.feature_engineer.extract_all_users_features(days_back=30)
            
            if len(features_df) == 0:
                print("❌ No user data found. Please ensure Phase 1 data exists.")
                return False
            
            print(f"✅ Extracted features for {len(features_df)} users")
            
            # Step 2: Train anomaly detection models
            if retrain_models:
                print("🧠 Training anomaly detection models...")
                
                self.anomaly_detector.train_isolation_forest(features_df, contamination=0.1)
                self.anomaly_detector.train_one_class_svm(features_df, nu=0.1)
                
                # Only train LSTM if we have enough data
                if len(features_df) >= 10:
                    self.anomaly_detector.train_lstm_autoencoder(features_df, sequence_length=7)
                else:
                    print("⚠️  Insufficient data for LSTM training, skipping...")
                
                # Save trained models
                self.anomaly_detector.save_models('models/anomaly_models')
                print("✅ Models trained and saved")
            else:
                # Load existing models
                print("📂 Loading existing models...")
                try:
                    self.anomaly_detector.load_models('models/anomaly_models')
                    print("✅ Models loaded successfully")
                except:
                    print("❌ Failed to load models, training new ones...")
                    return self.initialize_system(retrain_models=True)
            
            # Step 3: Initialize real-time detector
            self.realtime_detector = RealTimeAnomalyDetector(self.anomaly_detector)
            
            # Step 4: Run initial threat assessment
            print("🔍 Running initial threat assessment...")
            initial_threats = self.assess_all_users()
            
            high_risk_users = len([t for t in initial_threats if t['risk_level'] in ['high', 'critical']])
            print(f"⚠️  Found {high_risk_users} high-risk users")
            
            self.models_trained = True
            print("✅ AI Security Engine initialized successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Failed to initialize AI Security Engine: {e}")
            return False
    
    def start_monitoring(self):
        """Start real-time security monitoring"""
        
        if not self.models_trained:
            print("❌ Models not trained. Please run initialize_system() first.")
            return False
        
        if self.is_running:
            print("⚠️  Monitoring already running")
            return True
        
        print("🔄 Starting real-time security monitoring...")
        self.is_running = True
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        print(f"✅ Real-time monitoring started (interval: {self.monitoring_interval}s)")
        return True
    
    def stop_monitoring(self):
        """Stop real-time security monitoring"""
        
        if not self.is_running:
            print("⚠️  Monitoring not running")
            return
        
        print("🛑 Stopping real-time security monitoring...")
        self.is_running = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        print("✅ Monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs continuously"""
        
        while self.is_running:
            try:
                # Assess all users for threats
                threats = self.assess_all_users()
                
                # Process high-risk threats
                high_risk_threats = [t for t in threats if t['risk_level'] in ['high', 'critical']]
                
                if high_risk_threats:
                    print(f"🚨 Detected {len(high_risk_threats)} high-risk threats")
                    
                    # Process threats in parallel
                    with ThreadPoolExecutor(max_workers=5) as executor:
                        futures = [executor.submit(self._process_threat, threat) for threat in high_risk_threats]
                        
                        for future in futures:
                            try:
                                future.result(timeout=30)
                            except Exception as e:
                                print(f"Error processing threat: {e}")
                
                # Clean up old alerts
                self._cleanup_old_alerts()
                
                # Wait for next monitoring cycle
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def assess_all_users(self) -> List[Dict]:
        """Assess threat level for all active users"""
        
        try:
            # Extract current features for all users
            features_df = self.feature_engineer.extract_all_users_features(days_back=7)
            
            if len(features_df) == 0:
                return []
            
            # Detect anomalies
            anomaly_results = self.anomaly_detector.detect_anomalies(features_df)
            
            threats = []
            
            for _, row in anomaly_results.iterrows():
                # Prepare user features
                user_features = row.to_dict()
                
                # Prepare anomaly scores
                anomaly_scores = {
                    'ensemble_anomaly_score': row.get('ensemble_anomaly_score', 0),
                    'iso_forest_score': row.get('iso_forest_score', 0),
                    'svm_score': row.get('svm_score', 0),
                    'lstm_score': row.get('lstm_score', 0)
                }
                
                # Calculate risk score
                risk_assessment = self.risk_scorer.calculate_risk_score(
                    user_features=user_features,
                    anomaly_scores=anomaly_scores
                )
                
                # Convert to dict for easier handling
                threat_info = {
                    'user_id': risk_assessment.user_id,
                    'overall_score': risk_assessment.overall_score,
                    'risk_level': risk_assessment.risk_level.value,
                    'confidence': risk_assessment.confidence,
                    'timestamp': risk_assessment.timestamp.isoformat(),
                    'factors': [
                        {
                            'name': factor.name,
                            'score': factor.score,
                            'weight': factor.weight,
                            'description': factor.description,
                            'evidence': factor.evidence
                        }
                        for factor in risk_assessment.factors
                    ],
                    'recommendations': risk_assessment.recommendations,
                    'anomaly_scores': anomaly_scores
                }
                
                threats.append(threat_info)
            
            return threats
            
        except Exception as e:
            print(f"Error assessing users: {e}")
            return []
    
    def assess_single_user(self, user_id: int, context: Dict = None) -> Optional[Dict]:
        """Assess threat level for a single user"""
        
        try:
            # Extract features for specific user
            user_features = self.feature_engineer.extract_user_features(user_id, days_back=7)
            
            # Convert to dict
            features_dict = {
                'user_id': user_features.user_id,
                'email': user_features.email,
                'avg_login_hour': user_features.avg_login_hour,
                'login_frequency_daily': user_features.login_frequency_daily,
                'session_duration_avg': user_features.session_duration_avg,
                'weekend_activity_ratio': user_features.weekend_activity_ratio,
                'files_accessed_per_session': user_features.files_accessed_per_session,
                'unique_ips_count': user_features.unique_ips_count,
                'geographic_locations_count': user_features.geographic_locations_count,
                'device_consistency_score': user_features.device_consistency_score,
                'failed_login_ratio': user_features.failed_login_ratio,
                'suspicious_activity_count': user_features.suspicious_activity_count,
                'risk_score_avg': user_features.risk_score_avg,
                'recent_login_count': user_features.recent_login_count,
                'recent_access_count': user_features.recent_access_count,
                'recent_risk_events': user_features.recent_risk_events
            }
            
            # Detect anomalies for single user
            df = pd.DataFrame([features_dict])
            anomaly_results = self.anomaly_detector.detect_anomalies(df)
            
            # Get anomaly scores
            anomaly_scores = {
                'ensemble_anomaly_score': anomaly_results.get('ensemble_anomaly_score', [0]).iloc[0],
                'iso_forest_score': anomaly_results.get('iso_forest_score', [0]).iloc[0],
                'svm_score': anomaly_results.get('svm_score', [0]).iloc[0],
                'lstm_score': anomaly_results.get('lstm_score', [0]).iloc[0]
            }
            
            # Calculate risk score
            risk_assessment = self.risk_scorer.calculate_risk_score(
                user_features=features_dict,
                anomaly_scores=anomaly_scores,
                context=context
            )
            
            # Convert to dict
            return {
                'user_id': risk_assessment.user_id,
                'overall_score': risk_assessment.overall_score,
                'risk_level': risk_assessment.risk_level.value,
                'confidence': risk_assessment.confidence,
                'timestamp': risk_assessment.timestamp.isoformat(),
                'factors': [
                    {
                        'name': factor.name,
                        'score': factor.score,
                        'weight': factor.weight,
                        'description': factor.description,
                        'evidence': factor.evidence
                    }
                    for factor in risk_assessment.factors
                ],
                'recommendations': risk_assessment.recommendations,
                'anomaly_scores': anomaly_scores
            }
            
        except Exception as e:
            print(f"Error assessing user {user_id}: {e}")
            return None
    
    def _process_threat(self, threat_info: Dict):
        """Process a detected threat and execute appropriate responses"""
        
        user_id = threat_info['user_id']
        
        # Check alert cooldown
        if self._is_in_cooldown(user_id):
            return
        
        # Generate and execute responses
        responses = self.response_system.process_threat_detection(threat_info)
        executed_responses = self.response_system.execute_responses(responses)
        
        # Track alert
        self.recent_alerts[user_id] = datetime.now()
        
        # Log threat processing
        successful_responses = len([r for r in executed_responses if r.executed])
        print(f"🔒 Processed threat for user {user_id}: {successful_responses}/{len(executed_responses)} responses executed")
    
    def _is_in_cooldown(self, user_id: int) -> bool:
        """Check if user is in alert cooldown period"""
        
        if user_id not in self.recent_alerts:
            return False
        
        last_alert = self.recent_alerts[user_id]
        cooldown_expires = last_alert + timedelta(seconds=self.alert_cooldown)
        
        return datetime.now() < cooldown_expires
    
    def _cleanup_old_alerts(self):
        """Clean up old alert tracking data"""
        
        cutoff_time = datetime.now() - timedelta(seconds=self.alert_cooldown * 2)
        
        # Remove old alerts
        old_alerts = [user_id for user_id, timestamp in self.recent_alerts.items() 
                     if timestamp < cutoff_time]
        
        for user_id in old_alerts:
            del self.recent_alerts[user_id]
    
    def get_system_status(self) -> Dict:
        """Get current system status and statistics"""
        
        return {
            'is_running': self.is_running,
            'models_trained': self.models_trained,
            'monitoring_interval': self.monitoring_interval,
            'active_alerts': len(self.recent_alerts),
            'last_assessment': datetime.now().isoformat(),
            'components': {
                'feature_engineer': 'active',
                'anomaly_detector': 'active' if self.models_trained else 'inactive',
                'risk_scorer': 'active',
                'response_system': 'active',
                'realtime_detector': 'active' if self.realtime_detector else 'inactive'
            }
        }
    
    def generate_security_report(self, hours_back: int = 24) -> Dict:
        """Generate comprehensive security report"""
        
        try:
            # Get recent threats
            threats = self.assess_all_users()
            
            # Categorize by risk level
            risk_distribution = {}
            for level in ['very_low', 'low', 'medium', 'high', 'critical']:
                risk_distribution[level] = len([t for t in threats if t['risk_level'] == level])
            
            # Get top risk factors
            all_factors = []
            for threat in threats:
                all_factors.extend(threat['factors'])
            
            factor_scores = {}
            for factor in all_factors:
                name = factor['name']
                if name not in factor_scores:
                    factor_scores[name] = []
                factor_scores[name].append(factor['score'])
            
            avg_factor_scores = {name: np.mean(scores) for name, scores in factor_scores.items()}
            top_factors = sorted(avg_factor_scores.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                'report_timestamp': datetime.now().isoformat(),
                'assessment_period_hours': hours_back,
                'total_users_assessed': len(threats),
                'risk_distribution': risk_distribution,
                'high_risk_users': [t['user_id'] for t in threats if t['risk_level'] in ['high', 'critical']],
                'top_risk_factors': [{'factor': name, 'avg_score': score} for name, score in top_factors],
                'system_status': self.get_system_status(),
                'recommendations': self._generate_system_recommendations(threats)
            }
            
        except Exception as e:
            return {
                'error': f"Failed to generate report: {e}",
                'report_timestamp': datetime.now().isoformat()
            }
    
    def _generate_system_recommendations(self, threats: List[Dict]) -> List[str]:
        """Generate system-level security recommendations"""
        
        recommendations = []
        
        high_risk_count = len([t for t in threats if t['risk_level'] in ['high', 'critical']])
        total_count = len(threats)
        
        if high_risk_count > total_count * 0.1:  # More than 10% high risk
            recommendations.append("High percentage of risky users detected - consider system-wide security review")
        
        if high_risk_count > 5:
            recommendations.append("Multiple high-risk users detected - increase monitoring frequency")
        
        # Analyze common risk factors
        common_factors = {}
        for threat in threats:
            for factor in threat['factors']:
                if factor['score'] > 0.5:
                    name = factor['name']
                    common_factors[name] = common_factors.get(name, 0) + 1
        
        if common_factors:
            top_factor = max(common_factors.items(), key=lambda x: x[1])
            recommendations.append(f"Most common risk factor: {top_factor[0]} - consider targeted mitigation")
        
        return recommendations

# Example usage and testing
if __name__ == "__main__":
    # Database configuration
    db_config = {
        'host': 'localhost',
        'port': '5432',
        'database': 'blindsend_test',
        'user': 'postgres',
        'password': 'Swapnika2608'  # Replace with your PostgreSQL password
    }
    
    # Initialize AI Security Engine
    ai_engine = AISecurityEngine(db_config)
    
    # Initialize the system
    if ai_engine.initialize_system(retrain_models=True):
        print("\n" + "="*50)
        print("🛡️  AI SECURITY ENGINE READY")
        print("="*50)
        
        # Generate initial security report
        report = ai_engine.generate_security_report()
        print(f"\n📊 Security Report:")
        print(f"Total Users: {report['total_users_assessed']}")
        print(f"Risk Distribution: {report['risk_distribution']}")
        print(f"High Risk Users: {report['high_risk_users']}")
        
        # Start monitoring (uncomment for continuous monitoring)
        # ai_engine.start_monitoring()
        
        print("\n✅ AI Security Engine is operational!")
        print("Use ai_engine.start_monitoring() to begin real-time threat detection")
    else:
        print("❌ Failed to initialize AI Security Engine")