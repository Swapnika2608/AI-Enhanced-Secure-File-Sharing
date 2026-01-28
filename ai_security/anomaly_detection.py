"""
Anomaly Detection Module for AI Security Engine
Implements multiple ML algorithms to detect unusual user behavior
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Input, RepeatVector, TimeDistributed
from tensorflow.keras.optimizers import Adam
import joblib
from typing import Dict, List, Tuple, Optional
import json
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

class AnomalyDetector:
    """Multi-algorithm anomaly detection for user behavior analysis"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.thresholds = {}
        self.feature_columns = []
        
    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare features for ML algorithms"""
        
        # Select numerical features for anomaly detection
        feature_cols = [
            'avg_login_hour', 'login_frequency_daily', 'session_duration_avg',
            'weekend_activity_ratio', 'files_accessed_per_session', 'unique_ips_count',
            'geographic_locations_count', 'device_consistency_score', 'failed_login_ratio',
            'suspicious_activity_count', 'risk_score_avg', 'recent_login_count',
            'recent_access_count', 'recent_risk_events'
        ]
        
        # Handle missing values
        df_features = df[feature_cols].fillna(0)
        
        # Store feature columns
        self.feature_columns = feature_cols
        
        return df_features
    
    def train_isolation_forest(self, df: pd.DataFrame, contamination: float = 0.1) -> None:
        """Train Isolation Forest for outlier detection"""
        
        features = self.prepare_features(df)
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(features_scaled)
        
        # Store model and scaler
        self.models['isolation_forest'] = iso_forest
        self.scalers['isolation_forest'] = scaler
        
        print(f"Isolation Forest trained on {len(features)} samples")
    
    def train_one_class_svm(self, df: pd.DataFrame, nu: float = 0.1) -> None:
        """Train One-Class SVM for novelty detection"""
        
        features = self.prepare_features(df)
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train One-Class SVM
        oc_svm = OneClassSVM(nu=nu, kernel='rbf', gamma='scale')
        oc_svm.fit(features_scaled)
        
        # Store model and scaler
        self.models['one_class_svm'] = oc_svm
        self.scalers['one_class_svm'] = scaler
        
        print(f"One-Class SVM trained on {len(features)} samples")
    
    def train_lstm_autoencoder(self, df: pd.DataFrame, sequence_length: int = 7) -> None:
        """Train LSTM Autoencoder for temporal anomaly detection"""
        
        features = self.prepare_features(df)
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Create sequences for LSTM (simulate time series)
        sequences = self._create_sequences(features_scaled, sequence_length)
        
        if len(sequences) < 10:  # Need minimum data for training
            print("Insufficient data for LSTM training")
            return
        
        # Build LSTM Autoencoder
        input_dim = features_scaled.shape[1]
        
        # Encoder
        input_layer = Input(shape=(sequence_length, input_dim))
        encoded = LSTM(32, activation='relu', return_sequences=False)(input_layer)
        
        # Decoder
        decoded = RepeatVector(sequence_length)(encoded)
        decoded = LSTM(32, activation='relu', return_sequences=True)(decoded)
        decoded = TimeDistributed(Dense(input_dim))(decoded)
        
        # Autoencoder model
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(optimizer=Adam(0.001), loss='mse')
        
        # Train autoencoder
        history = autoencoder.fit(
            sequences, sequences,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            verbose=0
        )
        
        # Calculate reconstruction threshold
        reconstructions = autoencoder.predict(sequences)
        mse = np.mean(np.power(sequences - reconstructions, 2), axis=(1, 2))
        threshold = np.percentile(mse, 95)  # 95th percentile as threshold
        
        # Store model, scaler, and threshold
        self.models['lstm_autoencoder'] = autoencoder
        self.scalers['lstm_autoencoder'] = scaler
        self.thresholds['lstm_autoencoder'] = threshold
        
        print(f"LSTM Autoencoder trained on {len(sequences)} sequences")
    
    def _create_sequences(self, data: np.ndarray, sequence_length: int) -> np.ndarray:
        """Create sequences for LSTM training"""
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data[i:i + sequence_length])
        return np.array(sequences)
    
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect anomalies using all trained models"""
        
        features = self.prepare_features(df)
        results = df.copy()
        
        # Isolation Forest predictions
        if 'isolation_forest' in self.models:
            features_scaled = self.scalers['isolation_forest'].transform(features)
            iso_predictions = self.models['isolation_forest'].predict(features_scaled)
            iso_scores = self.models['isolation_forest'].decision_function(features_scaled)
            
            results['iso_forest_anomaly'] = (iso_predictions == -1).astype(int)
            results['iso_forest_score'] = iso_scores
        
        # One-Class SVM predictions
        if 'one_class_svm' in self.models:
            features_scaled = self.scalers['one_class_svm'].transform(features)
            svm_predictions = self.models['one_class_svm'].predict(features_scaled)
            svm_scores = self.models['one_class_svm'].decision_function(features_scaled)
            
            results['svm_anomaly'] = (svm_predictions == -1).astype(int)
            results['svm_score'] = svm_scores
        
        # LSTM Autoencoder predictions
        if 'lstm_autoencoder' in self.models:
            features_scaled = self.scalers['lstm_autoencoder'].transform(features)
            
            # For single predictions, repeat the pattern
            sequences = np.tile(features_scaled, (7, 1, 1)).transpose(1, 0, 2)
            
            reconstructions = self.models['lstm_autoencoder'].predict(sequences)
            mse = np.mean(np.power(sequences - reconstructions, 2), axis=(1, 2))
            
            threshold = self.thresholds['lstm_autoencoder']
            results['lstm_anomaly'] = (mse > threshold).astype(int)
            results['lstm_score'] = mse
        
        # Ensemble anomaly score
        anomaly_cols = [col for col in results.columns if col.endswith('_anomaly')]
        if anomaly_cols:
            results['ensemble_anomaly_score'] = results[anomaly_cols].mean(axis=1)
            results['is_anomaly'] = (results['ensemble_anomaly_score'] > 0.5).astype(int)
        
        return results
    
    def save_models(self, filepath: str) -> None:
        """Save trained models to disk"""
        model_data = {
            'models': {},
            'scalers': self.scalers,
            'thresholds': self.thresholds,
            'feature_columns': self.feature_columns
        }
        
        # Save sklearn models
        for name, model in self.models.items():
            if name != 'lstm_autoencoder':
                model_data['models'][name] = model
        
        # Save sklearn models and scalers
        joblib.dump(model_data, f"{filepath}_sklearn.pkl")
        
        # Save LSTM model separately
        if 'lstm_autoencoder' in self.models:
            self.models['lstm_autoencoder'].save(f"{filepath}_lstm.h5")
        
        print(f"Models saved to {filepath}")
    
    def load_models(self, filepath: str) -> None:
        """Load trained models from disk"""
        
        # Load sklearn models
        model_data = joblib.load(f"{filepath}_sklearn.pkl")
        self.models.update(model_data['models'])
        self.scalers = model_data['scalers']
        self.thresholds = model_data['thresholds']
        self.feature_columns = model_data['feature_columns']
        
        # Load LSTM model
        try:
            from tensorflow.keras.models import load_model
            self.models['lstm_autoencoder'] = load_model(f"{filepath}_lstm.h5")
        except:
            print("LSTM model not found or failed to load")
        
        print(f"Models loaded from {filepath}")

class RealTimeAnomalyDetector:
    """Real-time anomaly detection for live monitoring"""
    
    def __init__(self, anomaly_detector: AnomalyDetector):
        self.detector = anomaly_detector
        self.alert_thresholds = {
            'high_risk': 0.8,
            'medium_risk': 0.6,
            'low_risk': 0.4
        }
    
    def analyze_user_session(self, user_features: Dict) -> Dict:
        """Analyze a single user session for anomalies"""
        
        # Convert to DataFrame
        df = pd.DataFrame([user_features])
        
        # Detect anomalies
        results = self.detector.detect_anomalies(df)
        
        # Calculate risk level
        anomaly_score = results['ensemble_anomaly_score'].iloc[0] if 'ensemble_anomaly_score' in results.columns else 0
        
        risk_level = 'low'
        if anomaly_score >= self.alert_thresholds['high_risk']:
            risk_level = 'high'
        elif anomaly_score >= self.alert_thresholds['medium_risk']:
            risk_level = 'medium'
        
        return {
            'user_id': user_features.get('user_id'),
            'anomaly_score': float(anomaly_score),
            'risk_level': risk_level,
            'is_anomaly': bool(results['is_anomaly'].iloc[0]) if 'is_anomaly' in results.columns else False,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'isolation_forest': float(results.get('iso_forest_score', [0]).iloc[0]) if 'iso_forest_score' in results.columns else None,
                'one_class_svm': float(results.get('svm_score', [0]).iloc[0]) if 'svm_score' in results.columns else None,
                'lstm_autoencoder': float(results.get('lstm_score', [0]).iloc[0]) if 'lstm_score' in results.columns else None
            }
        }
    
    def generate_alert(self, analysis_result: Dict) -> Optional[Dict]:
        """Generate security alert if anomaly detected"""
        
        if analysis_result['risk_level'] in ['medium', 'high']:
            return {
                'alert_id': f"ALERT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{analysis_result['user_id']}",
                'user_id': analysis_result['user_id'],
                'risk_level': analysis_result['risk_level'],
                'anomaly_score': analysis_result['anomaly_score'],
                'timestamp': analysis_result['timestamp'],
                'message': f"Anomalous behavior detected for user {analysis_result['user_id']} with {analysis_result['risk_level']} risk level",
                'recommended_actions': self._get_recommended_actions(analysis_result['risk_level']),
                'details': analysis_result['details']
            }
        
        return None
    
    def _get_recommended_actions(self, risk_level: str) -> List[str]:
        """Get recommended security actions based on risk level"""
        
        actions = {
            'high': [
                'Immediately suspend user account',
                'Require step-up authentication',
                'Block access from current IP',
                'Notify security team',
                'Review recent file access history'
            ],
            'medium': [
                'Require additional authentication',
                'Monitor user activity closely',
                'Log detailed access attempts',
                'Consider temporary access restrictions'
            ],
            'low': [
                'Log event for review',
                'Monitor for pattern changes',
                'Update user behavior baseline'
            ]
        }
        
        return actions.get(risk_level, [])

# Example usage
if __name__ == "__main__":
    # Load user behavioral features
    try:
        features_df = pd.read_csv('user_behavioral_features.csv')
        print(f"Loaded features for {len(features_df)} users")
        
        # Initialize anomaly detector
        detector = AnomalyDetector()
        
        # Train multiple models
        print("Training anomaly detection models...")
        detector.train_isolation_forest(features_df, contamination=0.1)
        detector.train_one_class_svm(features_df, nu=0.1)
        detector.train_lstm_autoencoder(features_df, sequence_length=7)
        
        # Detect anomalies
        print("Detecting anomalies...")
        results = detector.detect_anomalies(features_df)
        
        # Show anomaly summary
        anomaly_count = results['is_anomaly'].sum() if 'is_anomaly' in results.columns else 0
        print(f"\nDetected {anomaly_count} anomalous users out of {len(results)}")
        
        if anomaly_count > 0:
            print("\nAnomalous users:")
            anomalous_users = results[results['is_anomaly'] == 1][['user_id', 'email', 'ensemble_anomaly_score']]
            print(anomalous_users)
        
        # Save models
        detector.save_models('anomaly_models')
        
        # Save results
        results.to_csv('anomaly_detection_results.csv', index=False)
        print("\nResults saved to anomaly_detection_results.csv")
        
    except FileNotFoundError:
        print("Please run feature_engineering.py first to generate user_behavioral_features.csv")