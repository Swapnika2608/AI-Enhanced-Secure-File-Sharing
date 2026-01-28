"""
Risk Scoring System for AI Security Engine
Combines multiple risk factors to calculate comprehensive threat scores
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import json
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    """Risk level classifications"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RiskFactor:
    """Individual risk factor with weight and score"""
    name: str
    score: float  # 0.0 to 1.0
    weight: float  # Importance weight
    description: str
    evidence: List[str]

@dataclass
class RiskAssessment:
    """Complete risk assessment result"""
    user_id: int
    overall_score: float
    risk_level: RiskLevel
    confidence: float
    factors: List[RiskFactor]
    timestamp: datetime
    recommendations: List[str]

class RiskScorer:
    """Multi-factor risk scoring engine"""
    
    def __init__(self):
        # Risk factor weights (sum should equal 1.0)
        self.weights = {
            'temporal_anomaly': 0.15,
            'geographic_anomaly': 0.20,
            'behavioral_anomaly': 0.25,
            'access_pattern_anomaly': 0.15,
            'authentication_risk': 0.15,
            'device_risk': 0.10
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            RiskLevel.VERY_LOW: (0.0, 0.2),
            RiskLevel.LOW: (0.2, 0.4),
            RiskLevel.MEDIUM: (0.4, 0.6),
            RiskLevel.HIGH: (0.6, 0.8),
            RiskLevel.CRITICAL: (0.8, 1.0)
        }
    
    def calculate_risk_score(self, user_features: Dict, 
                           anomaly_scores: Dict = None,
                           context: Dict = None) -> RiskAssessment:
        """Calculate comprehensive risk score for a user"""
        
        factors = []
        
        # 1. Temporal Anomaly Risk
        temporal_factor = self._calculate_temporal_risk(user_features, context)
        factors.append(temporal_factor)
        
        # 2. Geographic Anomaly Risk
        geographic_factor = self._calculate_geographic_risk(user_features, context)
        factors.append(geographic_factor)
        
        # 3. Behavioral Anomaly Risk
        behavioral_factor = self._calculate_behavioral_risk(user_features, anomaly_scores)
        factors.append(behavioral_factor)
        
        # 4. Access Pattern Risk
        access_factor = self._calculate_access_pattern_risk(user_features, context)
        factors.append(access_factor)
        
        # 5. Authentication Risk
        auth_factor = self._calculate_authentication_risk(user_features, context)
        factors.append(auth_factor)
        
        # 6. Device Risk
        device_factor = self._calculate_device_risk(user_features, context)
        factors.append(device_factor)
        
        # Calculate weighted overall score
        overall_score = sum(factor.score * factor.weight for factor in factors)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Calculate confidence based on data quality
        confidence = self._calculate_confidence(user_features, factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(factors, risk_level)
        
        return RiskAssessment(
            user_id=user_features.get('user_id', 0),
            overall_score=overall_score,
            risk_level=risk_level,
            confidence=confidence,
            factors=factors,
            timestamp=datetime.now(),
            recommendations=recommendations
        )
    
    def _calculate_temporal_risk(self, user_features: Dict, context: Dict = None) -> RiskFactor:
        """Calculate risk based on temporal patterns"""
        
        evidence = []
        risk_score = 0.0
        
        # Current time analysis
        current_hour = datetime.now().hour
        avg_login_hour = user_features.get('avg_login_hour', 12)
        
        # Time deviation risk
        hour_deviation = abs(current_hour - avg_login_hour)
        if hour_deviation > 12:
            hour_deviation = 24 - hour_deviation
        
        time_risk = min(hour_deviation / 8.0, 1.0)  # Normalize to 0-1
        
        if time_risk > 0.5:
            evidence.append(f"Access at unusual time: {current_hour}:00 vs typical {avg_login_hour:.1f}:00")
        
        # Weekend activity risk
        is_weekend = datetime.now().weekday() >= 5
        weekend_ratio = user_features.get('weekend_activity_ratio', 0.3)
        
        if is_weekend and weekend_ratio < 0.1:
            time_risk += 0.3
            evidence.append("Unusual weekend activity detected")
        
        # Recent activity spike
        recent_logins = user_features.get('recent_login_count', 0)
        daily_frequency = user_features.get('login_frequency_daily', 1)
        
        if recent_logins > daily_frequency * 7 * 2:  # More than 2x normal weekly activity
            time_risk += 0.2
            evidence.append(f"Activity spike: {recent_logins} recent logins vs {daily_frequency:.1f} daily average")
        
        risk_score = min(time_risk, 1.0)
        
        return RiskFactor(
            name="temporal_anomaly",
            score=risk_score,
            weight=self.weights['temporal_anomaly'],
            description="Risk based on unusual timing patterns",
            evidence=evidence
        )
    
    def _calculate_geographic_risk(self, user_features: Dict, context: Dict = None) -> RiskFactor:
        """Calculate risk based on geographic patterns"""
        
        evidence = []
        risk_score = 0.0
        
        # Multiple IP addresses risk
        unique_ips = user_features.get('unique_ips_count', 1)
        if unique_ips > 5:
            risk_score += 0.4
            evidence.append(f"Multiple IP addresses used: {unique_ips}")
        elif unique_ips > 2:
            risk_score += 0.2
            evidence.append(f"Several IP addresses used: {unique_ips}")
        
        # Geographic diversity risk
        geo_locations = user_features.get('geographic_locations_count', 1)
        if geo_locations > 3:
            risk_score += 0.5
            evidence.append(f"Access from multiple geographic locations: {geo_locations}")
        elif geo_locations > 1:
            risk_score += 0.2
            evidence.append(f"Access from different locations: {geo_locations}")
        
        risk_score = min(risk_score, 1.0)
        
        return RiskFactor(
            name="geographic_anomaly",
            score=risk_score,
            weight=self.weights['geographic_anomaly'],
            description="Risk based on geographic access patterns",
            evidence=evidence
        )
    
    def _calculate_behavioral_risk(self, user_features: Dict, anomaly_scores: Dict = None) -> RiskFactor:
        """Calculate risk based on behavioral anomalies"""
        
        evidence = []
        risk_score = 0.0
        
        # Use ML anomaly scores if available
        if anomaly_scores:
            ensemble_score = anomaly_scores.get('ensemble_anomaly_score', 0)
            risk_score = ensemble_score
            
            if ensemble_score > 0.7:
                evidence.append(f"High behavioral anomaly score: {ensemble_score:.2f}")
            elif ensemble_score > 0.5:
                evidence.append(f"Moderate behavioral anomaly detected: {ensemble_score:.2f}")
        
        # Session duration anomalies
        session_duration = user_features.get('session_duration_avg', 1)
        if session_duration > 8:  # Very long sessions
            risk_score += 0.2
            evidence.append(f"Unusually long sessions: {session_duration:.1f} hours average")
        elif session_duration < 0.1:  # Very short sessions
            risk_score += 0.1
            evidence.append(f"Unusually short sessions: {session_duration:.1f} hours average")
        
        # File access patterns
        files_per_session = user_features.get('files_accessed_per_session', 1)
        if files_per_session > 10:
            risk_score += 0.3
            evidence.append(f"High file access rate: {files_per_session:.1f} files per session")
        
        risk_score = min(risk_score, 1.0)
        
        return RiskFactor(
            name="behavioral_anomaly",
            score=risk_score,
            weight=self.weights['behavioral_anomaly'],
            description="Risk based on unusual behavioral patterns",
            evidence=evidence
        )
    
    def _calculate_access_pattern_risk(self, user_features: Dict, context: Dict = None) -> RiskFactor:
        """Calculate risk based on file access patterns"""
        
        evidence = []
        risk_score = 0.0
        
        # Recent high-risk access attempts
        recent_risk_events = user_features.get('recent_risk_events', 0)
        if recent_risk_events > 0:
            risk_score += min(recent_risk_events * 0.2, 0.8)
            evidence.append(f"Recent high-risk access attempts: {recent_risk_events}")
        
        # Suspicious activity count
        suspicious_count = user_features.get('suspicious_activity_count', 0)
        if suspicious_count > 0:
            risk_score += min(suspicious_count * 0.15, 0.6)
            evidence.append(f"Suspicious activities detected: {suspicious_count}")
        
        # Average risk score from historical data
        avg_risk = user_features.get('risk_score_avg', 0)
        if avg_risk > 0.5:
            risk_score += avg_risk * 0.4
            evidence.append(f"High average risk score: {avg_risk:.2f}")
        
        risk_score = min(risk_score, 1.0)
        
        return RiskFactor(
            name="access_pattern_anomaly",
            score=risk_score,
            weight=self.weights['access_pattern_anomaly'],
            description="Risk based on file access patterns",
            evidence=evidence
        )
    
    def _calculate_authentication_risk(self, user_features: Dict, context: Dict = None) -> RiskFactor:
        """Calculate risk based on authentication patterns"""
        
        evidence = []
        risk_score = 0.0
        
        # Failed login ratio
        failed_ratio = user_features.get('failed_login_ratio', 0)
        if failed_ratio > 0.3:
            risk_score += 0.8
            evidence.append(f"High failed login ratio: {failed_ratio:.2f}")
        elif failed_ratio > 0.1:
            risk_score += 0.4
            evidence.append(f"Elevated failed login ratio: {failed_ratio:.2f}")
        
        # Recent login frequency
        recent_logins = user_features.get('recent_login_count', 0)
        if recent_logins == 0:
            risk_score += 0.2
            evidence.append("No recent login activity")
        elif recent_logins > 20:  # Too many recent logins
            risk_score += 0.3
            evidence.append(f"Excessive recent logins: {recent_logins}")
        
        risk_score = min(risk_score, 1.0)
        
        return RiskFactor(
            name="authentication_risk",
            score=risk_score,
            weight=self.weights['authentication_risk'],
            description="Risk based on authentication patterns",
            evidence=evidence
        )
    
    def _calculate_device_risk(self, user_features: Dict, context: Dict = None) -> RiskFactor:
        """Calculate risk based on device patterns"""
        
        evidence = []
        risk_score = 0.0
        
        # Device consistency
        device_consistency = user_features.get('device_consistency_score', 1.0)
        if device_consistency < 0.5:
            risk_score += 0.6
            evidence.append(f"Low device consistency: {device_consistency:.2f}")
        elif device_consistency < 0.8:
            risk_score += 0.3
            evidence.append(f"Moderate device inconsistency: {device_consistency:.2f}")
        
        risk_score = min(risk_score, 1.0)
        
        return RiskFactor(
            name="device_risk",
            score=risk_score,
            weight=self.weights['device_risk'],
            description="Risk based on device usage patterns",
            evidence=evidence
        )
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on overall score"""
        
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= score < max_score:
                return level
        
        return RiskLevel.CRITICAL  # Default to highest risk
    
    def _calculate_confidence(self, user_features: Dict, factors: List[RiskFactor]) -> float:
        """Calculate confidence in the risk assessment"""
        
        # Base confidence on data availability and quality
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on available data
        data_points = len([v for v in user_features.values() if v is not None and v != 0])
        confidence += min(data_points * 0.02, 0.3)
        
        # Increase confidence based on evidence strength
        total_evidence = sum(len(factor.evidence) for factor in factors)
        confidence += min(total_evidence * 0.02, 0.2)
        
        return min(confidence, 1.0)
    
    def _generate_recommendations(self, factors: List[RiskFactor], risk_level: RiskLevel) -> List[str]:
        """Generate security recommendations based on risk factors"""
        
        recommendations = []
        
        # Risk level based recommendations
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "IMMEDIATE ACTION: Suspend user account",
                "Block all current sessions",
                "Require security team review before reactivation"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Require immediate step-up authentication",
                "Temporarily restrict file access permissions",
                "Monitor all user activity in real-time"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Require additional authentication for sensitive operations",
                "Increase monitoring frequency"
            ])
        
        # Factor-specific recommendations
        for factor in factors:
            if factor.score > 0.6:
                if factor.name == "geographic_anomaly":
                    recommendations.append("Verify user location and block suspicious IPs")
                elif factor.name == "temporal_anomaly":
                    recommendations.append("Verify user identity for off-hours access")
                elif factor.name == "behavioral_anomaly":
                    recommendations.append("Review recent user behavior changes")
                elif factor.name == "authentication_risk":
                    recommendations.append("Force password reset and enable MFA")
                elif factor.name == "device_risk":
                    recommendations.append("Verify device ownership")
        
        return list(set(recommendations))  # Remove duplicates

# Example usage
if __name__ == "__main__":
    # Initialize risk scorer
    risk_scorer = RiskScorer()
    
    # Example user features
    user_features = {
        'user_id': 1,
        'avg_login_hour': 9.5,
        'login_frequency_daily': 2.1,
        'session_duration_avg': 1.5,
        'weekend_activity_ratio': 0.1,
        'files_accessed_per_session': 3.2,
        'unique_ips_count': 1,
        'geographic_locations_count': 1,
        'device_consistency_score': 0.9,
        'failed_login_ratio': 0.05,
        'suspicious_activity_count': 0,
        'risk_score_avg': 0.2,
        'recent_login_count': 5,
        'recent_access_count': 12,
        'recent_risk_events': 0
    }
    
    # Example anomaly scores
    anomaly_scores = {
        'ensemble_anomaly_score': 0.3
    }
    
    # Calculate risk
    assessment = risk_scorer.calculate_risk_score(
        user_features=user_features,
        anomaly_scores=anomaly_scores
    )
    
    # Display results
    print(f"User {assessment.user_id} Risk Assessment:")
    print(f"Overall Score: {assessment.overall_score:.3f}")
    print(f"Risk Level: {assessment.risk_level.value}")
    print(f"Confidence: {assessment.confidence:.3f}")
    
    print("\nTop Risk Factors:")
    for factor in sorted(assessment.factors, key=lambda x: x.score, reverse=True)[:3]:
        if factor.score > 0.1:
            print(f"- {factor.name}: {factor.score:.3f}")
            for evidence in factor.evidence:
                print(f"  * {evidence}")
    
    print(f"\nRecommendations:")
    for rec in assessment.recommendations:
        print(f"- {rec}")