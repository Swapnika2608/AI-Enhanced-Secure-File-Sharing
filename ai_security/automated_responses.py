"""
Automated Response System for AI Security Engine
Takes automated security actions based on threat detection and risk scores
"""

import psycopg
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum
from dataclasses import dataclass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class ResponseAction(Enum):
    """Types of automated security responses"""
    LOG_EVENT = "log_event"
    INCREASE_MONITORING = "increase_monitoring"
    REQUIRE_MFA = "require_mfa"
    RESTRICT_ACCESS = "restrict_access"
    BLOCK_IP = "block_ip"
    SUSPEND_ACCOUNT = "suspend_account"
    REVOKE_TOKENS = "revoke_tokens"
    NOTIFY_ADMIN = "notify_admin"
    FORCE_LOGOUT = "force_logout"

@dataclass
class SecurityResponse:
    """Security response action details"""
    action: ResponseAction
    user_id: int
    reason: str
    risk_score: float
    timestamp: datetime
    details: Dict
    executed: bool = False
    execution_result: Optional[str] = None

class AutomatedResponseSystem:
    """Automated security response engine"""
    
    def __init__(self, db_config: Dict[str, str], email_config: Dict[str, str] = None):
        self.db_config = db_config
        self.email_config = email_config
        
        # Response thresholds
        self.response_thresholds = {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.9
        }
        
        # Action mappings based on risk level
        self.risk_actions = {
            'low': [ResponseAction.LOG_EVENT, ResponseAction.INCREASE_MONITORING],
            'medium': [ResponseAction.LOG_EVENT, ResponseAction.REQUIRE_MFA, ResponseAction.INCREASE_MONITORING],
            'high': [ResponseAction.RESTRICT_ACCESS, ResponseAction.REQUIRE_MFA, ResponseAction.NOTIFY_ADMIN, ResponseAction.LOG_EVENT],
            'critical': [ResponseAction.SUSPEND_ACCOUNT, ResponseAction.REVOKE_TOKENS, ResponseAction.FORCE_LOGOUT, ResponseAction.BLOCK_IP, ResponseAction.NOTIFY_ADMIN]
        }
    
    def connect_db(self):
        """Connect to PostgreSQL database"""
        db_config = self.db_config.copy()
        if 'database' in db_config:
            db_config['dbname'] = db_config.pop('database')
        return psycopg.connect(**db_config)
    
    def process_threat_detection(self, risk_assessment: Dict, context: Dict = None) -> List[SecurityResponse]:
        """Process threat detection and determine appropriate responses"""
        
        user_id = risk_assessment['user_id']
        risk_score = risk_assessment['overall_score']
        risk_level = risk_assessment['risk_level']
        
        # Determine required actions based on risk level
        required_actions = self.risk_actions.get(risk_level, [ResponseAction.LOG_EVENT])
        
        responses = []
        for action in required_actions:
            response = SecurityResponse(
                action=action,
                user_id=user_id,
                reason=f"Risk level: {risk_level}, Score: {risk_score:.3f}",
                risk_score=risk_score,
                timestamp=datetime.now(),
                details={
                    'risk_assessment': risk_assessment,
                    'context': context or {}
                }
            )
            responses.append(response)
        
        return responses
    
    def execute_responses(self, responses: List[SecurityResponse]) -> List[SecurityResponse]:
        """Execute all security responses"""
        
        executed_responses = []
        
        for response in responses:
            try:
                success = self._execute_single_response(response)
                response.executed = success
                response.execution_result = "Success" if success else "Failed"
                
                # Log the response execution
                self._log_response_execution(response)
                
            except Exception as e:
                response.executed = False
                response.execution_result = f"Error: {str(e)}"
                print(f"Failed to execute response {response.action.value}: {e}")
            
            executed_responses.append(response)
        
        return executed_responses
    
    def _execute_single_response(self, response: SecurityResponse) -> bool:
        """Execute a single security response action"""
        
        if response.action == ResponseAction.LOG_EVENT:
            return self._log_security_event(response)
        
        elif response.action == ResponseAction.SUSPEND_ACCOUNT:
            return self._suspend_user_account(response.user_id, response.reason)
        
        elif response.action == ResponseAction.REVOKE_TOKENS:
            return self._revoke_user_tokens(response.user_id, response.reason)
        
        elif response.action == ResponseAction.FORCE_LOGOUT:
            return self._force_user_logout(response.user_id, response.reason)
        
        elif response.action == ResponseAction.RESTRICT_ACCESS:
            return self._restrict_user_access(response.user_id, response.reason)
        
        elif response.action == ResponseAction.BLOCK_IP:
            return self._block_suspicious_ips(response)
        
        elif response.action == ResponseAction.NOTIFY_ADMIN:
            return self._notify_administrators(response)
        
        elif response.action == ResponseAction.REQUIRE_MFA:
            return self._require_mfa(response.user_id, response.reason)
        
        elif response.action == ResponseAction.INCREASE_MONITORING:
            return self._increase_monitoring(response.user_id, response.reason)
        
        else:
            print(f"Unknown response action: {response.action}")
            return False
    
    def _log_security_event(self, response: SecurityResponse) -> bool:
        """Log security event to audit table"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'automated_security_response',
                    f'user_{response.user_id}',
                    'system',
                    response.timestamp,
                    True,
                    json.dumps({
                        'action': response.action.value,
                        'reason': response.reason,
                        'risk_score': response.risk_score,
                        'details': response.details
                    })
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Failed to log security event: {e}")
            return False
    
    def _suspend_user_account(self, user_id: int, reason: str) -> bool:
        """Suspend user account"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Deactivate user account
                cursor.execute("""
                    UPDATE users 
                    SET is_active = false 
                    WHERE id = %s
                """, (user_id,))
                
                # Log the suspension
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'account_suspended',
                    f'user_{user_id}',
                    'system',
                    datetime.now(),
                    True,
                    json.dumps({'reason': reason, 'automated': True})
                ))
                
                conn.commit()
                print(f"User {user_id} account suspended: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to suspend user account: {e}")
            return False
    
    def _revoke_user_tokens(self, user_id: int, reason: str) -> bool:
        """Revoke all user access tokens"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Deactivate all user's access tokens
                cursor.execute("""
                    UPDATE access_tokens 
                    SET is_active = false 
                    WHERE link_id IN (
                        SELECT link_id FROM user_links WHERE user_id = %s
                    )
                """, (user_id,))
                
                # Revoke all user's link access controls
                cursor.execute("""
                    UPDATE link_access_controls 
                    SET is_revoked = true, revoked_at = %s
                    WHERE link_id IN (
                        SELECT link_id FROM user_links WHERE user_id = %s
                    )
                """, (datetime.now(), user_id))
                
                conn.commit()
                print(f"All tokens revoked for user {user_id}: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to revoke user tokens: {e}")
            return False
    
    def _force_user_logout(self, user_id: int, reason: str) -> bool:
        """Force logout all user sessions"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Deactivate all user sessions
                cursor.execute("""
                    UPDATE user_sessions 
                    SET is_active = false 
                    WHERE user_id = %s
                """, (user_id,))
                
                conn.commit()
                print(f"Forced logout for user {user_id}: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to force user logout: {e}")
            return False
    
    def _restrict_user_access(self, user_id: int, reason: str) -> bool:
        """Restrict user access permissions"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Set download limits to 0 for all user links
                cursor.execute("""
                    UPDATE link_access_controls 
                    SET max_downloads = 0
                    WHERE link_id IN (
                        SELECT link_id FROM user_links WHERE user_id = %s
                    )
                """, (user_id,))
                
                # Set custom expiration to now (effectively disabling access)
                cursor.execute("""
                    UPDATE link_access_controls 
                    SET custom_expires_at = %s
                    WHERE link_id IN (
                        SELECT link_id FROM user_links WHERE user_id = %s
                    )
                """, (datetime.now(), user_id))
                
                conn.commit()
                print(f"Access restricted for user {user_id}: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to restrict user access: {e}")
            return False
    
    def _block_suspicious_ips(self, response: SecurityResponse) -> bool:
        """Block suspicious IP addresses"""
        
        try:
            # Get suspicious IPs from user's recent activity
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Find recent high-risk access attempts
                cursor.execute("""
                    SELECT DISTINCT ip_address 
                    FROM access_attempts aa
                    JOIN user_links ul ON aa.link_id = ul.link_id
                    WHERE ul.user_id = %s 
                      AND aa.risk_score > 0.7
                      AND aa.timestamp > %s
                """, (response.user_id, datetime.now() - timedelta(hours=24)))
                
                suspicious_ips = [row[0] for row in cursor.fetchall()]
                
                # Log blocked IPs (in real system, would integrate with firewall/WAF)
                for ip in suspicious_ips:
                    cursor.execute("""
                        INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        'ip_blocked',
                        f'user_{response.user_id}',
                        ip,
                        datetime.now(),
                        True,
                        json.dumps({'reason': response.reason, 'automated': True})
                    ))
                
                conn.commit()
                print(f"Blocked {len(suspicious_ips)} suspicious IPs for user {response.user_id}")
                return True
                
        except Exception as e:
            print(f"Failed to block suspicious IPs: {e}")
            return False
    
    def _notify_administrators(self, response: SecurityResponse) -> bool:
        """Notify administrators of security incident"""
        
        try:
            if not self.email_config:
                print("Email configuration not provided, logging notification instead")
                return self._log_admin_notification(response)
            
            # Prepare email content
            subject = f"🚨 SECURITY ALERT - User {response.user_id} - Risk Level: {response.details['risk_assessment']['risk_level']}"
            
            body = f"""
AUTOMATED SECURITY ALERT

User ID: {response.user_id}
Risk Score: {response.risk_score:.3f}
Risk Level: {response.details['risk_assessment']['risk_level']}
Timestamp: {response.timestamp}

Reason: {response.reason}

Risk Factors:
"""
            
            # Add risk factor details
            for factor in response.details['risk_assessment'].get('factors', []):
                if factor['score'] > 0.3:
                    body += f"- {factor['name']}: {factor['score']:.3f}\n"
                    for evidence in factor.get('evidence', []):
                        body += f"  * {evidence}\n"
            
            body += f"\nRecommendations:\n"
            for rec in response.details['risk_assessment'].get('recommendations', []):
                body += f"- {rec}\n"
            
            # Send email
            self._send_email(subject, body)
            print(f"Admin notification sent for user {response.user_id}")
            return True
            
        except Exception as e:
            print(f"Failed to notify administrators: {e}")
            return False
    
    def _send_email(self, subject: str, body: str):
        """Send email notification"""
        
        msg = MIMEMultipart()
        msg['From'] = self.email_config['from_email']
        msg['To'] = self.email_config['admin_email']
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
        if self.email_config.get('use_tls'):
            server.starttls()
        if self.email_config.get('username'):
            server.login(self.email_config['username'], self.email_config['password'])
        
        server.send_message(msg)
        server.quit()
    
    def _log_admin_notification(self, response: SecurityResponse) -> bool:
        """Log admin notification when email is not configured"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'admin_notification',
                    f'user_{response.user_id}',
                    'system',
                    datetime.now(),
                    True,
                    json.dumps({
                        'notification_type': 'security_alert',
                        'risk_score': response.risk_score,
                        'reason': response.reason,
                        'details': response.details
                    })
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Failed to log admin notification: {e}")
            return False
    
    def _require_mfa(self, user_id: int, reason: str) -> bool:
        """Require multi-factor authentication for user"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Log MFA requirement (in real system, would set user flags)
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'mfa_required',
                    f'user_{user_id}',
                    'system',
                    datetime.now(),
                    True,
                    json.dumps({'reason': reason, 'automated': True})
                ))
                
                conn.commit()
                print(f"MFA required for user {user_id}: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to require MFA: {e}")
            return False
    
    def _increase_monitoring(self, user_id: int, reason: str) -> bool:
        """Increase monitoring for user activities"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                # Log increased monitoring (in real system, would set monitoring flags)
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'monitoring_increased',
                    f'user_{user_id}',
                    'system',
                    datetime.now(),
                    True,
                    json.dumps({'reason': reason, 'automated': True})
                ))
                
                conn.commit()
                print(f"Increased monitoring for user {user_id}: {reason}")
                return True
                
        except Exception as e:
            print(f"Failed to increase monitoring: {e}")
            return False
    
    def _log_response_execution(self, response: SecurityResponse):
        """Log the execution of security response"""
        
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO audit_events (event_type, link_id, ip_address, timestamp, success, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    'security_response_executed',
                    f'user_{response.user_id}',
                    'system',
                    datetime.now(),
                    response.executed,
                    json.dumps({
                        'action': response.action.value,
                        'execution_result': response.execution_result,
                        'risk_score': response.risk_score,
                        'reason': response.reason
                    })
                ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Failed to log response execution: {e}")

# Example usage
if __name__ == "__main__":
    # Database configuration
    db_config = {
        'host': 'localhost',
        'port': '5432',
        'database': 'blindsend_test',
        'user': 'postgres',
        'password': 'your_actual_password_here'  # Replace with your PostgreSQL password
    }
    
    # Email configuration (optional)
    email_config = {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'use_tls': True,
        'from_email': 'security@yourcompany.com',
        'admin_email': 'admin@yourcompany.com',
        'username': 'your_email@gmail.com',
        'password': 'your_app_password'
    }
    
    # Initialize response system
    response_system = AutomatedResponseSystem(db_config, email_config)
    
    # Example risk assessment (would come from risk scoring system)
    risk_assessment = {
        'user_id': 1,
        'overall_score': 0.85,
        'risk_level': 'critical',
        'confidence': 0.9,
        'factors': [
            {
                'name': 'behavioral_anomaly',
                'score': 0.9,
                'evidence': ['High behavioral anomaly score: 0.90']
            }
        ],
        'recommendations': [
            'IMMEDIATE ACTION: Suspend user account',
            'Block all current sessions'
        ]
    }
    
    # Process threat and execute responses
    responses = response_system.process_threat_detection(risk_assessment)
    executed_responses = response_system.execute_responses(responses)
    
    print(f"\nExecuted {len(executed_responses)} security responses:")
    for response in executed_responses:
        status = "✅" if response.executed else "❌"
        print(f"{status} {response.action.value}: {response.execution_result}")