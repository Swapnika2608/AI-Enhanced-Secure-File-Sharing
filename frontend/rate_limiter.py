"""
Rate Limiting Middleware for BlindSend API
Protects against brute force and DDoS attacks
"""

from fastapi import HTTPException, Request
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Tuple
import asyncio

class RateLimiter:
    def __init__(self, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.minute_requests: Dict[str, list] = defaultdict(list)
        self.hour_requests: Dict[str, list] = defaultdict(list)
        self.blocked_ips: Dict[str, datetime] = {}
        
    def _clean_old_requests(self, ip: str):
        """Remove requests older than tracking window"""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        # Clean minute window
        self.minute_requests[ip] = [
            req_time for req_time in self.minute_requests[ip]
            if req_time > minute_ago
        ]
        
        # Clean hour window
        self.hour_requests[ip] = [
            req_time for req_time in self.hour_requests[ip]
            if req_time > hour_ago
        ]
        
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is temporarily blocked"""
        if ip in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def block_ip(self, ip: str, minutes: int = 15):
        """Temporarily block an IP address"""
        self.blocked_ips[ip] = datetime.now() + timedelta(minutes=minutes)
    
    async def check_rate_limit(self, request: Request) -> bool:
        """Check if request should be allowed"""
        # Get client IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip = forwarded_for.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "127.0.0.1"
        
        # Check if blocked
        if self.is_blocked(ip):
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Your IP has been temporarily blocked. Try again in 15 minutes."
            )
        
        # Clean old requests
        self._clean_old_requests(ip)
        
        # Check minute limit
        minute_count = len(self.minute_requests[ip])
        if minute_count >= self.requests_per_minute:
            self.block_ip(ip, minutes=5)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.requests_per_minute} requests per minute"
            )
        
        # Check hour limit
        hour_count = len(self.hour_requests[ip])
        if hour_count >= self.requests_per_hour:
            self.block_ip(ip, minutes=15)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.requests_per_hour} requests per hour"
            )
        
        # Record this request
        now = datetime.now()
        self.minute_requests[ip].append(now)
        self.hour_requests[ip].append(now)
        
        return True

# Global rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=60,
    requests_per_hour=1000
)

async def rate_limit_dependency(request: Request):
    """FastAPI dependency for rate limiting"""
    await rate_limiter.check_rate_limit(request)
    return True
