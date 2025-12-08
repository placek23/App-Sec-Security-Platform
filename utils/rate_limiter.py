"""
Rate Limiter - Control request rates to avoid detection and bans
"""
import time
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Optional, Callable
from functools import wraps


class RateLimiter:
    """Token bucket rate limiter for controlling request rates"""
    
    def __init__(self, requests_per_second: float = 10.0, burst_size: int = 20):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum sustained request rate
            burst_size: Maximum burst of requests allowed
        """
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.monotonic()
        self.lock = threading.Lock()
        
        # Stats tracking
        self.total_requests = 0
        self.total_wait_time = 0.0
        self.requests_throttled = 0
    
    def _add_tokens(self):
        """Add tokens based on elapsed time"""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst_size, self.tokens + elapsed * self.requests_per_second)
        self.last_update = now
    
    def acquire(self, tokens: int = 1, blocking: bool = True, timeout: float = None) -> bool:
        """
        Acquire tokens for a request.
        
        Args:
            tokens: Number of tokens to acquire
            blocking: If True, wait for tokens. If False, return immediately.
            timeout: Maximum time to wait for tokens
            
        Returns:
            True if tokens were acquired, False otherwise
        """
        with self.lock:
            self._add_tokens()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                self.total_requests += 1
                return True
            
            if not blocking:
                return False
            
            # Calculate wait time
            tokens_needed = tokens - self.tokens
            wait_time = tokens_needed / self.requests_per_second
            
            if timeout is not None and wait_time > timeout:
                return False
            
            self.requests_throttled += 1
            self.total_wait_time += wait_time
        
        # Wait outside the lock
        time.sleep(wait_time)
        
        with self.lock:
            self._add_tokens()
            self.tokens -= tokens
            self.total_requests += 1
            return True
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        return {
            'total_requests': self.total_requests,
            'requests_throttled': self.requests_throttled,
            'total_wait_time': self.total_wait_time,
            'avg_wait_time': self.total_wait_time / max(1, self.requests_throttled),
            'current_tokens': self.tokens,
            'requests_per_second': self.requests_per_second,
            'burst_size': self.burst_size
        }
    
    def reset(self):
        """Reset the rate limiter"""
        with self.lock:
            self.tokens = self.burst_size
            self.last_update = time.monotonic()
            self.total_requests = 0
            self.total_wait_time = 0.0
            self.requests_throttled = 0


class AdaptiveRateLimiter(RateLimiter):
    """Rate limiter that adapts based on server responses"""
    
    def __init__(self, 
                 initial_rps: float = 10.0, 
                 min_rps: float = 1.0,
                 max_rps: float = 50.0,
                 burst_size: int = 20):
        super().__init__(initial_rps, burst_size)
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.initial_rps = initial_rps
        
        # Response tracking
        self.response_times = deque(maxlen=100)
        self.error_count = 0
        self.success_count = 0
        self.last_adjustment = time.monotonic()
        self.adjustment_interval = 10.0  # Adjust every 10 seconds
    
    def report_response(self, success: bool, response_time: float = 0.0, status_code: int = 200):
        """
        Report a response to adapt rate limiting.
        
        Args:
            success: Whether the request was successful
            response_time: Time taken for the response
            status_code: HTTP status code
        """
        with self.lock:
            if success and status_code < 400:
                self.success_count += 1
                self.response_times.append(response_time)
            else:
                self.error_count += 1
                
                # Immediate slowdown for rate limiting responses
                if status_code == 429:
                    self._decrease_rate(factor=0.5)
                elif status_code >= 500:
                    self._decrease_rate(factor=0.7)
            
            # Periodic adjustment
            now = time.monotonic()
            if now - self.last_adjustment >= self.adjustment_interval:
                self._adjust_rate()
                self.last_adjustment = now
    
    def _decrease_rate(self, factor: float = 0.8):
        """Decrease the request rate"""
        new_rps = max(self.min_rps, self.requests_per_second * factor)
        if new_rps != self.requests_per_second:
            print(f"[!] Rate decreased: {self.requests_per_second:.1f} -> {new_rps:.1f} req/s")
            self.requests_per_second = new_rps
    
    def _increase_rate(self, factor: float = 1.1):
        """Increase the request rate"""
        new_rps = min(self.max_rps, self.requests_per_second * factor)
        if new_rps != self.requests_per_second:
            print(f"[+] Rate increased: {self.requests_per_second:.1f} -> {new_rps:.1f} req/s")
            self.requests_per_second = new_rps
    
    def _adjust_rate(self):
        """Adjust rate based on recent performance"""
        total = self.success_count + self.error_count
        if total == 0:
            return
        
        error_rate = self.error_count / total
        
        if error_rate > 0.2:  # More than 20% errors
            self._decrease_rate(factor=0.7)
        elif error_rate < 0.05 and len(self.response_times) > 10:  # Less than 5% errors
            avg_response = sum(self.response_times) / len(self.response_times)
            if avg_response < 1.0:  # Fast responses
                self._increase_rate(factor=1.2)
        
        # Reset counters
        self.error_count = 0
        self.success_count = 0


class DomainRateLimiter:
    """Per-domain rate limiting to respect different site limits"""
    
    def __init__(self, default_rps: float = 10.0):
        self.default_rps = default_rps
        self.limiters = {}
        self.lock = threading.Lock()
        
        # Known domain limits
        self.domain_limits = {
            'github.com': 5.0,
            'gitlab.com': 5.0,
            'bitbucket.org': 5.0,
            'api.github.com': 3.0,
            'shodan.io': 1.0,
            'censys.io': 1.0,
        }
    
    def get_limiter(self, domain: str) -> RateLimiter:
        """Get or create a rate limiter for a domain"""
        with self.lock:
            if domain not in self.limiters:
                rps = self.domain_limits.get(domain, self.default_rps)
                self.limiters[domain] = AdaptiveRateLimiter(initial_rps=rps)
            return self.limiters[domain]
    
    def acquire(self, domain: str, tokens: int = 1) -> bool:
        """Acquire tokens for a domain"""
        limiter = self.get_limiter(domain)
        return limiter.acquire(tokens)
    
    def report_response(self, domain: str, success: bool, response_time: float = 0.0, status_code: int = 200):
        """Report a response for a domain"""
        limiter = self.get_limiter(domain)
        if isinstance(limiter, AdaptiveRateLimiter):
            limiter.report_response(success, response_time, status_code)
    
    def get_all_stats(self) -> dict:
        """Get stats for all domains"""
        stats = {}
        for domain, limiter in self.limiters.items():
            stats[domain] = limiter.get_stats()
        return stats


def rate_limited(limiter: RateLimiter = None, rps: float = 10.0):
    """
    Decorator to rate limit function calls.
    
    Args:
        limiter: RateLimiter instance to use
        rps: Requests per second if creating new limiter
    """
    if limiter is None:
        limiter = RateLimiter(requests_per_second=rps)
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.acquire()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def delay_between_calls(seconds: float = 1.0):
    """
    Decorator to add delay between function calls.
    
    Args:
        seconds: Delay in seconds between calls
    """
    last_call = [0.0]  # Use list to allow modification in closure
    lock = threading.Lock()
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                now = time.monotonic()
                elapsed = now - last_call[0]
                if elapsed < seconds:
                    time.sleep(seconds - elapsed)
                last_call[0] = time.monotonic()
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global rate limiter instance
global_limiter = DomainRateLimiter(default_rps=10.0)


if __name__ == "__main__":
    # Test the rate limiter
    limiter = RateLimiter(requests_per_second=5.0, burst_size=10)
    
    print("Testing rate limiter (5 req/s, burst 10)...")
    start = time.time()
    
    for i in range(20):
        limiter.acquire()
        print(f"Request {i+1} at {time.time() - start:.2f}s")
    
    print("\nStats:", limiter.get_stats())
