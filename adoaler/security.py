"""
===========================================================================
Adoaler Security Module
Rate Limiting, HMAC Signing, Encryption, CSRF, Webhooks
===========================================================================
"""

import hashlib
import hmac
import secrets
import base64
import time
import json
import threading
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
from functools import wraps
import os

# Optional crypto library - falls back to basic if not available
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class SecurityException(Exception):
    """Base security exception"""
    pass


class RateLimitExceeded(SecurityException):
    """Rate limit exceeded"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message)
        self.retry_after = retry_after


class SignatureError(SecurityException):
    """Signature verification failed"""
    pass


class EncryptionError(SecurityException):
    """Encryption/decryption failed"""
    pass


class CSRFError(SecurityException):
    """CSRF validation failed"""
    pass


# ===========================================================================
# Rate Limiter - Client-side rate limiting to prevent 429s
# ===========================================================================

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests: int
    window_seconds: int
    burst: int = 0  # Allow burst above limit temporarily


@dataclass
class RateLimitState:
    """Track rate limit state"""
    timestamps: List[float] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class RateLimiter:
    """
    Client-side rate limiter using sliding window algorithm
    
    Usage:
        limiter = RateLimiter()
        limiter.configure('api', RateLimitConfig(requests=100, window_seconds=60))
        
        # Before making request
        if limiter.check('api'):
            response = api.make_request()
        else:
            print(f"Rate limited, retry after {limiter.get_retry_after('api')}s")
    """
    
    # Default rate limits matching Adoaler API
    DEFAULT_LIMITS = {
        'default': RateLimitConfig(requests=60, window_seconds=60),
        'auth': RateLimitConfig(requests=5, window_seconds=60),
        'api': RateLimitConfig(requests=1000, window_seconds=3600),
        'search': RateLimitConfig(requests=30, window_seconds=60),
        'upload': RateLimitConfig(requests=10, window_seconds=60),
        'email': RateLimitConfig(requests=3, window_seconds=3600),
    }
    
    def __init__(self):
        self._limits: Dict[str, RateLimitConfig] = dict(self.DEFAULT_LIMITS)
        self._states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
    
    def configure(self, limit_type: str, config: RateLimitConfig) -> None:
        """Configure rate limit for a type"""
        self._limits[limit_type] = config
    
    def check(self, limit_type: str = 'default', key: str = None) -> bool:
        """
        Check if request is allowed under rate limit
        
        Args:
            limit_type: Type of rate limit to check
            key: Optional key for per-resource limiting
            
        Returns:
            True if allowed, False if rate limited
        """
        config = self._limits.get(limit_type, self._limits['default'])
        state_key = f"{limit_type}:{key}" if key else limit_type
        state = self._states[state_key]
        
        now = time.time()
        window_start = now - config.window_seconds
        
        with state.lock:
            # Remove expired timestamps
            state.timestamps = [ts for ts in state.timestamps if ts > window_start]
            
            # Check limit
            max_requests = config.requests + config.burst
            if len(state.timestamps) >= max_requests:
                return False
            
            # Record this request
            state.timestamps.append(now)
            return True
    
    def acquire(self, limit_type: str = 'default', key: str = None, block: bool = True) -> bool:
        """
        Acquire rate limit slot, optionally blocking until available
        
        Args:
            limit_type: Type of rate limit
            key: Optional key for per-resource limiting
            block: If True, wait for slot; if False, return immediately
            
        Returns:
            True if acquired, False if not (when block=False)
            
        Raises:
            RateLimitExceeded if block=False and limit exceeded
        """
        if self.check(limit_type, key):
            return True
        
        if not block:
            retry_after = self.get_retry_after(limit_type, key)
            raise RateLimitExceeded(
                f"Rate limit exceeded for {limit_type}",
                retry_after=retry_after
            )
        
        # Wait and retry
        retry_after = self.get_retry_after(limit_type, key)
        time.sleep(retry_after)
        return self.acquire(limit_type, key, block=True)
    
    def get_retry_after(self, limit_type: str = 'default', key: str = None) -> int:
        """Get seconds until rate limit resets"""
        config = self._limits.get(limit_type, self._limits['default'])
        state_key = f"{limit_type}:{key}" if key else limit_type
        state = self._states[state_key]
        
        now = time.time()
        window_start = now - config.window_seconds
        
        with state.lock:
            valid_timestamps = [ts for ts in state.timestamps if ts > window_start]
            if not valid_timestamps:
                return 0
            
            oldest = min(valid_timestamps)
            retry_after = config.window_seconds - (now - oldest)
            return max(1, int(retry_after))
    
    def get_remaining(self, limit_type: str = 'default', key: str = None) -> int:
        """Get remaining requests in current window"""
        config = self._limits.get(limit_type, self._limits['default'])
        state_key = f"{limit_type}:{key}" if key else limit_type
        state = self._states[state_key]
        
        now = time.time()
        window_start = now - config.window_seconds
        
        with state.lock:
            valid_timestamps = [ts for ts in state.timestamps if ts > window_start]
            return max(0, config.requests - len(valid_timestamps))
    
    def reset(self, limit_type: str = None, key: str = None) -> None:
        """Reset rate limit state"""
        if limit_type:
            state_key = f"{limit_type}:{key}" if key else limit_type
            if state_key in self._states:
                with self._states[state_key].lock:
                    self._states[state_key].timestamps.clear()
        else:
            self._states.clear()


def rate_limited(limiter: RateLimiter, limit_type: str = 'default', key_func: Callable = None):
    """
    Decorator for rate-limiting functions
    
    Usage:
        limiter = RateLimiter()
        
        @rate_limited(limiter, 'api')
        def make_api_call():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs) if key_func else None
            limiter.acquire(limit_type, key)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ===========================================================================
# HMAC Request Signing
# ===========================================================================

class HMACSigner:
    """
    HMAC request signing for secure API communication
    
    Usage:
        signer = HMACSigner(api_key='key', api_secret='secret')
        
        # Sign a request
        headers = signer.sign_request('POST', '/api/v1/secure', {'data': 'value'})
        
        # Verify a webhook signature
        if signer.verify_signature(payload, signature, timestamp):
            process_webhook(payload)
    """
    
    SIGNATURE_HEADER = 'X-Adoaler-Signature'
    TIMESTAMP_HEADER = 'X-Adoaler-Timestamp'
    NONCE_HEADER = 'X-Adoaler-Nonce'
    
    # Signature valid for 5 minutes
    TIMESTAMP_TOLERANCE = 300
    
    def __init__(self, api_key: str, api_secret: str, algorithm: str = 'sha256'):
        self.api_key = api_key
        self.api_secret = api_secret.encode('utf-8') if isinstance(api_secret, str) else api_secret
        self.algorithm = algorithm
        self._used_nonces: Dict[str, float] = {}
        self._nonce_lock = threading.Lock()
    
    def sign_request(
        self,
        method: str,
        path: str,
        body: Any = None,
        timestamp: int = None,
        nonce: str = None
    ) -> Dict[str, str]:
        """
        Sign a request and return headers to include
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body (dict or string)
            timestamp: Unix timestamp (optional, defaults to now)
            nonce: Unique request ID (optional, auto-generated)
            
        Returns:
            Dict of headers to include in request
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        if nonce is None:
            nonce = secrets.token_hex(16)
        
        # Build signature payload
        if body is not None:
            if isinstance(body, dict):
                body_str = json.dumps(body, separators=(',', ':'), sort_keys=True)
            else:
                body_str = str(body)
        else:
            body_str = ''
        
        payload = f"{method.upper()}\n{path}\n{body_str}\n{timestamp}\n{nonce}"
        
        # Generate signature
        signature = hmac.new(
            self.api_secret,
            payload.encode('utf-8'),
            getattr(hashlib, self.algorithm)
        ).hexdigest()
        
        return {
            self.SIGNATURE_HEADER: f"v1={signature}",
            self.TIMESTAMP_HEADER: str(timestamp),
            self.NONCE_HEADER: nonce,
            'X-Adoaler-Key': self.api_key,
        }
    
    def verify_signature(
        self,
        payload: str,
        signature: str,
        timestamp: int,
        nonce: str = None
    ) -> bool:
        """
        Verify an incoming signature (e.g., webhook)
        
        Args:
            payload: The signed payload (usually request body)
            signature: The signature to verify
            timestamp: Unix timestamp from header
            nonce: Optional nonce for replay protection
            
        Returns:
            True if signature is valid
            
        Raises:
            SignatureError if verification fails
        """
        # Check timestamp freshness
        now = int(time.time())
        if abs(now - timestamp) > self.TIMESTAMP_TOLERANCE:
            raise SignatureError('Signature timestamp expired')
        
        # Check nonce for replay protection
        if nonce:
            with self._nonce_lock:
                # Clean old nonces
                cutoff = now - self.TIMESTAMP_TOLERANCE
                self._used_nonces = {
                    n: ts for n, ts in self._used_nonces.items() 
                    if ts > cutoff
                }
                
                if nonce in self._used_nonces:
                    raise SignatureError('Nonce already used (replay attack)')
                
                self._used_nonces[nonce] = timestamp
        
        # Extract signature version and value
        if signature.startswith('v1='):
            signature = signature[3:]
        
        # Build expected signature payload
        sig_payload = f"{payload}\n{timestamp}"
        if nonce:
            sig_payload += f"\n{nonce}"
        
        expected = hmac.new(
            self.api_secret,
            sig_payload.encode('utf-8'),
            getattr(hashlib, self.algorithm)
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected):
            raise SignatureError('Invalid signature')
        
        return True
    
    def generate_api_signature(self, data: Dict[str, Any]) -> str:
        """Generate a simple signature for data"""
        sorted_data = json.dumps(data, separators=(',', ':'), sort_keys=True)
        return hmac.new(
            self.api_secret,
            sorted_data.encode('utf-8'),
            getattr(hashlib, self.algorithm)
        ).hexdigest()


# ===========================================================================
# Webhook Verification
# ===========================================================================

class WebhookVerifier:
    """
    Verify incoming webhook signatures from Adoaler
    
    Usage:
        verifier = WebhookVerifier(webhook_secret='whsec_xxx')
        
        @app.route('/webhook', methods=['POST'])
        def handle_webhook():
            signature = request.headers.get('X-Adoaler-Signature')
            timestamp = request.headers.get('X-Adoaler-Timestamp')
            
            if verifier.verify(request.data, signature, timestamp):
                event = verifier.construct_event(request.data)
                # Process event
    """
    
    TIMESTAMP_TOLERANCE = 300  # 5 minutes
    
    def __init__(self, webhook_secret: str):
        self.secret = webhook_secret.encode('utf-8') if isinstance(webhook_secret, str) else webhook_secret
    
    def verify(
        self,
        payload: bytes,
        signature: str,
        timestamp: str,
        tolerance: int = None
    ) -> bool:
        """
        Verify webhook signature
        
        Args:
            payload: Raw request body
            signature: X-Adoaler-Signature header
            timestamp: X-Adoaler-Timestamp header
            tolerance: Optional custom tolerance in seconds
            
        Returns:
            True if valid
            
        Raises:
            SignatureError if invalid
        """
        if tolerance is None:
            tolerance = self.TIMESTAMP_TOLERANCE
        
        # Validate timestamp
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            raise SignatureError('Invalid timestamp format')
        
        now = int(time.time())
        if abs(now - ts) > tolerance:
            raise SignatureError(f'Timestamp outside tolerance ({tolerance}s)')
        
        # Parse signature header (may contain multiple signatures for key rotation)
        signatures = self._parse_signature_header(signature)
        
        if not signatures:
            raise SignatureError('No valid signature found')
        
        # Build signed payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        signed_payload = f"{ts}.{payload}"
        
        # Compute expected signature
        expected = hmac.new(
            self.secret,
            signed_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Check if any signature matches
        for sig in signatures:
            if hmac.compare_digest(sig, expected):
                return True
        
        raise SignatureError('Signature verification failed')
    
    def _parse_signature_header(self, header: str) -> List[str]:
        """Parse signature header into list of signatures"""
        signatures = []
        
        for part in header.split(','):
            part = part.strip()
            if '=' in part:
                version, sig = part.split('=', 1)
                if version in ('v1', 't'):  # v1 = signature, t = timestamp
                    signatures.append(sig)
            else:
                signatures.append(part)
        
        return signatures
    
    def construct_event(self, payload: bytes) -> Dict[str, Any]:
        """Parse webhook payload into event dict"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        return json.loads(payload)


# ===========================================================================
# Encryption - AES-256-GCM
# ===========================================================================

class Encryptor:
    """
    AES-256-GCM encryption for sensitive data
    
    Usage:
        enc = Encryptor(key='your-32-byte-key-here-xxxxxxxx')
        
        # Encrypt
        encrypted = enc.encrypt('sensitive data')
        
        # Decrypt
        original = enc.decrypt(encrypted)
    """
    
    def __init__(self, key: str = None):
        """
        Initialize encryptor
        
        Args:
            key: 32-byte encryption key (will be derived if shorter)
        """
        if key is None:
            key = secrets.token_bytes(32)
        elif isinstance(key, str):
            # Derive key if not exactly 32 bytes
            if len(key) != 32:
                key = self._derive_key(key)
            else:
                key = key.encode('utf-8')
        
        self.key = key
        
        if HAS_CRYPTOGRAPHY:
            self._aesgcm = AESGCM(key)
    
    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive a 32-byte key from password"""
        if salt is None:
            salt = b'adoaler-sdk-salt'  # Static salt for reproducibility
        
        if HAS_CRYPTOGRAPHY:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            return kdf.derive(password.encode('utf-8'))
        else:
            # Fallback: simple key derivation
            return hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000,
                dklen=32
            )
    
    def encrypt(self, data: str, associated_data: bytes = None) -> str:
        """
        Encrypt data using AES-256-GCM
        
        Args:
            data: String to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Base64-encoded encrypted string (IV + tag + ciphertext)
        """
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
        
        if HAS_CRYPTOGRAPHY:
            ciphertext = self._aesgcm.encrypt(
                iv,
                data.encode('utf-8'),
                associated_data
            )
            # ciphertext includes the tag
            result = iv + ciphertext
        else:
            # Pure Python fallback using simple XOR (NOT secure, just for testing)
            raise EncryptionError(
                "cryptography library required for encryption. "
                "Install with: pip install cryptography"
            )
        
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt(self, encrypted_data: str, associated_data: bytes = None) -> str:
        """
        Decrypt AES-256-GCM encrypted data
        
        Args:
            encrypted_data: Base64-encoded encrypted string
            associated_data: Optional additional authenticated data
            
        Returns:
            Decrypted string
        """
        try:
            data = base64.b64decode(encrypted_data)
        except Exception:
            raise EncryptionError('Invalid base64 encoding')
        
        if len(data) < 28:  # 12 (IV) + 16 (tag minimum)
            raise EncryptionError('Invalid encrypted data length')
        
        iv = data[:12]
        ciphertext = data[12:]
        
        if HAS_CRYPTOGRAPHY:
            try:
                plaintext = self._aesgcm.decrypt(iv, ciphertext, associated_data)
                return plaintext.decode('utf-8')
            except Exception as e:
                raise EncryptionError(f'Decryption failed: {e}')
        else:
            raise EncryptionError(
                "cryptography library required for decryption. "
                "Install with: pip install cryptography"
            )
    
    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """Encrypt a dictionary as JSON"""
        json_str = json.dumps(data, separators=(',', ':'))
        return self.encrypt(json_str)
    
    def decrypt_dict(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt and parse as dictionary"""
        json_str = self.decrypt(encrypted_data)
        return json.loads(json_str)


# ===========================================================================
# CSRF Protection
# ===========================================================================

class CSRFProtection:
    """
    CSRF token management for web applications
    
    Usage:
        csrf = CSRFProtection(secret_key='your-secret')
        
        # Generate token for form
        token = csrf.generate_token(session_id='user-session-123')
        
        # Validate on form submission
        if csrf.validate_token(token, session_id='user-session-123'):
            process_form()
    """
    
    TOKEN_LENGTH = 32
    TOKEN_LIFETIME = 3600  # 1 hour
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode('utf-8') if isinstance(secret_key, str) else secret_key
        self._tokens: Dict[str, tuple] = {}  # token -> (session_id, expiry)
        self._lock = threading.Lock()
    
    def generate_token(self, session_id: str = None) -> str:
        """
        Generate a CSRF token
        
        Args:
            session_id: Optional session identifier to bind token to
            
        Returns:
            CSRF token string
        """
        token = secrets.token_urlsafe(self.TOKEN_LENGTH)
        expiry = time.time() + self.TOKEN_LIFETIME
        
        # Create signed token
        payload = f"{token}:{expiry}"
        if session_id:
            payload += f":{session_id}"
        
        signature = hmac.new(
            self.secret_key,
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:16]
        
        signed_token = f"{token}.{signature}"
        
        with self._lock:
            self._tokens[token] = (session_id, expiry)
            self._cleanup_expired()
        
        return signed_token
    
    def validate_token(self, token: str, session_id: str = None) -> bool:
        """
        Validate a CSRF token
        
        Args:
            token: Token to validate
            session_id: Session identifier to check binding
            
        Returns:
            True if valid
            
        Raises:
            CSRFError if invalid
        """
        if not token or '.' not in token:
            raise CSRFError('Invalid token format')
        
        token_value, signature = token.rsplit('.', 1)
        
        with self._lock:
            stored = self._tokens.get(token_value)
            
            if not stored:
                raise CSRFError('Token not found or expired')
            
            stored_session, expiry = stored
            
            if time.time() > expiry:
                del self._tokens[token_value]
                raise CSRFError('Token expired')
            
            if session_id and stored_session and stored_session != session_id:
                raise CSRFError('Token session mismatch')
            
            # Verify signature
            payload = f"{token_value}:{expiry}"
            if stored_session:
                payload += f":{stored_session}"
            
            expected_sig = hmac.new(
                self.secret_key,
                payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()[:16]
            
            if not hmac.compare_digest(signature, expected_sig):
                raise CSRFError('Invalid token signature')
            
            # Remove used token (one-time use)
            del self._tokens[token_value]
            
            return True
    
    def _cleanup_expired(self):
        """Remove expired tokens"""
        now = time.time()
        self._tokens = {
            t: (s, e) for t, (s, e) in self._tokens.items()
            if e > now
        }


# ===========================================================================
# IP Allowlist
# ===========================================================================

class IPAllowlist:
    """
    IP address allowlist for access control
    
    Usage:
        allowlist = IPAllowlist(['192.168.1.0/24', '10.0.0.0/8'])
        
        if allowlist.is_allowed('192.168.1.100'):
            allow_access()
    """
    
    def __init__(self, allowed_ips: List[str] = None):
        self.allowed_ranges: List[tuple] = []
        self.allowed_single: set = set()
        
        if allowed_ips:
            for ip in allowed_ips:
                self.add(ip)
    
    def add(self, ip_or_range: str) -> None:
        """Add IP or CIDR range to allowlist"""
        if '/' in ip_or_range:
            # CIDR notation
            ip, prefix = ip_or_range.split('/')
            prefix = int(prefix)
            ip_int = self._ip_to_int(ip)
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            network = ip_int & mask
            self.allowed_ranges.append((network, mask))
        else:
            self.allowed_single.add(ip_or_range)
    
    def remove(self, ip_or_range: str) -> None:
        """Remove IP from allowlist"""
        if ip_or_range in self.allowed_single:
            self.allowed_single.remove(ip_or_range)
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is in allowlist"""
        # Check single IPs first
        if ip in self.allowed_single:
            return True
        
        # Check CIDR ranges
        ip_int = self._ip_to_int(ip)
        for network, mask in self.allowed_ranges:
            if (ip_int & mask) == network:
                return True
        
        return False
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer"""
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f'Invalid IP address: {ip}')
        
        result = 0
        for part in parts:
            result = (result << 8) | int(part)
        return result
    
    def clear(self) -> None:
        """Clear all entries"""
        self.allowed_ranges.clear()
        self.allowed_single.clear()


# ===========================================================================
# Session Manager
# ===========================================================================

@dataclass
class Session:
    """Session data container"""
    session_id: str
    user_id: str = None
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = None
    last_activity: float = field(default_factory=time.time)
    ip_address: str = None
    user_agent: str = None


class SessionManager:
    """
    Secure session management
    
    Usage:
        sessions = SessionManager(secret_key='your-secret')
        
        # Create session
        session = sessions.create(user_id='user123')
        
        # Get session
        session = sessions.get(session_id)
        
        # Validate
        if sessions.validate(session_id, ip_address='...'):
            ...
    """
    
    SESSION_LIFETIME = 86400  # 24 hours
    IDLE_TIMEOUT = 3600  # 1 hour idle timeout
    
    def __init__(
        self,
        secret_key: str,
        session_lifetime: int = None,
        idle_timeout: int = None
    ):
        self.secret_key = secret_key.encode('utf-8') if isinstance(secret_key, str) else secret_key
        self.session_lifetime = session_lifetime or self.SESSION_LIFETIME
        self.idle_timeout = idle_timeout or self.IDLE_TIMEOUT
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()
    
    def create(
        self,
        user_id: str = None,
        data: Dict[str, Any] = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Session:
        """Create a new session"""
        session_id = self._generate_session_id()
        now = time.time()
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            data=data or {},
            created_at=now,
            expires_at=now + self.session_lifetime,
            last_activity=now,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        with self._lock:
            self._sessions[session_id] = session
            self._cleanup_expired()
        
        return session
    
    def get(self, session_id: str, update_activity: bool = True) -> Optional[Session]:
        """Get session by ID"""
        with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return None
            
            now = time.time()
            
            # Check expiry
            if session.expires_at and now > session.expires_at:
                del self._sessions[session_id]
                return None
            
            # Check idle timeout
            if now - session.last_activity > self.idle_timeout:
                del self._sessions[session_id]
                return None
            
            if update_activity:
                session.last_activity = now
            
            return session
    
    def validate(
        self,
        session_id: str,
        ip_address: str = None,
        user_agent: str = None
    ) -> bool:
        """Validate session with optional binding checks"""
        session = self.get(session_id)
        
        if not session:
            return False
        
        # Optional IP binding
        if ip_address and session.ip_address:
            if ip_address != session.ip_address:
                return False
        
        # Optional user agent binding
        if user_agent and session.user_agent:
            if user_agent != session.user_agent:
                return False
        
        return True
    
    def update(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.data.update(data)
                session.last_activity = time.time()
                return True
            return False
    
    def destroy(self, session_id: str) -> bool:
        """Destroy a session"""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False
    
    def destroy_user_sessions(self, user_id: str) -> int:
        """Destroy all sessions for a user"""
        count = 0
        with self._lock:
            to_remove = [
                sid for sid, s in self._sessions.items()
                if s.user_id == user_id
            ]
            for sid in to_remove:
                del self._sessions[sid]
                count += 1
        return count
    
    def _generate_session_id(self) -> str:
        """Generate a secure session ID"""
        random_bytes = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        
        combined = random_bytes + timestamp
        return hashlib.sha256(combined).hexdigest()
    
    def _cleanup_expired(self):
        """Remove expired sessions"""
        now = time.time()
        to_remove = []
        
        for sid, session in self._sessions.items():
            if session.expires_at and now > session.expires_at:
                to_remove.append(sid)
            elif now - session.last_activity > self.idle_timeout:
                to_remove.append(sid)
        
        for sid in to_remove:
            del self._sessions[sid]


# ===========================================================================
# Security Headers Helper
# ===========================================================================

class SecurityHeaders:
    """
    Security headers for HTTP responses
    
    Usage:
        headers = SecurityHeaders()
        
        # Get all recommended headers
        for name, value in headers.get_all().items():
            response.headers[name] = value
    """
    
    def __init__(
        self,
        csp: str = None,
        hsts_max_age: int = 31536000,
        frame_options: str = 'DENY',
        content_type_nosniff: bool = True,
        xss_protection: bool = True,
        referrer_policy: str = 'strict-origin-when-cross-origin'
    ):
        self.csp = csp
        self.hsts_max_age = hsts_max_age
        self.frame_options = frame_options
        self.content_type_nosniff = content_type_nosniff
        self.xss_protection = xss_protection
        self.referrer_policy = referrer_policy
    
    def get_all(self) -> Dict[str, str]:
        """Get all security headers"""
        headers = {}
        
        # Content Security Policy
        if self.csp:
            headers['Content-Security-Policy'] = self.csp
        
        # HTTP Strict Transport Security
        if self.hsts_max_age:
            headers['Strict-Transport-Security'] = f'max-age={self.hsts_max_age}; includeSubDomains'
        
        # X-Frame-Options
        if self.frame_options:
            headers['X-Frame-Options'] = self.frame_options
        
        # X-Content-Type-Options
        if self.content_type_nosniff:
            headers['X-Content-Type-Options'] = 'nosniff'
        
        # X-XSS-Protection
        if self.xss_protection:
            headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer-Policy
        if self.referrer_policy:
            headers['Referrer-Policy'] = self.referrer_policy
        
        # Additional security headers
        headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        return headers


# ===========================================================================
# Secure Client - All-in-one secure API client
# ===========================================================================

class SecureClient:
    """
    Secure API client with all security features integrated
    
    Usage:
        client = SecureClient(
            api_key='your-api-key',
            api_secret='your-api-secret',
            webhook_secret='whsec_xxx'
        )
        
        # Make signed request
        response = client.request('POST', '/api/secure', data={'key': 'value'})
        
        # Verify webhook
        event = client.verify_webhook(payload, headers)
    """
    
    def __init__(
        self,
        api_key: str,
        api_secret: str,
        webhook_secret: str = None,
        encryption_key: str = None,
        base_url: str = 'https://api.adoaler.com'
    ):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url
        
        # Initialize components
        self.rate_limiter = RateLimiter()
        self.signer = HMACSigner(api_key, api_secret)
        
        if webhook_secret:
            self.webhook_verifier = WebhookVerifier(webhook_secret)
        else:
            self.webhook_verifier = None
        
        if encryption_key:
            self.encryptor = Encryptor(encryption_key)
        else:
            self.encryptor = None
        
        # Session for requests
        import requests
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Adoaler-Python-SDK/1.0 (Secure)',
            'X-Adoaler-Key': api_key,
        })
    
    def request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        params: Dict = None,
        sign: bool = True,
        encrypt: bool = False,
        rate_limit_type: str = 'api'
    ) -> Dict[str, Any]:
        """
        Make a secure API request
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body
            params: Query parameters
            sign: Whether to sign the request
            encrypt: Whether to encrypt sensitive data
            rate_limit_type: Rate limit category
        """
        # Check rate limit
        self.rate_limiter.acquire(rate_limit_type, block=True)
        
        url = f"{self.base_url}{endpoint}"
        headers = {}
        
        # Encrypt data if requested
        if encrypt and data and self.encryptor:
            data = {'_encrypted': self.encryptor.encrypt_dict(data)}
        
        # Sign request
        if sign:
            sign_headers = self.signer.sign_request(method, endpoint, data)
            headers.update(sign_headers)
        
        response = self._session.request(
            method,
            url,
            json=data,
            params=params,
            headers=headers
        )
        
        # Update rate limit from response headers
        if 'X-RateLimit-Remaining' in response.headers:
            # Could update internal state here
            pass
        
        if response.status_code >= 400:
            error_data = response.json() if response.content else {}
            from . import APIError
            raise APIError(
                error_data.get('error', {}).get('message', 'Request failed'),
                response.status_code
            )
        
        if response.status_code == 204:
            return {}
        
        return response.json()
    
    def verify_webhook(
        self,
        payload: bytes,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Verify and parse a webhook
        
        Args:
            payload: Raw request body
            headers: Request headers
            
        Returns:
            Parsed webhook event
        """
        if not self.webhook_verifier:
            raise SecurityException('Webhook secret not configured')
        
        signature = headers.get('X-Adoaler-Signature', '')
        timestamp = headers.get('X-Adoaler-Timestamp', '')
        
        self.webhook_verifier.verify(payload, signature, timestamp)
        
        return self.webhook_verifier.construct_event(payload)


# ===========================================================================
# Exports
# ===========================================================================

__all__ = [
    # Exceptions
    'SecurityException',
    'RateLimitExceeded',
    'SignatureError',
    'EncryptionError',
    'CSRFError',
    
    # Rate Limiting
    'RateLimiter',
    'RateLimitConfig',
    'rate_limited',
    
    # HMAC Signing
    'HMACSigner',
    
    # Webhooks
    'WebhookVerifier',
    
    # Encryption
    'Encryptor',
    
    # CSRF
    'CSRFProtection',
    
    # IP Allowlist
    'IPAllowlist',
    
    # Sessions
    'SessionManager',
    'Session',
    
    # Headers
    'SecurityHeaders',
    
    # All-in-one
    'SecureClient',
]
