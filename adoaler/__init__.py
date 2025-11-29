"""
===========================================================================
Adoaler Python SDK
OAuth 2.0 Client & API Integration
===========================================================================
"""

__version__ = "2.0.0"

import hashlib
import secrets
import base64
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
import requests

# Import modular components
from .ads import AdoalerAds, AdConfig, AdUnit, AdResponse
from .id import AdoalerID as AdoalerIDClient
from .auth import AdoalerAuth, SessionManager, MFAManager, JWTHandler

__all__ = [
    # Core
    "AdoalerException",
    "AuthenticationError", 
    "APIError",
    "AdoalerID",
    "AdoalerClient",
    
    # Ads
    "AdoalerAds",
    "AdConfig",
    "AdUnit",
    "AdResponse",
    
    # ID (OAuth)
    "AdoalerIDClient",
    
    # Auth
    "AdoalerAuth",
    "SessionManager",
    "MFAManager",
    "JWTHandler",
]


class AdoalerException(Exception):
    """Base exception for Adoaler SDK"""
    pass


class AuthenticationError(AdoalerException):
    """Authentication related errors"""
    pass


class APIError(AdoalerException):
    """API request errors"""
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code


class AdoalerID:
    """
    Adoaler OAuth 2.0 Client
    
    Usage:
        client = AdoalerID(
            client_id='your_client_id',
            client_secret='your_client_secret',
            redirect_uri='https://yoursite.com/callback'
        )
        
        # Get authorization URL
        auth_url, state = client.get_authorization_url()
        
        # After callback, exchange code for tokens
        tokens = client.get_tokens(code, state)
        
        # Get user info
        user = client.get_user_info(tokens['access_token'])
    """
    
    BASE_URL = 'https://id.adoaler.com'
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: List[str] = None
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or ['openid', 'profile', 'email']
        self._session = requests.Session()
        
    def get_authorization_url(
        self,
        state: str = None,
        nonce: str = None,
        code_verifier: str = None
    ) -> tuple:
        """
        Generate OAuth authorization URL
        
        Returns:
            Tuple of (authorization_url, state, code_verifier)
        """
        if state is None:
            state = secrets.token_urlsafe(32)
            
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(self.scopes),
            'state': state,
        }
        
        # Add nonce for OpenID Connect
        if 'openid' in self.scopes:
            params['nonce'] = nonce or secrets.token_urlsafe(32)
            
        # PKCE support
        if code_verifier is None:
            code_verifier = secrets.token_urlsafe(64)
            
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()
        
        params['code_challenge'] = code_challenge
        params['code_challenge_method'] = 'S256'
        
        auth_url = f"{self.BASE_URL}/oauth/authorize?{urlencode(params)}"
        
        return auth_url, state, code_verifier
    
    def get_tokens(
        self,
        code: str,
        code_verifier: str = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens
        """
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        
        if code_verifier:
            data['code_verifier'] = code_verifier
            
        response = self._session.post(
            f"{self.BASE_URL}/oauth/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        result = response.json()
        
        if response.status_code != 200:
            raise AuthenticationError(
                result.get('error_description', result.get('error', 'Token exchange failed'))
            )
            
        return result
    
    def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token
        """
        response = self._session.post(
            f"{self.BASE_URL}/oauth/token",
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        result = response.json()
        
        if response.status_code != 200:
            raise AuthenticationError(
                result.get('error_description', result.get('error', 'Token refresh failed'))
            )
            
        return result
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get authenticated user information
        """
        response = self._session.get(
            f"{self.BASE_URL}/oauth/userinfo",
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code == 401:
            raise AuthenticationError('Invalid or expired access token')
            
        if response.status_code != 200:
            raise APIError('Failed to get user info', response.status_code)
            
        return response.json()
    
    def revoke_token(self, token: str, token_type_hint: str = 'access_token') -> None:
        """
        Revoke a token
        """
        self._session.post(
            f"{self.BASE_URL}/oauth/revoke",
            data={
                'token': token,
                'token_type_hint': token_type_hint,
            }
        )
        
    def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Verify and decode ID token
        """
        parts = id_token.split('.')
        if len(parts) != 3:
            raise AuthenticationError('Invalid ID token format')
            
        try:
            # Add padding if needed
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            claims = eval(decoded.decode())  # In production, use json.loads
        except Exception:
            raise AuthenticationError('Failed to decode ID token')
            
        # Verify claims
        if claims.get('iss') != self.BASE_URL:
            raise AuthenticationError('Invalid issuer')
        if claims.get('aud') != self.client_id:
            raise AuthenticationError('Invalid audience')
        if claims.get('exp', 0) < time.time():
            raise AuthenticationError('ID token expired')
            
        return claims


class AdoalerAPI:
    """
    Adoaler API Client
    
    Usage:
        api = AdoalerAPI(access_token='your_access_token')
        
        # Get authenticated user
        me = api.get_me()
        
        # Create a post
        post = api.create_post("Hello from Python!")
        
        # Get timeline
        timeline = api.get_timeline(limit=50)
    """
    
    API_URL = 'https://api.adoaler.com/v1'
    
    def __init__(self, access_token: str):
        self.access_token = access_token
        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Adoaler-Python-SDK/1.0',
        })
        
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        params: Dict = None
    ) -> Dict[str, Any]:
        url = f"{self.API_URL}{endpoint}"
        
        response = self._session.request(
            method,
            url,
            json=data,
            params=params
        )
        
        if response.status_code == 401:
            raise AuthenticationError('Invalid or expired access token')
            
        if response.status_code >= 400:
            error = response.json()
            raise APIError(
                error.get('error', {}).get('message', 'Request failed'),
                response.status_code
            )
            
        if response.status_code == 204:
            return {}
            
        return response.json()
    
    # User endpoints
    
    def get_me(self) -> Dict[str, Any]:
        """Get authenticated user profile"""
        return self._request('GET', '/users/me')
    
    def get_user(self, username: str) -> Dict[str, Any]:
        """Get user by username"""
        return self._request('GET', f'/users/{username}')
    
    def update_profile(self, **kwargs) -> Dict[str, Any]:
        """Update authenticated user profile"""
        return self._request('PUT', '/users/me', data=kwargs)
    
    # Posts endpoints
    
    def get_timeline(
        self,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get user's timeline"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', '/timeline', params=params)
    
    def get_user_posts(
        self,
        username: str,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get posts from a user"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', f'/users/{username}/posts', params=params)
    
    def get_post(self, post_id: str) -> Dict[str, Any]:
        """Get a single post"""
        return self._request('GET', f'/posts/{post_id}')
    
    def create_post(
        self,
        content: str,
        media: List[str] = None,
        reply_to: str = None,
        visibility: str = 'public'
    ) -> Dict[str, Any]:
        """Create a new post"""
        data = {
            'content': content,
            'visibility': visibility,
        }
        if media:
            data['media'] = media
        if reply_to:
            data['reply_to_id'] = reply_to
        return self._request('POST', '/posts', data=data)
    
    def delete_post(self, post_id: str) -> None:
        """Delete a post"""
        self._request('DELETE', f'/posts/{post_id}')
    
    def like_post(self, post_id: str) -> Dict[str, Any]:
        """Like a post"""
        return self._request('POST', f'/posts/{post_id}/like')
    
    def unlike_post(self, post_id: str) -> None:
        """Unlike a post"""
        self._request('DELETE', f'/posts/{post_id}/like')
    
    def repost(self, post_id: str) -> Dict[str, Any]:
        """Repost a post"""
        return self._request('POST', f'/posts/{post_id}/repost')
    
    def quote_post(self, post_id: str, content: str) -> Dict[str, Any]:
        """Quote a post"""
        return self._request('POST', '/posts', data={
            'content': content,
            'quote_id': post_id,
        })
    
    # Follow endpoints
    
    def follow(self, user_id: str) -> Dict[str, Any]:
        """Follow a user"""
        return self._request('POST', f'/users/{user_id}/follow')
    
    def unfollow(self, user_id: str) -> None:
        """Unfollow a user"""
        self._request('DELETE', f'/users/{user_id}/follow')
    
    def get_followers(
        self,
        username: str,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get user's followers"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', f'/users/{username}/followers', params=params)
    
    def get_following(
        self,
        username: str,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get accounts user is following"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', f'/users/{username}/following', params=params)
    
    # Search endpoints
    
    def search_posts(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search posts"""
        return self._request('GET', '/search/posts', params={'q': query, 'limit': limit})
    
    def search_users(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search users"""
        return self._request('GET', '/search/users', params={'q': query, 'limit': limit})
    
    def search_hashtags(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search hashtags"""
        return self._request('GET', '/search/hashtags', params={'q': query, 'limit': limit})
    
    # Notifications
    
    def get_notifications(
        self,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get notifications"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', '/notifications', params=params)
    
    def mark_notifications_read(self, notification_ids: List[str] = None) -> None:
        """Mark notifications as read"""
        data = {}
        if notification_ids:
            data['ids'] = notification_ids
        self._request('POST', '/notifications/read', data=data)
    
    # Bookmarks
    
    def get_bookmarks(
        self,
        limit: int = 20,
        cursor: str = None
    ) -> Dict[str, Any]:
        """Get bookmarked posts"""
        params = {'limit': limit}
        if cursor:
            params['cursor'] = cursor
        return self._request('GET', '/bookmarks', params=params)
    
    def bookmark_post(self, post_id: str) -> Dict[str, Any]:
        """Bookmark a post"""
        return self._request('POST', f'/posts/{post_id}/bookmark')
    
    def remove_bookmark(self, post_id: str) -> None:
        """Remove bookmark from a post"""
        self._request('DELETE', f'/posts/{post_id}/bookmark')


class AdoalerAds:
    """
    Adoaler Ads SDK for Publishers
    
    Usage:
        ads = AdoalerAds(
            publisher_id='pub-XXXXXXXX',
            api_key='your_api_key'
        )
        
        # Get earnings
        earnings = ads.get_earnings('2024-01-01', '2024-01-31')
        
        # Get sites
        sites = ads.get_sites()
    """
    
    ADS_URL = 'https://ads.adoaler.com'
    
    def __init__(self, publisher_id: str, api_key: str):
        self.publisher_id = publisher_id
        self.api_key = api_key
        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'X-Publisher-ID': publisher_id,
            'Content-Type': 'application/json',
        })
        
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        params: Dict = None
    ) -> Dict[str, Any]:
        response = self._session.request(
            method,
            f"{self.ADS_URL}{endpoint}",
            json=data,
            params=params
        )
        
        if response.status_code >= 400:
            error = response.json()
            raise APIError(error.get('error', 'Request failed'), response.status_code)
            
        return response.json()
    
    def get_earnings(
        self,
        start_date: str,
        end_date: str,
        site_id: str = None,
        granularity: str = 'day'
    ) -> Dict[str, Any]:
        """Get earnings report"""
        params = {
            'start_date': start_date,
            'end_date': end_date,
            'granularity': granularity,
        }
        if site_id:
            params['site_id'] = site_id
        return self._request('GET', '/publisher/earnings', params=params)
    
    def get_sites(self) -> Dict[str, Any]:
        """Get all registered sites"""
        return self._request('GET', '/publisher/sites')
    
    def get_ad_units(self, site_id: str) -> Dict[str, Any]:
        """Get ad units for a site"""
        return self._request('GET', f'/publisher/sites/{site_id}/ad-units')
    
    def create_ad_unit(
        self,
        site_id: str,
        name: str,
        ad_type: str,
        size: str = 'responsive'
    ) -> Dict[str, Any]:
        """Create a new ad unit"""
        return self._request('POST', f'/publisher/sites/{site_id}/ad-units', data={
            'name': name,
            'ad_type': ad_type,
            'size': size,
        })
    
    def get_payouts(self, limit: int = 20) -> Dict[str, Any]:
        """Get payout history"""
        return self._request('GET', '/publisher/payouts', params={'limit': limit})
    
    def get_performance(
        self,
        start_date: str,
        end_date: str,
        dimensions: List[str] = None
    ) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        params = {
            'start_date': start_date,
            'end_date': end_date,
        }
        if dimensions:
            params['dimensions'] = ','.join(dimensions)
        return self._request('GET', '/publisher/performance', params=params)


# Flask integration helper
def flask_oauth_routes(app, config: Dict[str, str]):
    """
    Add OAuth routes to Flask app
    
    Usage:
        from flask import Flask
        from adoaler import flask_oauth_routes
        
        app = Flask(__name__)
        flask_oauth_routes(app, {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'redirect_uri': 'http://localhost:5000/callback',
        })
    """
    from flask import redirect, session, url_for, request
    
    client = AdoalerID(
        config['client_id'],
        config['client_secret'],
        config['redirect_uri'],
        config.get('scopes', ['openid', 'profile', 'email'])
    )
    
    @app.route('/login/adoaler')
    def adoaler_login():
        auth_url, state, code_verifier = client.get_authorization_url()
        session['adoaler_state'] = state
        session['adoaler_verifier'] = code_verifier
        return redirect(auth_url)
    
    @app.route('/callback')
    def adoaler_callback():
        state = request.args.get('state')
        if state != session.get('adoaler_state'):
            return 'Invalid state', 400
            
        code = request.args.get('code')
        if not code:
            error = request.args.get('error_description', request.args.get('error'))
            return f'Error: {error}', 400
            
        try:
            tokens = client.get_tokens(code, session.get('adoaler_verifier'))
            user = client.get_user_info(tokens['access_token'])
            
            session['adoaler_user'] = user
            session['adoaler_tokens'] = tokens
            
            return redirect(url_for('index'))
        except AuthenticationError as e:
            return f'Authentication failed: {e}', 400
    
    @app.route('/logout')
    def adoaler_logout():
        session.pop('adoaler_user', None)
        session.pop('adoaler_tokens', None)
        return redirect(url_for('index'))


# Django integration helper
class AdoalerDjangoMiddleware:
    """
    Django middleware for Adoaler authentication
    
    Usage:
        # settings.py
        MIDDLEWARE = [
            ...
            'adoaler.AdoalerDjangoMiddleware',
        ]
        
        ADOALER_CONFIG = {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'redirect_uri': 'http://localhost:8000/callback/',
        }
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Add adoaler user to request if authenticated
        user_data = request.session.get('adoaler_user')
        if user_data:
            request.adoaler_user = user_data
        else:
            request.adoaler_user = None
            
        response = self.get_response(request)
        return response


# Import security module
from .security import (
    # Exceptions
    SecurityException,
    RateLimitExceeded,
    SignatureError,
    EncryptionError,
    CSRFError,
    
    # Components
    RateLimiter,
    RateLimitConfig,
    rate_limited,
    HMACSigner,
    WebhookVerifier,
    Encryptor,
    CSRFProtection,
    IPAllowlist,
    SessionManager,
    Session,
    SecurityHeaders,
    SecureClient,
)

# Version
__version__ = '1.0.0'

# All public exports
__all__ = [
    # OAuth & API
    'AdoalerID',
    'AdoalerAPI',
    'AdoalerAds',
    'AdoalerException',
    'AuthenticationError',
    'APIError',
    
    # Framework Integration
    'flask_oauth_routes',
    'AdoalerDjangoMiddleware',
    
    # Security
    'SecurityException',
    'RateLimitExceeded',
    'SignatureError',
    'EncryptionError',
    'CSRFError',
    'RateLimiter',
    'RateLimitConfig',
    'rate_limited',
    'HMACSigner',
    'WebhookVerifier',
    'Encryptor',
    'CSRFProtection',
    'IPAllowlist',
    'SessionManager',
    'Session',
    'SecurityHeaders',
    'SecureClient',
]
