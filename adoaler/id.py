"""
Adoaler ID SDK - Python
"Login com Adoaler" - OAuth 2.0 / OpenID Connect Client
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class AdoalerIDConfig:
    """Configuração do Adoaler ID"""
    client_id: str
    client_secret: Optional[str] = None  # Para aplicações confidenciais
    redirect_uri: str = ""
    scopes: List[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    base_url: str = "https://id.adoaler.com"
    use_pkce: bool = True
    timeout: int = 30


@dataclass
class AdoalerUser:
    """Usuário autenticado"""
    sub: str  # Subject (ID único)
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    picture: Optional[str] = None
    profile: Optional[str] = None
    locale: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_verified: bool = False
    address: Optional[Dict[str, str]] = None
    updated_at: Optional[int] = None
    raw_claims: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenSet:
    """Conjunto de tokens"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    expires_at: Optional[int] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: str = ""
    
    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = int(time.time()) + self.expires_in
    
    def is_expired(self) -> bool:
        """Verifica se o token expirou"""
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at - 60  # 60s de margem


@dataclass 
class AuthResult:
    """Resultado da autenticação"""
    success: bool
    user: Optional[AdoalerUser] = None
    tokens: Optional[TokenSet] = None
    error: Optional[str] = None
    error_description: Optional[str] = None


class PKCE:
    """Utilitários PKCE (Proof Key for Code Exchange)"""
    
    @staticmethod
    def generate_verifier(length: int = 64) -> str:
        """Gera code verifier"""
        return secrets.token_urlsafe(length)[:length]
    
    @staticmethod
    def generate_challenge(verifier: str) -> str:
        """Gera code challenge a partir do verifier"""
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    
    @staticmethod
    def generate_state() -> str:
        """Gera state para CSRF protection"""
        return secrets.token_urlsafe(32)


class AdoalerID:
    """
    Cliente do Adoaler ID (OAuth 2.0 / OpenID Connect)
    
    Exemplo de uso (Web Application):
        # Configuração
        adoaler_id = AdoalerID(AdoalerIDConfig(
            client_id="seu_client_id",
            client_secret="seu_client_secret",
            redirect_uri="https://seu-app.com/callback"
        ))
        
        # Gerar URL de autorização
        auth_url, state = adoaler_id.get_authorization_url()
        # Redirecionar usuário para auth_url
        
        # No callback, trocar código por tokens
        result = await adoaler_id.exchange_code(code, state)
        if result.success:
            user = result.user
            print(f"Bem-vindo, {user.name}!")
    
    Exemplo de uso (Mobile/SPA com PKCE):
        adoaler_id = AdoalerID(AdoalerIDConfig(
            client_id="seu_client_id",
            redirect_uri="myapp://callback",
            use_pkce=True
        ))
        
        # Gerar URL com PKCE
        auth_url, state, verifier = adoaler_id.get_authorization_url_pkce()
        # Armazenar verifier de forma segura
        
        # No callback
        result = await adoaler_id.exchange_code_pkce(code, verifier)
    """
    
    def __init__(self, config: AdoalerIDConfig):
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=config.timeout,
        )
        self._state_store: Dict[str, Dict[str, Any]] = {}
    
    async def close(self):
        """Fecha o cliente HTTP"""
        await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    # -------------------------------------------------------------------------
    # Authorization URL
    # -------------------------------------------------------------------------
    
    def get_authorization_url(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> tuple[str, str]:
        """
        Gera URL de autorização (sem PKCE)
        
        Returns:
            Tuple de (url, state)
        """
        state = state or PKCE.generate_state()
        nonce = nonce or secrets.token_urlsafe(16)
        
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint
        if extra_params:
            params.update(extra_params)
        
        self._state_store[state] = {"nonce": nonce}
        
        url = f"{self.config.base_url}/oauth2/authorize?{urllib.parse.urlencode(params)}"
        return url, state
    
    def get_authorization_url_pkce(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        **kwargs
    ) -> tuple[str, str, str]:
        """
        Gera URL de autorização com PKCE
        
        Returns:
            Tuple de (url, state, code_verifier)
        """
        state = state or PKCE.generate_state()
        nonce = nonce or secrets.token_urlsafe(16)
        verifier = PKCE.generate_verifier()
        challenge = PKCE.generate_challenge(verifier)
        
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        
        self._state_store[state] = {"nonce": nonce, "verifier": verifier}
        
        url = f"{self.config.base_url}/oauth2/authorize?{urllib.parse.urlencode(params)}"
        return url, state, verifier
    
    # -------------------------------------------------------------------------
    # Token Exchange
    # -------------------------------------------------------------------------
    
    async def exchange_code(
        self,
        code: str,
        state: Optional[str] = None,
    ) -> AuthResult:
        """
        Troca código de autorização por tokens
        
        Args:
            code: Código de autorização
            state: State para validação CSRF
            
        Returns:
            AuthResult com user e tokens
        """
        # Validar state se fornecido
        if state and state not in self._state_store:
            return AuthResult(
                success=False,
                error="invalid_state",
                error_description="State inválido ou expirado"
            )
        
        data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "code": code,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        
        return await self._token_request(data, state)
    
    async def exchange_code_pkce(
        self,
        code: str,
        code_verifier: str,
        state: Optional[str] = None,
    ) -> AuthResult:
        """
        Troca código por tokens usando PKCE
        
        Args:
            code: Código de autorização
            code_verifier: PKCE code verifier
            state: State para validação
            
        Returns:
            AuthResult com user e tokens
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
        }
        
        return await self._token_request(data, state)
    
    async def refresh_tokens(self, refresh_token: str) -> AuthResult:
        """
        Renova tokens usando refresh token
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            AuthResult com novos tokens
        """
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": refresh_token,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        
        return await self._token_request(data)
    
    async def _token_request(
        self, 
        data: Dict[str, str],
        state: Optional[str] = None
    ) -> AuthResult:
        """Executa requisição de token"""
        try:
            response = await self._client.post(
                "/oauth2/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_data = response.json()
                return AuthResult(
                    success=False,
                    error=error_data.get("error", "unknown_error"),
                    error_description=error_data.get("error_description")
                )
            
            token_data = response.json()
            
            tokens = TokenSet(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=token_data.get("refresh_token"),
                id_token=token_data.get("id_token"),
                scope=token_data.get("scope", ""),
            )
            
            # Buscar informações do usuário
            user = await self._get_userinfo(tokens.access_token)
            
            # Limpar state store
            if state and state in self._state_store:
                del self._state_store[state]
            
            return AuthResult(success=True, user=user, tokens=tokens)
            
        except Exception as e:
            return AuthResult(
                success=False,
                error="request_failed",
                error_description=str(e)
            )
    
    # -------------------------------------------------------------------------
    # User Info
    # -------------------------------------------------------------------------
    
    async def _get_userinfo(self, access_token: str) -> AdoalerUser:
        """Obtém informações do usuário"""
        response = await self._client.get(
            "/oauth2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        data = response.json()
        
        return AdoalerUser(
            sub=data["sub"],
            name=data.get("name"),
            preferred_username=data.get("preferred_username"),
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            picture=data.get("picture"),
            profile=data.get("profile"),
            locale=data.get("locale"),
            phone_number=data.get("phone_number"),
            phone_number_verified=data.get("phone_number_verified", False),
            address=data.get("address"),
            updated_at=data.get("updated_at"),
            raw_claims=data,
        )
    
    async def get_userinfo(self, access_token: str) -> Optional[AdoalerUser]:
        """
        Obtém informações do usuário com um access token
        
        Args:
            access_token: Access token válido
            
        Returns:
            AdoalerUser ou None se falhar
        """
        try:
            return await self._get_userinfo(access_token)
        except:
            return None
    
    # -------------------------------------------------------------------------
    # Token Validation
    # -------------------------------------------------------------------------
    
    async def validate_token(self, access_token: str) -> Dict[str, Any]:
        """
        Valida um access token via introspection
        
        Args:
            access_token: Token a validar
            
        Returns:
            Dict com informações do token
        """
        data = {
            "token": access_token,
            "client_id": self.config.client_id,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        
        try:
            response = await self._client.post(
                "/oauth2/introspect",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            return response.json()
        except:
            return {"active": False}
    
    async def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoga um token
        
        Args:
            token: Token a revogar
            token_type: 'access_token' ou 'refresh_token'
            
        Returns:
            True se revogado com sucesso
        """
        data = {
            "token": token,
            "token_type_hint": token_type,
            "client_id": self.config.client_id,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        
        try:
            response = await self._client.post(
                "/oauth2/revoke",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            return response.status_code == 200
        except:
            return False
    
    # -------------------------------------------------------------------------
    # Logout
    # -------------------------------------------------------------------------
    
    def get_logout_url(
        self,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """
        Gera URL de logout
        
        Args:
            id_token_hint: ID token (opcional)
            post_logout_redirect_uri: URL de redirecionamento pós-logout
            state: State parameter
            
        Returns:
            URL de logout
        """
        params = {}
        
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        
        if params:
            return f"{self.config.base_url}/oauth2/logout?{urllib.parse.urlencode(params)}"
        return f"{self.config.base_url}/oauth2/logout"


# Versão síncrona
class AdoalerIDSync:
    """Versão síncrona do cliente Adoaler ID"""
    
    def __init__(self, config: AdoalerIDConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            timeout=config.timeout,
        )
        self._state_store: Dict[str, Dict[str, Any]] = {}
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def get_authorization_url(self, **kwargs) -> tuple[str, str]:
        """Gera URL de autorização"""
        state = kwargs.get("state") or PKCE.generate_state()
        nonce = secrets.token_urlsafe(16)
        
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        
        url = f"{self.config.base_url}/oauth2/authorize?{urllib.parse.urlencode(params)}"
        return url, state
    
    def exchange_code(self, code: str, **kwargs) -> AuthResult:
        """Troca código por tokens (síncrono)"""
        data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "code": code,
        }
        
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        
        try:
            response = self._client.post(
                "/oauth2/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_data = response.json()
                return AuthResult(
                    success=False,
                    error=error_data.get("error"),
                    error_description=error_data.get("error_description")
                )
            
            token_data = response.json()
            tokens = TokenSet(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 3600),
                refresh_token=token_data.get("refresh_token"),
                id_token=token_data.get("id_token"),
                scope=token_data.get("scope", ""),
            )
            
            # Get user info
            user_response = self._client.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {tokens.access_token}"}
            )
            user_data = user_response.json()
            
            user = AdoalerUser(
                sub=user_data["sub"],
                name=user_data.get("name"),
                email=user_data.get("email"),
                email_verified=user_data.get("email_verified", False),
                picture=user_data.get("picture"),
                raw_claims=user_data,
            )
            
            return AuthResult(success=True, user=user, tokens=tokens)
            
        except Exception as e:
            return AuthResult(
                success=False,
                error="request_failed",
                error_description=str(e)
            )
