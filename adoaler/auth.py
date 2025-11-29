"""
Adoaler Auth SDK - Python
Autenticação e gerenciamento de sessões
"""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

import httpx


class AuthProvider(Enum):
    """Provedores de autenticação suportados"""
    EMAIL_PASSWORD = "email_password"
    PHONE_OTP = "phone_otp"
    EMAIL_OTP = "email_otp"
    MAGIC_LINK = "magic_link"
    GOOGLE = "google"
    FACEBOOK = "facebook"
    APPLE = "apple"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    ADOALER_ID = "adoaler_id"


class MFAMethod(Enum):
    """Métodos de MFA suportados"""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    SECURITY_KEY = "security_key"


@dataclass
class AuthConfig:
    """Configuração do SDK de Auth"""
    api_key: str
    project_id: str
    api_url: str = "https://auth.adoaler.com"
    timeout: int = 30
    auto_refresh: bool = True
    persist_session: bool = True
    storage_key: str = "adoaler_auth_session"
    debug: bool = False


@dataclass
class User:
    """Usuário autenticado"""
    id: str
    email: Optional[str] = None
    phone: Optional[str] = None
    email_verified: bool = False
    phone_verified: bool = False
    display_name: Optional[str] = None
    photo_url: Optional[str] = None
    provider: Optional[str] = None
    providers: List[str] = field(default_factory=list)
    mfa_enabled: bool = False
    created_at: Optional[datetime] = None
    last_sign_in: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    custom_claims: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """Sessão de autenticação"""
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    token_type: str = "Bearer"
    user: Optional[User] = None
    
    def is_expired(self) -> bool:
        """Verifica se a sessão expirou"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at - timedelta(minutes=1)


@dataclass
class AuthResponse:
    """Resposta de operação de autenticação"""
    success: bool
    user: Optional[User] = None
    session: Optional[Session] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    requires_mfa: bool = False
    mfa_token: Optional[str] = None
    available_mfa_methods: List[str] = field(default_factory=list)


@dataclass
class SignUpOptions:
    """Opções para registro"""
    email: Optional[str] = None
    password: Optional[str] = None
    phone: Optional[str] = None
    display_name: Optional[str] = None
    photo_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    email_redirect_url: Optional[str] = None
    captcha_token: Optional[str] = None


@dataclass
class SignInOptions:
    """Opções para login"""
    email: Optional[str] = None
    password: Optional[str] = None
    phone: Optional[str] = None
    otp: Optional[str] = None
    provider: Optional[AuthProvider] = None
    redirect_url: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    captcha_token: Optional[str] = None


class AdoalerAuth:
    """
    Cliente do Adoaler Auth SDK
    
    Exemplo de uso:
        auth = AdoalerAuth(AuthConfig(
            api_key="sua_api_key",
            project_id="seu_project_id"
        ))
        
        # Registrar novo usuário
        result = await auth.sign_up(SignUpOptions(
            email="user@example.com",
            password="senha_segura",
            display_name="João Silva"
        ))
        
        # Login com email/senha
        result = await auth.sign_in(SignInOptions(
            email="user@example.com",
            password="senha_segura"
        ))
        
        if result.success:
            user = result.user
            print(f"Bem-vindo, {user.display_name}!")
        
        # Login com OAuth
        url = auth.get_oauth_url(AuthProvider.GOOGLE)
        # Redirecionar usuário
    """
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.api_url,
            timeout=config.timeout,
            headers={
                "X-API-Key": config.api_key,
                "X-Project-ID": config.project_id,
                "Content-Type": "application/json",
            }
        )
        self._session: Optional[Session] = None
        self._auth_state_listeners: List[Callable[[Optional[User]], None]] = []
    
    async def close(self):
        """Fecha o cliente HTTP"""
        await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    def _log(self, message: str, *args):
        """Log de debug"""
        if self.config.debug:
            print(f"[AdoalerAuth] {message}", *args)
    
    # -------------------------------------------------------------------------
    # Event Listeners
    # -------------------------------------------------------------------------
    
    def on_auth_state_change(
        self, 
        callback: Callable[[Optional[User]], None]
    ) -> Callable[[], None]:
        """
        Registra listener para mudanças de estado de autenticação
        
        Args:
            callback: Função chamada quando o estado muda
            
        Returns:
            Função para remover o listener
        """
        self._auth_state_listeners.append(callback)
        
        def unsubscribe():
            self._auth_state_listeners.remove(callback)
        
        return unsubscribe
    
    def _notify_auth_state_change(self, user: Optional[User]):
        """Notifica listeners sobre mudança de estado"""
        for listener in self._auth_state_listeners:
            try:
                listener(user)
            except Exception as e:
                self._log(f"Error in auth state listener: {e}")
    
    # -------------------------------------------------------------------------
    # Sign Up
    # -------------------------------------------------------------------------
    
    async def sign_up(self, options: SignUpOptions) -> AuthResponse:
        """
        Registra um novo usuário
        
        Args:
            options: Opções de registro
            
        Returns:
            AuthResponse com resultado
        """
        payload = {
            "email": options.email,
            "password": options.password,
            "phone": options.phone,
            "display_name": options.display_name,
            "photo_url": options.photo_url,
            "metadata": options.metadata,
            "email_redirect_url": options.email_redirect_url,
            "captcha_token": options.captcha_token,
        }
        
        # Remover campos None
        payload = {k: v for k, v in payload.items() if v is not None}
        
        try:
            response = await self._client.post("/v1/auth/signup", json=payload)
            return self._handle_auth_response(response)
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def sign_up_with_email(
        self, 
        email: str, 
        password: str,
        **kwargs
    ) -> AuthResponse:
        """Registra com email e senha"""
        return await self.sign_up(SignUpOptions(
            email=email,
            password=password,
            **kwargs
        ))
    
    async def sign_up_with_phone(
        self, 
        phone: str,
        **kwargs
    ) -> AuthResponse:
        """Registra com telefone (envia OTP)"""
        return await self.sign_up(SignUpOptions(phone=phone, **kwargs))
    
    # -------------------------------------------------------------------------
    # Sign In
    # -------------------------------------------------------------------------
    
    async def sign_in(self, options: SignInOptions) -> AuthResponse:
        """
        Faz login de um usuário
        
        Args:
            options: Opções de login
            
        Returns:
            AuthResponse com resultado
        """
        payload = {
            "email": options.email,
            "password": options.password,
            "phone": options.phone,
            "otp": options.otp,
            "provider": options.provider.value if options.provider else None,
            "captcha_token": options.captcha_token,
        }
        
        payload = {k: v for k, v in payload.items() if v is not None}
        
        try:
            response = await self._client.post("/v1/auth/signin", json=payload)
            result = self._handle_auth_response(response)
            
            if result.success and result.session:
                self._session = result.session
                self._notify_auth_state_change(result.user)
            
            return result
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def sign_in_with_email(
        self, 
        email: str, 
        password: str
    ) -> AuthResponse:
        """Login com email e senha"""
        return await self.sign_in(SignInOptions(email=email, password=password))
    
    async def sign_in_with_otp(
        self, 
        phone: str, 
        otp: str
    ) -> AuthResponse:
        """Login com OTP de telefone"""
        return await self.sign_in(SignInOptions(phone=phone, otp=otp))
    
    async def send_otp(
        self, 
        phone: Optional[str] = None,
        email: Optional[str] = None,
    ) -> AuthResponse:
        """
        Envia OTP para telefone ou email
        
        Args:
            phone: Número de telefone
            email: Endereço de email
            
        Returns:
            AuthResponse indicando sucesso/falha
        """
        payload = {}
        if phone:
            payload["phone"] = phone
        if email:
            payload["email"] = email
        
        try:
            response = await self._client.post("/v1/auth/otp/send", json=payload)
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(
                success=False,
                error=data.get("error"),
                error_code=data.get("error_code")
            )
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def send_magic_link(
        self, 
        email: str,
        redirect_url: Optional[str] = None
    ) -> AuthResponse:
        """
        Envia magic link para email
        
        Args:
            email: Endereço de email
            redirect_url: URL de redirecionamento após login
            
        Returns:
            AuthResponse indicando sucesso/falha
        """
        try:
            response = await self._client.post(
                "/v1/auth/magic-link",
                json={"email": email, "redirect_url": redirect_url}
            )
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(
                success=False,
                error=data.get("error"),
                error_code=data.get("error_code")
            )
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    # -------------------------------------------------------------------------
    # OAuth
    # -------------------------------------------------------------------------
    
    def get_oauth_url(
        self, 
        provider: AuthProvider,
        redirect_url: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ) -> str:
        """
        Gera URL para login OAuth
        
        Args:
            provider: Provedor OAuth
            redirect_url: URL de callback
            scopes: Escopos adicionais
            
        Returns:
            URL de autorização
        """
        import urllib.parse
        
        params = {
            "provider": provider.value,
            "api_key": self.config.api_key,
            "project_id": self.config.project_id,
        }
        
        if redirect_url:
            params["redirect_url"] = redirect_url
        if scopes:
            params["scopes"] = ",".join(scopes)
        
        return f"{self.config.api_url}/v1/auth/oauth?{urllib.parse.urlencode(params)}"
    
    async def handle_oauth_callback(
        self, 
        code: str,
        state: Optional[str] = None
    ) -> AuthResponse:
        """
        Processa callback OAuth
        
        Args:
            code: Código de autorização
            state: State parameter
            
        Returns:
            AuthResponse com resultado
        """
        try:
            response = await self._client.post(
                "/v1/auth/oauth/callback",
                json={"code": code, "state": state}
            )
            result = self._handle_auth_response(response)
            
            if result.success and result.session:
                self._session = result.session
                self._notify_auth_state_change(result.user)
            
            return result
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    # -------------------------------------------------------------------------
    # MFA
    # -------------------------------------------------------------------------
    
    async def enroll_mfa(self, method: MFAMethod) -> Dict[str, Any]:
        """
        Inicia enrollment de MFA
        
        Args:
            method: Método de MFA
            
        Returns:
            Dict com dados de enrollment (ex: TOTP secret, QR code)
        """
        if not self._session:
            return {"error": "Not authenticated"}
        
        try:
            response = await self._client.post(
                "/v1/auth/mfa/enroll",
                json={"method": method.value},
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    async def verify_mfa_enrollment(
        self, 
        method: MFAMethod, 
        code: str,
        enrollment_id: str
    ) -> AuthResponse:
        """
        Verifica enrollment de MFA
        
        Args:
            method: Método de MFA
            code: Código de verificação
            enrollment_id: ID do enrollment
            
        Returns:
            AuthResponse
        """
        if not self._session:
            return AuthResponse(success=False, error="Not authenticated")
        
        try:
            response = await self._client.post(
                "/v1/auth/mfa/verify-enrollment",
                json={
                    "method": method.value,
                    "code": code,
                    "enrollment_id": enrollment_id
                },
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(
                success=False,
                error=data.get("error"),
                error_code=data.get("error_code")
            )
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def challenge_mfa(
        self, 
        mfa_token: str,
        method: MFAMethod,
        code: str
    ) -> AuthResponse:
        """
        Responde a um desafio MFA
        
        Args:
            mfa_token: Token MFA recebido no login
            method: Método de MFA
            code: Código de verificação
            
        Returns:
            AuthResponse com sessão completa
        """
        try:
            response = await self._client.post(
                "/v1/auth/mfa/challenge",
                json={
                    "mfa_token": mfa_token,
                    "method": method.value,
                    "code": code
                }
            )
            result = self._handle_auth_response(response)
            
            if result.success and result.session:
                self._session = result.session
                self._notify_auth_state_change(result.user)
            
            return result
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def disable_mfa(self, method: MFAMethod, code: str) -> AuthResponse:
        """Desativa MFA"""
        if not self._session:
            return AuthResponse(success=False, error="Not authenticated")
        
        try:
            response = await self._client.post(
                "/v1/auth/mfa/disable",
                json={"method": method.value, "code": code},
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(success=False, error=data.get("error"))
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    # -------------------------------------------------------------------------
    # Session Management
    # -------------------------------------------------------------------------
    
    async def refresh_session(self) -> AuthResponse:
        """Renova a sessão atual"""
        if not self._session or not self._session.refresh_token:
            return AuthResponse(success=False, error="No refresh token")
        
        try:
            response = await self._client.post(
                "/v1/auth/refresh",
                json={"refresh_token": self._session.refresh_token}
            )
            result = self._handle_auth_response(response)
            
            if result.success and result.session:
                self._session = result.session
            
            return result
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def sign_out(self) -> AuthResponse:
        """Faz logout do usuário"""
        if not self._session:
            return AuthResponse(success=True)
        
        try:
            await self._client.post(
                "/v1/auth/signout",
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
        except:
            pass  # Ignorar erros no logout
        
        self._session = None
        self._notify_auth_state_change(None)
        return AuthResponse(success=True)
    
    def get_session(self) -> Optional[Session]:
        """Retorna sessão atual"""
        return self._session
    
    def get_user(self) -> Optional[User]:
        """Retorna usuário atual"""
        return self._session.user if self._session else None
    
    # -------------------------------------------------------------------------
    # Password Management
    # -------------------------------------------------------------------------
    
    async def reset_password(self, email: str) -> AuthResponse:
        """Envia email de reset de senha"""
        try:
            response = await self._client.post(
                "/v1/auth/password/reset",
                json={"email": email}
            )
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(success=False, error=data.get("error"))
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def update_password(
        self, 
        current_password: str, 
        new_password: str
    ) -> AuthResponse:
        """Atualiza senha do usuário logado"""
        if not self._session:
            return AuthResponse(success=False, error="Not authenticated")
        
        try:
            response = await self._client.post(
                "/v1/auth/password/update",
                json={
                    "current_password": current_password,
                    "new_password": new_password
                },
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            
            if response.status_code == 200:
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(success=False, error=data.get("error"))
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    # -------------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------------
    
    async def update_user(
        self,
        display_name: Optional[str] = None,
        photo_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuthResponse:
        """Atualiza dados do usuário"""
        if not self._session:
            return AuthResponse(success=False, error="Not authenticated")
        
        payload = {}
        if display_name is not None:
            payload["display_name"] = display_name
        if photo_url is not None:
            payload["photo_url"] = photo_url
        if metadata is not None:
            payload["metadata"] = metadata
        
        try:
            response = await self._client.patch(
                "/v1/auth/user",
                json=payload,
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            return self._handle_auth_response(response)
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    async def delete_user(self) -> AuthResponse:
        """Exclui conta do usuário"""
        if not self._session:
            return AuthResponse(success=False, error="Not authenticated")
        
        try:
            response = await self._client.delete(
                "/v1/auth/user",
                headers={"Authorization": f"Bearer {self._session.access_token}"}
            )
            
            if response.status_code == 200:
                self._session = None
                self._notify_auth_state_change(None)
                return AuthResponse(success=True)
            
            data = response.json()
            return AuthResponse(success=False, error=data.get("error"))
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    
    def _handle_auth_response(self, response: httpx.Response) -> AuthResponse:
        """Processa resposta de autenticação"""
        try:
            data = response.json()
        except:
            return AuthResponse(
                success=False,
                error="Invalid response",
                error_code="INVALID_RESPONSE"
            )
        
        if response.status_code != 200:
            return AuthResponse(
                success=False,
                error=data.get("error", "Unknown error"),
                error_code=data.get("error_code"),
                requires_mfa=data.get("requires_mfa", False),
                mfa_token=data.get("mfa_token"),
                available_mfa_methods=data.get("available_mfa_methods", [])
            )
        
        # Parsear usuário
        user_data = data.get("user", {})
        user = User(
            id=user_data.get("id", ""),
            email=user_data.get("email"),
            phone=user_data.get("phone"),
            email_verified=user_data.get("email_verified", False),
            phone_verified=user_data.get("phone_verified", False),
            display_name=user_data.get("display_name"),
            photo_url=user_data.get("photo_url"),
            provider=user_data.get("provider"),
            providers=user_data.get("providers", []),
            mfa_enabled=user_data.get("mfa_enabled", False),
            metadata=user_data.get("metadata", {}),
            custom_claims=user_data.get("custom_claims", {}),
        )
        
        # Parsear sessão
        session = Session(
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            user=user,
        )
        
        if data.get("expires_in"):
            session.expires_at = datetime.utcnow() + timedelta(
                seconds=data["expires_in"]
            )
        
        return AuthResponse(success=True, user=user, session=session)


# Versão síncrona
class AdoalerAuthSync:
    """Versão síncrona do cliente de Auth"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.api_url,
            timeout=config.timeout,
            headers={
                "X-API-Key": config.api_key,
                "X-Project-ID": config.project_id,
                "Content-Type": "application/json",
            }
        )
        self._session: Optional[Session] = None
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def sign_in_with_email(self, email: str, password: str) -> AuthResponse:
        """Login com email e senha (síncrono)"""
        try:
            response = self._client.post(
                "/v1/auth/signin",
                json={"email": email, "password": password}
            )
            # ... processar resposta
            return AuthResponse(success=response.status_code == 200)
        except Exception as e:
            return AuthResponse(success=False, error=str(e))
    
    def sign_out(self) -> AuthResponse:
        """Logout (síncrono)"""
        self._session = None
        return AuthResponse(success=True)
    
    def get_user(self) -> Optional[User]:
        """Retorna usuário atual"""
        return self._session.user if self._session else None
