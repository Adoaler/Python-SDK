"""
Adoaler Ads SDK - Python
Para integração de anúncios em aplicações Python
"""

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode

import httpx


@dataclass
class AdConfig:
    """Configuração do SDK de Ads"""
    client_id: str
    publisher_id: str
    api_url: str = "https://ads.adoaler.com"
    timeout: int = 30
    debug: bool = False


@dataclass
class Ad:
    """Representa um anúncio"""
    id: str
    impression_id: str
    type: str  # 'banner', 'native', 'video', 'interstitial'
    headline: str
    description: str
    cta: str
    destination_url: str
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    tracking_urls: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdRequest:
    """Requisição de anúncio"""
    slot_id: str
    format: str = "banner"  # 'banner', 'native', 'video', 'interstitial'
    size: Optional[str] = None  # '300x250', '728x90', etc
    keywords: List[str] = field(default_factory=list)
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    geo: Optional[Dict[str, str]] = None
    custom_targeting: Dict[str, str] = field(default_factory=dict)


@dataclass
class AdResponse:
    """Resposta de requisição de anúncio"""
    success: bool
    ad: Optional[Ad] = None
    error: Optional[str] = None
    no_fill: bool = False


class AdoalerAds:
    """
    Cliente do Adoaler Ads SDK
    
    Exemplo de uso:
        ads = AdoalerAds(AdConfig(
            client_id="seu_client_id",
            publisher_id="seu_publisher_id"
        ))
        
        # Solicitar anúncio
        response = await ads.request_ad(AdRequest(
            slot_id="slot_123",
            format="banner",
            size="300x250"
        ))
        
        if response.success and response.ad:
            print(f"Anúncio: {response.ad.headline}")
            # Registrar impressão
            await ads.track_impression(response.ad.impression_id)
    """
    
    def __init__(self, config: AdConfig):
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.api_url,
            timeout=config.timeout,
            headers={
                "X-Client-ID": config.client_id,
                "X-Publisher-ID": config.publisher_id,
                "Content-Type": "application/json",
            }
        )
        self._session_id = str(uuid.uuid4())
    
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
            print(f"[AdoalerAds] {message}", *args)
    
    def _generate_request_id(self) -> str:
        """Gera ID único para requisição"""
        return str(uuid.uuid4())
    
    async def request_ad(self, request: AdRequest) -> AdResponse:
        """
        Solicita um anúncio
        
        Args:
            request: Configuração da requisição
            
        Returns:
            AdResponse com o anúncio ou erro
        """
        request_id = self._generate_request_id()
        
        payload = {
            "request_id": request_id,
            "session_id": self._session_id,
            "slot_id": request.slot_id,
            "format": request.format,
            "size": request.size,
            "keywords": request.keywords,
            "user_id": request.user_id,
            "device_id": request.device_id,
            "ip_address": request.ip_address,
            "user_agent": request.user_agent,
            "geo": request.geo,
            "custom_targeting": request.custom_targeting,
            "timestamp": int(time.time() * 1000),
        }
        
        self._log(f"Requesting ad: {request.slot_id}")
        
        try:
            response = await self._client.post("/v1/ads/request", json=payload)
            response.raise_for_status()
            data = response.json()
            
            if data.get("no_fill"):
                return AdResponse(success=True, no_fill=True)
            
            ad_data = data.get("ad")
            if not ad_data:
                return AdResponse(success=False, error="No ad returned")
            
            ad = Ad(
                id=ad_data["id"],
                impression_id=ad_data["impression_id"],
                type=ad_data["type"],
                headline=ad_data["headline"],
                description=ad_data["description"],
                cta=ad_data["cta"],
                destination_url=ad_data["destination_url"],
                image_url=ad_data.get("image_url"),
                video_url=ad_data.get("video_url"),
                tracking_urls=ad_data.get("tracking", {}),
                metadata=ad_data.get("metadata", {}),
            )
            
            return AdResponse(success=True, ad=ad)
            
        except httpx.HTTPStatusError as e:
            self._log(f"HTTP error: {e}")
            return AdResponse(success=False, error=str(e))
        except Exception as e:
            self._log(f"Error: {e}")
            return AdResponse(success=False, error=str(e))
    
    async def request_multiple_ads(
        self, 
        requests: List[AdRequest]
    ) -> List[AdResponse]:
        """
        Solicita múltiplos anúncios
        
        Args:
            requests: Lista de requisições
            
        Returns:
            Lista de respostas
        """
        import asyncio
        return await asyncio.gather(*[
            self.request_ad(req) for req in requests
        ])
    
    async def track_impression(self, impression_id: str) -> bool:
        """
        Registra uma impressão de anúncio
        
        Args:
            impression_id: ID da impressão
            
        Returns:
            True se registrado com sucesso
        """
        try:
            response = await self._client.post(
                "/v1/ads/impression",
                json={
                    "impression_id": impression_id,
                    "timestamp": int(time.time() * 1000),
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            self._log(f"Error tracking impression: {e}")
            return False
    
    async def track_click(self, impression_id: str) -> bool:
        """
        Registra um clique em anúncio
        
        Args:
            impression_id: ID da impressão
            
        Returns:
            True se registrado com sucesso
        """
        try:
            response = await self._client.post(
                "/v1/ads/click",
                json={
                    "impression_id": impression_id,
                    "timestamp": int(time.time() * 1000),
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            self._log(f"Error tracking click: {e}")
            return False
    
    async def track_viewable(
        self, 
        impression_id: str, 
        viewable_time_ms: int
    ) -> bool:
        """
        Registra viewability de anúncio
        
        Args:
            impression_id: ID da impressão
            viewable_time_ms: Tempo visível em milissegundos
            
        Returns:
            True se registrado com sucesso
        """
        try:
            response = await self._client.post(
                "/v1/ads/viewable",
                json={
                    "impression_id": impression_id,
                    "viewable_time_ms": viewable_time_ms,
                    "timestamp": int(time.time() * 1000),
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            self._log(f"Error tracking viewable: {e}")
            return False
    
    async def track_video_event(
        self, 
        impression_id: str, 
        event: str,
        progress_percent: Optional[int] = None
    ) -> bool:
        """
        Registra evento de vídeo
        
        Args:
            impression_id: ID da impressão
            event: 'start', 'firstQuartile', 'midpoint', 'thirdQuartile', 'complete'
            progress_percent: Percentual de progresso (opcional)
            
        Returns:
            True se registrado com sucesso
        """
        try:
            response = await self._client.post(
                "/v1/ads/video",
                json={
                    "impression_id": impression_id,
                    "event": event,
                    "progress_percent": progress_percent,
                    "timestamp": int(time.time() * 1000),
                }
            )
            response.raise_for_status()
            return True
        except Exception as e:
            self._log(f"Error tracking video event: {e}")
            return False
    
    async def get_publisher_stats(
        self,
        start_date: str,
        end_date: str,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Obtém estatísticas do publisher
        
        Args:
            start_date: Data início (YYYY-MM-DD)
            end_date: Data fim (YYYY-MM-DD)
            granularity: 'hour', 'day', 'week', 'month'
            
        Returns:
            Dicionário com estatísticas
        """
        try:
            response = await self._client.get(
                "/v1/publisher/stats",
                params={
                    "start_date": start_date,
                    "end_date": end_date,
                    "granularity": granularity,
                }
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._log(f"Error getting stats: {e}")
            return {"error": str(e)}


# Classe síncrona para compatibilidade
class AdoalerAdsSync:
    """Versão síncrona do cliente de Ads"""
    
    def __init__(self, config: AdConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.api_url,
            timeout=config.timeout,
            headers={
                "X-Client-ID": config.client_id,
                "X-Publisher-ID": config.publisher_id,
                "Content-Type": "application/json",
            }
        )
        self._session_id = str(uuid.uuid4())
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def request_ad(self, request: AdRequest) -> AdResponse:
        """Solicita um anúncio (síncrono)"""
        payload = {
            "request_id": str(uuid.uuid4()),
            "session_id": self._session_id,
            "slot_id": request.slot_id,
            "format": request.format,
            "size": request.size,
            "keywords": request.keywords,
            "timestamp": int(time.time() * 1000),
        }
        
        try:
            response = self._client.post("/v1/ads/request", json=payload)
            response.raise_for_status()
            data = response.json()
            
            if data.get("no_fill"):
                return AdResponse(success=True, no_fill=True)
            
            ad_data = data.get("ad")
            if not ad_data:
                return AdResponse(success=False, error="No ad returned")
            
            ad = Ad(
                id=ad_data["id"],
                impression_id=ad_data["impression_id"],
                type=ad_data["type"],
                headline=ad_data["headline"],
                description=ad_data["description"],
                cta=ad_data["cta"],
                destination_url=ad_data["destination_url"],
                image_url=ad_data.get("image_url"),
                video_url=ad_data.get("video_url"),
                tracking_urls=ad_data.get("tracking", {}),
            )
            
            return AdResponse(success=True, ad=ad)
            
        except Exception as e:
            return AdResponse(success=False, error=str(e))
    
    def track_impression(self, impression_id: str) -> bool:
        """Registra impressão (síncrono)"""
        try:
            response = self._client.post(
                "/v1/ads/impression",
                json={"impression_id": impression_id}
            )
            response.raise_for_status()
            return True
        except:
            return False
    
    def track_click(self, impression_id: str) -> bool:
        """Registra clique (síncrono)"""
        try:
            response = self._client.post(
                "/v1/ads/click",
                json={"impression_id": impression_id}
            )
            response.raise_for_status()
            return True
        except:
            return False
