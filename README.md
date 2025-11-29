# Adoaler Python SDK

[![PyPI version](https://badge.fury.io/py/adoaler-sdk.svg)](https://badge.fury.io/py/adoaler-sdk)
[![Python Support](https://img.shields.io/pypi/pyversions/adoaler-sdk.svg)](https://pypi.org/project/adoaler-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SDK oficial Python para integração com o Adoaler Security Platform.

## Instalação

```bash
pip install adoaler-sdk
```

### Requisitos

- Python 3.8+
- requests >= 2.28.0

## Quick Start

```python
from adoaler import Adoaler

# Inicializar cliente
client = Adoaler(
    api_key="sua_api_key",
    environment="production"  # ou "sandbox"
)

# Verificar risco de IP
result = client.ip.check("203.0.113.42")
print(f"Risk Score: {result.risk_score}")
print(f"Risk Level: {result.risk_level}")

# Verificar dispositivo
device_result = client.device.verify(
    fingerprint="device_fingerprint_hash",
    user_id="user_123"
)
print(f"Device Trust Score: {device_result.trust_score}")
```

## Funcionalidades

### IP Intelligence

```python
# Verificação completa de IP
ip_info = client.ip.check("203.0.113.42")

# Propriedades disponíveis
ip_info.ip                  # IP verificado
ip_info.risk_score          # Score de risco (0-100)
ip_info.risk_level          # critical, high, medium, low
ip_info.is_vpn              # É VPN?
ip_info.is_proxy            # É proxy?
ip_info.is_tor              # É Tor?
ip_info.is_datacenter       # É datacenter?
ip_info.country             # País (ISO code)
ip_info.city                # Cidade
ip_info.asn                 # ASN
ip_info.organization        # Organização
ip_info.categories          # Categorias de ameaça

# Verificação em lote
ips = ["203.0.113.42", "198.51.100.23", "192.0.2.1"]
results = client.ip.check_batch(ips)
```

### Device Fingerprinting

```python
# Verificar dispositivo
device = client.device.verify(
    fingerprint="fp_hash_from_js_sdk",
    user_id="user_123",
    metadata={"session_id": "sess_abc"}
)

device.device_id            # ID único do dispositivo
device.trust_score          # Score de confiança (0-100)
device.is_known             # Dispositivo já visto?
device.bot_probability      # Probabilidade de ser bot
```

### Bot Detection

```python
bot_check = client.bot.detect(
    fingerprint="fp_hash",
    user_agent="Mozilla/5.0...",
    ip="203.0.113.42",
    behavior={
        "mouse_movements": 150,
        "keystrokes": 45,
        "time_on_page": 12.5
    }
)

bot_check.is_bot            # É bot?
bot_check.bot_type          # Tipo de bot
bot_check.confidence        # Confiança da detecção
```

### Fraud Detection

```python
fraud_check = client.fraud.check_transaction(
    transaction_id="txn_123",
    amount=199.99,
    currency="BRL",
    user_id="user_123",
    device_fingerprint="fp_hash",
    ip="203.0.113.42",
    email="user@example.com"
)

fraud_check.risk_score      # Score de risco (0-100)
fraud_check.recommendation  # approve, review, decline
fraud_check.signals         # Sinais de risco detectados
```

## Integração com Frameworks

### Flask

```python
from flask import Flask
from adoaler.integrations.flask import AdoalerMiddleware

app = Flask(__name__)
app.wsgi_app = AdoalerMiddleware(
    app.wsgi_app,
    api_key="sua_api_key",
    block_high_risk=True
)
```

### Django

```python
# settings.py
MIDDLEWARE = [
    'adoaler.integrations.django.AdoalerMiddleware',
]

ADOALER = {
    'API_KEY': 'sua_api_key',
    'ENVIRONMENT': 'production',
}
```

### FastAPI

```python
from fastapi import FastAPI
from adoaler.integrations.fastapi import AdoalerMiddleware

app = FastAPI()
app.add_middleware(AdoalerMiddleware, api_key="sua_api_key")
```

## Async Support

```python
from adoaler import AsyncAdoaler

async def main():
    client = AsyncAdoaler(api_key="sua_api_key")
    result = await client.ip.check("203.0.113.42")
    await client.close()
```

## Tratamento de Erros

```python
from adoaler.exceptions import (
    AdoalerError,
    AuthenticationError,
    RateLimitError,
    ValidationError
)

try:
    result = client.ip.check("203.0.113.42")
except RateLimitError as e:
    print(f"Rate limit. Retry após: {e.retry_after}s")
except AuthenticationError:
    print("Chave de API inválida")
except AdoalerError as e:
    print(f"Erro: {e}")
```

## Webhooks

```python
from adoaler.webhooks import WebhookHandler

webhook = WebhookHandler(signing_secret="seu_webhook_secret")

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    payload = request.get_data()
    signature = request.headers.get("X-Adoaler-Signature")
    
    event = webhook.verify_and_parse(payload, signature)
    
    if event.type == "threat.detected":
        handle_threat(event.data)
    
    return {"received": True}
```

## Documentação

- **Docs**: https://docs.adoaler.com/sdk/python
- **API Reference**: https://docs.adoaler.com/api

## Suporte

- **Email**: support@adoaler.com
- **GitHub Issues**: https://github.com/adoaler/python-sdk/issues

## Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

