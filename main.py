"""
API de Auditoría e Inspección de Seguridad Web
Desarrollada con FastAPI y Python 3.12+
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
import os
import re
import socket
import ssl
from typing import Literal, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel, Field, field_validator

# -----------------------------------------------------------------------------
# Configuración de Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("auditor-seguridad")

# -----------------------------------------------------------------------------
# Modelos Pydantic para Solicitudes y Respuestas
# -----------------------------------------------------------------------------
FindingStatus = Literal["ok", "warn", "missing"]


class AuditRequest(BaseModel):
    """Esquema de solicitud para auditar un objetivo web."""

    url: Optional[str] = Field(
        default=None,
        description="URL completa a auditar (ej: https://ejemplo.com)",
        examples=["https://example.com"],
    )
    target: Optional[str] = Field(
        default=None,
        description="Alias alternativo para la URL objetivo",
        examples=["https://example.com"],
    )

    @field_validator("url", mode="before")
    @classmethod
    def validate_and_normalize_url(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("La URL no puede estar vacía.")
        if not re.match(r"^https?://", trimmed, re.IGNORECASE):
            trimmed = f"https://{trimmed}"
        return trimmed

    def get_target_url(self) -> str:
        raw_url = self.url or self.target
        if not raw_url or not raw_url.strip():
            raise HTTPException(
                status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
                detail="Se requiere el campo 'url' o 'target' con una dirección válida.",
            )
        cleaned = raw_url.strip()
        if not re.match(r"^https?://", cleaned, re.IGNORECASE):
            cleaned = f"https://{cleaned}"
        return cleaned


class Finding(BaseModel):
    """Representa un hallazgo específico en la inspección."""

    label: str = Field(..., description="Nombre del control o cabecera evaluada")
    value: str = Field(..., description="Detalle del resultado o valor detectado")
    status: FindingStatus = Field(
        ..., description="Estado de seguridad: ok, warn o missing"
    )


class AuditSummary(BaseModel):
    """Resumen cuantitativo de hallazgos."""

    ok: int = Field(0, description="Controles conformes")
    warn: int = Field(0, description="Advertencias que requieren atención")
    missing: int = Field(0, description="Controles faltantes o críticos")
    total: int = Field(0, description="Total de controles evaluados")


class AuditResponse(BaseModel):
    """Respuesta estructurada de la auditoría de seguridad."""

    target: str = Field(..., description="URL auditada normalizada")
    headers: list[Finding] = Field(
        default_factory=list, description="Análisis de cabeceras de respuesta HTTP"
    )
    ssl: list[Finding] = Field(
        default_factory=list, description="Evaluación de cifrado y certificado TLS/SSL"
    )
    meta: list[Finding] = Field(
        default_factory=list, description="Inspección de etiquetas meta HTML"
    )
    summary: AuditSummary = Field(
        ..., description="Métricas acumuladas de la inspección"
    )
    timestamp: str = Field(
        ..., description="Marca de tiempo en formato ISO UTC de la ejecución"
    )


# -----------------------------------------------------------------------------
# Inicialización de la Aplicación FastAPI
# -----------------------------------------------------------------------------
app = FastAPI(
    title="API de Auditoría e Inspección de Seguridad Web",
    description=(
        "Servicio de inspección y auditoría de seguridad para objetivos web. "
        "Analiza cabeceras de seguridad HTTP (CSP, HSTS, X-Frame-Options), "
        "parámetros TLS/SSL y metadatos HTML."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# -----------------------------------------------------------------------------
# Configuración de CORS
# -----------------------------------------------------------------------------
# Acepta solicitudes del frontend en los puertos 80 y 3000 (localhost y 127.0.0.1)
DEFAULT_ORIGINS = [
    "http://localhost",
    "http://localhost:80",
    "http://localhost:3000",
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:3000",
]

env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    if env_origins.strip() == "*":
        allowed_origins = ["*"]
        allow_credentials = False
    else:
        allowed_origins = [orig.strip() for orig in env_origins.split(",") if orig.strip()]
        allow_credentials = True
else:
    allowed_origins = DEFAULT_ORIGINS
    allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# -----------------------------------------------------------------------------
# Validaciones de Seguridad (Defensa contra SSRF)
# -----------------------------------------------------------------------------
def is_safe_target_url(url_str: str) -> tuple[bool, str]:
    """
    Verifica que la URL no apunte a direcciones IP privadas, de enlace local,
    o interfaces de bucle invertido para mitigar riesgos de SSRF.
    """
    try:
        parsed = urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            return False, "Solo se admiten protocolos http y https."

        hostname = parsed.hostname
        if not hostname:
            return False, "Nombre de host no válido."

        # Evitar loopback directo y dominios reservados locales
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False, "No está permitido auditar localhost ni direcciones locales."

        if hostname.endswith(".local") or hostname.endswith(".internal"):
            return False, "Dominios de red interna no permitidos."

        # Si el hostname es una IP literal, verificar que sea pública
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False, "Las direcciones IP privadas están bloqueadas."
        except ValueError:
            # Es un nombre de dominio estándar, continuamos
            pass

        return True, ""
    except Exception as exc:
        return False, f"Error al validar URL: {exc}"


# -----------------------------------------------------------------------------
# Motores de Inspección (Cabeceras, SSL, Meta tags)
# -----------------------------------------------------------------------------
def inspect_http_headers(headers: httpx.Headers) -> list[Finding]:
    """Evalúa las directivas y cabeceras de respuesta HTTP críticas para seguridad."""
    findings: list[Finding] = []

    # 1. Content-Security-Policy
    csp = headers.get("content-security-policy")
    if csp:
        findings.append(
            Finding(
                label="Content-Security-Policy",
                value=csp[:120] + ("..." if len(csp) > 120 else ""),
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="Content-Security-Policy",
                value="No se detectó política CSP en la respuesta de servidor.",
                status="missing",
            )
        )

    # 2. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if hsts:
        findings.append(
            Finding(
                label="Strict-Transport-Security",
                value=hsts,
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="Strict-Transport-Security",
                value="Cabecera HSTS ausente. Las conexiones podrían degradarse a HTTP plano.",
                status="missing",
            )
        )

    # 3. X-Frame-Options
    xfo = headers.get("x-frame-options")
    if xfo:
        val_upper = xfo.upper()
        if "DENY" in val_upper or "SAMEORIGIN" in val_upper:
            findings.append(
                Finding(
                    label="X-Frame-Options",
                    value=xfo,
                    status="ok",
                )
            )
        else:
            findings.append(
                Finding(
                    label="X-Frame-Options",
                    value=f"Configuración permisiva o inusual: {xfo}",
                    status="warn",
                )
            )
    else:
        findings.append(
            Finding(
                label="X-Frame-Options",
                value="Cabecera ausente. Posible riesgo de Clickjacking en iframes.",
                status="missing",
            )
        )

    # 4. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        findings.append(
            Finding(
                label="X-Content-Type-Options",
                value=xcto,
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="X-Content-Type-Options",
                value="Falta directiva 'nosniff' para prevenir ataques de MIME-Confusion.",
                status="missing",
            )
        )

    # 5. Referrer-Policy
    ref_policy = headers.get("referrer-policy")
    if ref_policy:
        findings.append(
            Finding(
                label="Referrer-Policy",
                value=ref_policy,
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="Referrer-Policy",
                value="Cabecera no declarada. Revisar filtrado de origen para evitar fugas de URLs.",
                status="warn",
            )
        )

    # 6. Permissions-Policy
    perm_policy = headers.get("permissions-policy")
    if perm_policy:
        findings.append(
            Finding(
                label="Permissions-Policy",
                value=perm_policy[:100] + ("..." if len(perm_policy) > 100 else ""),
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="Permissions-Policy",
                value="Cabecera no declarada. Las APIs del navegador (cámara, micro, geo) no están restringidas.",
                status="warn",
            )
        )

    # 7. Divulgación de información de servidor (Server / X-Powered-By)
    server = headers.get("server")
    x_powered_by = headers.get("x-powered-by")
    if server or x_powered_by:
        detail = f"Server: {server or 'N/A'} | X-Powered-By: {x_powered_by or 'N/A'}"
        findings.append(
            Finding(
                label="Divulgación de Servidor",
                value=f"Expone detalles de la infraestructura: {detail}",
                status="warn",
            )
        )
    else:
        findings.append(
            Finding(
                label="Divulgación de Servidor",
                value="Cabeceras de fingerprinting de servidor minimizadas u ocultas.",
                status="ok",
            )
        )

    return findings


def inspect_ssl_sync(hostname: str, port: int = 443) -> list[Finding]:
    """Inspecciona sincrónicamente los certificados TLS/SSL mediante sockets seguros."""
    findings: list[Finding] = []
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=6.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cert = ssock.getpeercert()

                # Versión de TLS
                if version in ("TLSv1.3", "TLSv1.2"):
                    findings.append(
                        Finding(
                            label="Protocolo",
                            value=version.replace("v", " "),
                            status="ok",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            label="Protocolo",
                            value=f"{version} (Versión TLS potencialmente obsoleta)",
                            status="warn",
                        )
                    )

                # Emisor (Issuer)
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_name = (
                    issuer_dict.get("organizationName")
                    or issuer_dict.get("commonName")
                    or "Desconocido"
                )
                findings.append(
                    Finding(
                        label="Emisor",
                        value=f"{issuer_name} — {hostname}",
                        status="ok",
                    )
                )

                # Caducidad
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Formato típico: 'May 20 12:00:00 2026 GMT'
                    expiry_date = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (expiry_date - now).days

                    if days_remaining < 0:
                        findings.append(
                            Finding(
                                label="Caducidad",
                                value=f"Certificado EXPIRADO hace {abs(days_remaining)} días.",
                                status="missing",
                            )
                        )
                    elif days_remaining <= 30:
                        findings.append(
                            Finding(
                                label="Caducidad",
                                value=f"Certificado próximo a vencer: {days_remaining} días restantes.",
                                status="warn",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                label="Caducidad",
                                value=f"Certificado vigente ({days_remaining} días restantes hasta {expiry_date.strftime('%Y-%m-%d')}).",
                                status="ok",
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            label="Caducidad",
                            value="No se pudo determinar la fecha de vencimiento.",
                            status="warn",
                        )
                    )

                # Indicador de HSTS Preload
                findings.append(
                    Finding(
                        label="HSTS preload",
                        value="Verificar registro formal en hstspreload.org.",
                        status="warn",
                    )
                )

    except ssl.SSLCertVerificationError as ssl_err:
        findings.append(
            Finding(
                label="Certificado SSL",
                value=f"Falla de verificación de certificado: {ssl_err.verify_message}",
                status="missing",
            )
        )
    except Exception as exc:
        logger.warning("No se pudo inspeccionar SSL para %s: %s", hostname, exc)
        findings.append(
            Finding(
                label="Conexión TLS/SSL",
                value=f"No se pudo completar el handshake SSL con {hostname}: {exc}",
                status="missing",
            )
        )

    return findings


def inspect_html_meta(html_text: str) -> list[Finding]:
    """Analiza las etiquetas meta y directivas en el código HTML de la respuesta."""
    findings: list[Finding] = []
    soup = BeautifulSoup(html_text, "html.parser")

    # 1. Viewport
    viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
    if viewport and viewport.get("content"):
        findings.append(
            Finding(
                label="viewport",
                value=str(viewport.get("content")),
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="viewport",
                value="Etiqueta meta viewport ausente o sin contenido.",
                status="warn",
            )
        )

    # 2. Robots
    robots = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
    if robots and robots.get("content"):
        findings.append(
            Finding(
                label="robots",
                value=str(robots.get("content")),
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="robots",
                value="Directiva robots no declarada en HTML (usa valores por defecto del buscador).",
                status="ok",
            )
        )

    # 3. Referrer meta
    referrer_meta = soup.find(
        "meta", attrs={"name": re.compile(r"^referrer$", re.I)}
    )
    if referrer_meta and referrer_meta.get("content"):
        findings.append(
            Finding(
                label="referrer",
                value=str(referrer_meta.get("content")),
                status="ok",
            )
        )
    else:
        findings.append(
            Finding(
                label="referrer",
                value="Meta referrer ausente a nivel HTML.",
                status="missing",
            )
        )

    # 4. Generator
    generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if generator and generator.get("content"):
        findings.append(
            Finding(
                label="generator",
                value=f"Expone el generador de la plataforma: '{generator.get('content')}'. Se recomienda omitir.",
                status="warn",
            )
        )
    else:
        findings.append(
            Finding(
                label="generator",
                value="No se detectó exposición del generador o CMS.",
                status="ok",
            )
        )

    return findings


# -----------------------------------------------------------------------------
# Endpoints de la API
# -----------------------------------------------------------------------------
@app.get(
    "/",
    summary="Información raíz del servicio",
    tags=["Sistema"],
)
async def root():
    return {
        "service": "Auditor de Seguridad Web API",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "auditar": "POST /api/auditar",
            "health": "GET /api/health",
        },
    }


@app.get(
    "/api/health",
    summary="Verificación de estado de salud del servicio",
    tags=["Sistema"],
)
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post(
    "/api/auditar",
    response_model=AuditResponse,
    summary="Ejecutar auditoría de seguridad sobre una URL objetivo",
    tags=["Auditoría"],
)
async def auditar_objetivo(solicitud: AuditRequest):
    """
    Realiza una inspección completa de seguridad del sitio web objetivo:
    - Evaluación de cabeceras HTTP de protección (CSP, HSTS, X-Frame-Options, etc.).
    - Verificación de protocolo TLS y validez del certificado SSL.
    - Inspección de metaetiquetas HTML críticas.
    """
    target_url = solicitud.get_target_url()
    logger.info("Iniciando auditoría para objetivo: %s", target_url)

    # Validación SSRF y esquema
    is_safe, error_msg = is_safe_target_url(target_url)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)

    # 1. Petición HTTP para inspeccionar cabeceras y HTML
    headers_findings: list[Finding] = []
    meta_findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(
            verify=False,  # Se evalúa SSL independientemente para no abortar si el cert tiene detalles
            timeout=10.0,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "SecurityAuditAgent/1.0 (+https://auditor-seguridad.local; inspeccion-autorizada)"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ) as client:
            async with client.stream("GET", target_url) as response:
                headers_findings = inspect_http_headers(response.headers)
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    # Protección OOM: Lectura acotada a máximo 256 KB para análisis de <head>
                    body_bytes = b""
                    async for chunk in response.aiter_bytes():
                        body_bytes += chunk
                        if len(body_bytes) >= 256 * 1024:
                            break
                    html_text = body_bytes.decode(response.encoding or "utf-8", errors="replace")
                    meta_findings = inspect_html_meta(html_text)
                else:
                    meta_findings = [
                        Finding(
                            label="HTML Meta",
                            value=f"Respuesta no HTML ({content_type or 'desconocido'}). Metadatos no aplicables.",
                            status="warn",
                        )
                    ]

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Tiempo de espera agotado al conectar con {target_url}.",
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"No se pudo establecer conexión con el objetivo: {str(exc)}",
        )

    # 2. Inspección TLS / SSL (ejecutada en hilo asíncrono para no bloquear el bucle de eventos)
    ssl_findings: list[Finding] = []
    if is_https:
        ssl_findings = await asyncio.to_thread(inspect_ssl_sync, hostname, port)
    else:
        ssl_findings = [
            Finding(
                label="Protocolo",
                value="HTTP sin cifrado. El tráfico viaja en texto plano.",
                status="missing",
            ),
            Finding(
                label="Certificado SSL",
                value="No configurado para protocolo HTTP.",
                status="missing",
            ),
        ]

    # 3. Cálculo de métricas y resumen
    all_findings = headers_findings + ssl_findings + meta_findings
    ok_count = sum(1 for f in all_findings if f.status == "ok")
    warn_count = sum(1 for f in all_findings if f.status == "warn")
    missing_count = sum(1 for f in all_findings if f.status == "missing")

    summary = AuditSummary(
        ok=ok_count,
        warn=warn_count,
        missing=missing_count,
        total=len(all_findings),
    )

    return AuditResponse(
        target=target_url,
        headers=headers_findings,
        ssl=ssl_findings,
        meta=meta_findings,
        summary=summary,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# -----------------------------------------------------------------------------
# Punto de entrada directo para uvicorn
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
