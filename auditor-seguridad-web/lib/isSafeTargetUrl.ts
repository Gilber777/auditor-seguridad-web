/**
 * Validador de URLs objetivo para protección contra Server-Side Request Forgery (SSRF).
 * Bloquea interfaces loopback, direcciones IP privadas (RFC 1918), enlaces locales y metadatos cloud.
 */

function isPrivateIp(ip: string): boolean {
  // IPv4 Loopback
  if (ip.startsWith("127.")) return true;
  if (ip === "0.0.0.0") return true;

  // IPv6 Loopback / Unspecified
  if (ip === "::1" || ip === "::") return true;

  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    // 10.0.0.0 - 10.255.255.255 (Clase A)
    if (parts[0] === 10) return true;

    // 172.16.0.0 - 172.31.255.255 (Clase B)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

    // 192.168.0.0 - 192.168.255.255 (Clase C)
    if (parts[0] === 192 && parts[1] === 168) return true;

    // 169.254.0.0 - 169.254.255.255 (Link-Local y Metadatos AWS/GCP)
    if (parts[0] === 169 && parts[1] === 254) return true;

    // 100.64.0.0/10 (Carrier-Grade NAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  }

  return false;
}

export function validateSafeTargetUrl(rawUrl: string): { isValid: boolean; error?: string; url?: URL } {
  if (!rawUrl || typeof rawUrl !== "string") {
    return { isValid: false, error: "La URL es requerida." };
  }

  const trimmed = rawUrl.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return { isValid: false, error: "La URL debe comenzar con http:// o https://" };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { isValid: false, error: "Formato de URL no válido." };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { isValid: false, error: "Solo se admiten protocolos http: y https:" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (!hostname) {
    return { isValid: false, error: "Nombre de host no válido." };
  }

  // Bloqueo de nombres de host locales reservados
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan")
  ) {
    return { isValid: false, error: "Acceso a dominios internos o locales restringido por política SSRF." };
  }

  // Verificación de IP directa
  if (isPrivateIp(hostname)) {
    return { isValid: false, error: "Acceso a direcciones IP privadas o de bucle invertido bloqueado (Anti-SSRF)." };
  }

  // Requiere un dominio con al menos un punto si no es IP válida
  if (!hostname.includes(".")) {
    return { isValid: false, error: "El objetivo debe ser un dominio calificado (FQDN)." };
  }

  return { isValid: true, url: parsed };
}
