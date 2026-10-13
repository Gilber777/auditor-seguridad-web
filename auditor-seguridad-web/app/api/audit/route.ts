import { NextResponse } from "next/server";
import { validateSafeTargetUrl } from "@/lib/isSafeTargetUrl";
import type { AuditApiResponse, ErrorResponse, SecurityCheck } from "@/types/audit";

export async function POST(
  request: Request
): Promise<NextResponse<AuditApiResponse | ErrorResponse>> {
  try {
    let body: { url?: string };
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Cuerpo de solicitud inválido. Se espera un objeto JSON con el campo "url".' },
        { status: 400 }
      );
    }

    const { url } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json(
        { error: "URL inválida. Debe incluir http:// o https://" },
        { status: 400 }
      );
    }

    const trimmedUrl = url.trim();

    // 1. Validación de seguridad Anti-SSRF
    const validation = validateSafeTargetUrl(trimmedUrl);
    if (!validation.isValid || !validation.url) {
      return NextResponse.json(
        { error: validation.error || "URL no autorizada o inválida." },
        { status: 400 }
      );
    }

    const safeUrl = validation.url.toString();

    // 2. Petición HTTP optimizada para evitar fugas de memoria (Memory Leaks)
    // Intentamos HEAD primero para transferir 0 bytes de cuerpo. Si el servidor no lo soporta,
    // usamos GET pero cancelamos inmediatamente el stream del body para liberar sockets y buffers.
    let response: Response;
    const requestHeaders = {
      "User-Agent":
        "Mozilla/5.0 (compatible; SecurityAuditAgent/1.0; +https://auditor-seguridad.local)",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    };

    try {
      response = await fetch(safeUrl, {
        method: "HEAD",
        redirect: "follow",
        signal: AbortSignal.timeout(6000),
        headers: requestHeaders,
      });

      // Si el servidor remoto rechaza HEAD con 405 (Method Not Allowed), degradamos a GET
      if (response.status === 405 || response.status === 501) {
        throw new Error("HEAD_METHOD_UNSUPPORTED");
      }
    } catch (err: unknown) {
      const isTimeout =
        (err as { name?: string })?.name === "TimeoutError" ||
        (err as { name?: string })?.name === "AbortError";

      if (isTimeout) {
        return NextResponse.json(
          { error: "Tiempo de espera agotado al conectar con el objetivo (timeout)." },
          { status: 504 }
        );
      }

      // Si falló por método no admitido o error de handshake en HEAD, ejecutamos GET
      response = await fetch(safeUrl, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(8000),
        headers: requestHeaders,
      });

      // Liberación explícita del stream para evitar Memory Leaks y saturación de conexiones en Node.js
      if (response.body) {
        try {
          await response.body.cancel();
        } catch {
          // Ignorar si el stream ya fue consumido o cerrado
        }
      }
    }

    const headers = response.headers;

    // 3. Evaluación de los vectores de seguridad
    const checks: SecurityCheck[] = [
      {
        header: "strict-transport-security",
        present: headers.has("strict-transport-security"),
        status: headers.has("strict-transport-security") ? "PASS" : "FAIL",
        value: headers.get("strict-transport-security"),
        severity: "HIGH",
        description:
          "Fuerza el uso exclusivo de conexiones HTTPS seguras y protege contra ataques de degradación (SSL Strip).",
        recommendation:
          "Implemente HSTS con max-age de al menos 31536000 segundos e incluya includeSubDomains.",
      },
      {
        header: "content-security-policy",
        present: headers.has("content-security-policy"),
        status: headers.has("content-security-policy") ? "PASS" : "FAIL",
        value: headers.get("content-security-policy"),
        severity: "HIGH",
        description:
          "Restringe las fuentes de carga de scripts y recursos, mitigando ataques de Cross-Site Scripting (XSS).",
        recommendation:
          "Configure CSP definiendo directivas estrictas como default-src, script-src y object-src.",
      },
      {
        header: "x-frame-options",
        present: headers.has("x-frame-options"),
        status: headers.has("x-frame-options") ? "PASS" : "FAIL",
        value: headers.get("x-frame-options"),
        severity: "MEDIUM",
        description:
          "Previene que el sitio sea incrustado en iframes o marcos externos no autorizados (Clickjacking).",
        recommendation:
          "Active X-Frame-Options estableciendo su valor en DENY o SAMEORIGIN.",
      },
      {
        header: "x-content-type-options",
        present: headers.has("x-content-type-options"),
        status: headers.has("x-content-type-options") ? "PASS" : "FAIL",
        value: headers.get("x-content-type-options"),
        severity: "LOW",
        description:
          "Impide que los navegadores interpreten archivos como tipos MIME diferentes al declarado (MIME-sniffing).",
        recommendation:
          "Establezca x-content-type-options: nosniff en todas las respuestas.",
      },
      {
        header: "referrer-policy",
        present: headers.has("referrer-policy"),
        status: headers.has("referrer-policy") ? "PASS" : "FAIL",
        value: headers.get("referrer-policy"),
        severity: "MEDIUM",
        description:
          "Controla cuánta información del referente (URL previa) se transmite en las peticiones salientes.",
        recommendation:
          "Configure Referrer-Policy con strict-origin-when-cross-origin o no-referrer.",
      },
    ];

    const passedCount = checks.filter((c) => c.present).length;
    const score = Math.round((passedCount / checks.length) * 100);

    return NextResponse.json({
      target: safeUrl,
      score,
      isHttps: response.url.startsWith("https://"),
      checks,
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const err = error as { name?: string; message?: string } | undefined;
    if (err?.name === "TimeoutError" || err?.name === "AbortError") {
      return NextResponse.json(
        { error: "Tiempo de espera agotado al conectar con el objetivo (timeout)." },
        { status: 504 }
      );
    }

    return NextResponse.json(
      { error: "Error al conectar con el objetivo: " + (err?.message || "Error de red") },
      { status: 500 }
    );
  }
}
