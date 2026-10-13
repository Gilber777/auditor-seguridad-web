"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Fingerprint,
  Globe,
  LoaderCircle,
  Lock,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  XCircle,
} from "lucide-react";
import { sanitizeAuditUrl } from "@/lib/sanitizeUrl";
import type { AuditApiResponse } from "@/types/audit";

export default function Home() {
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);
  const [auditData, setAuditData] = useState<AuditApiResponse | null>(null);

  // Referencia para cancelar peticiones activas y prevenir memory leaks / condiciones de carrera
  const abortControllerRef = useRef<AbortController | null>(null);

  // Cancelar cualquier petición pendiente al desmontar el componente
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const stats = useMemo(() => {
    if (!auditData) return null;
    const passed = auditData.checks.filter((c) => c.status === "PASS").length;
    const failed = auditData.checks.filter((c) => c.status === "FAIL").length;
    const highRisk = auditData.checks.filter(
      (c) => c.status === "FAIL" && c.severity === "HIGH"
    ).length;
    return {
      passed,
      failed,
      highRisk,
      total: auditData.checks.length,
    };
  }, [auditData]);

  async function handleInspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const sanitized = sanitizeAuditUrl(query);

    if (!sanitized) {
      setAuditData(null);
      setError(
        "Introduce una URL válida con dominio público (ejemplo: https://ejemplo.com o github.com)"
      );
      return;
    }

    // Cancelar cualquier petición en vuelo previa
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    setError(null);
    setIsInspecting(true);

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: sanitized }),
        signal: abortController.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Error del servidor (${response.status})`);
      }

      setAuditData(data);
    } catch (err: unknown) {
      // Ignorar errores de cancelación intencional del usuario
      if ((err as { name?: string })?.name === "AbortError") {
        return;
      }

      setAuditData(null);
      const errorMessage =
        err instanceof Error
          ? err.message
          : "Error desconocido al procesar la auditoría.";
      setError(errorMessage);
    } finally {
      setIsInspecting(false);
    }
  }

  // Código de colores requerido: Rojo: <50, Amarillo: 50-79, Verde: 80-100
  const scoreConfig = useMemo(() => {
    if (!auditData) return null;
    const score = auditData.score;

    if (score < 50) {
      return {
        label: "Nivel Crítico de Riesgo",
        colorClass: "text-red-400",
        borderClass: "border-red-500/50",
        bgClass: "bg-red-950/25",
        progressBarClass: "bg-red-500",
        glowClass: "shadow-[0_0_35px_-8px_rgba(239,68,68,0.45)]",
        badgeClass: "bg-red-500/20 text-red-300 border-red-500/40",
        icon: ShieldAlert,
        description:
          "El objetivo carece de múltiples directivas de seguridad esenciales. Alta exposición a vectores comunes de ataque.",
      };
    }

    if (score < 80) {
      return {
        label: "Nivel Medio / Advertencia",
        colorClass: "text-amber-400",
        borderClass: "border-amber-500/50",
        bgClass: "bg-amber-950/20",
        progressBarClass: "bg-amber-500",
        glowClass: "shadow-[0_0_35px_-8px_rgba(245,158,11,0.45)]",
        badgeClass: "bg-amber-500/20 text-amber-300 border-amber-500/40",
        icon: AlertTriangle,
        description:
          "El objetivo posee blindaje parcial. Existen cabeceras críticas faltantes que requieren remediación preventiva.",
      };
    }

    return {
      label: "Nivel Óptimo de Seguridad",
      colorClass: "text-emerald-400",
      borderClass: "border-emerald-500/50",
      bgClass: "bg-emerald-950/20",
      progressBarClass: "bg-emerald-500",
      glowClass: "shadow-[0_0_35px_-8px_rgba(16,185,129,0.45)]",
      badgeClass: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      icon: ShieldCheck,
      description:
        "El objetivo cumple con las directivas de seguridad recomendadas por OWASP para encabezados HTTP.",
    };
  }, [auditData]);

  return (
    <div className="relative min-h-screen overflow-hidden bg-ink-950 bg-grid-fade bg-[size:42px_42px] text-foreground">
      {/* Luces y texturas ambientales */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-crimson-500 to-transparent" />
      <div className="pointer-events-none absolute -left-24 top-24 h-72 w-72 rounded-full bg-crimson-600/15 blur-3xl" />
      <div className="pointer-events-none absolute -right-16 bottom-10 h-80 w-80 rounded-full bg-steel-500/15 blur-3xl" />

      <main className="relative mx-auto flex w-full max-w-6xl flex-col gap-8 px-5 py-10 sm:px-8 sm:py-12">
        {/* Encabezado Principal */}
        <header className="flex flex-col gap-6 border-b border-steel-600/30 pb-8 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-[0.42em] text-crimson-400">
              Unidad de inspección · caso abierto
            </p>
            <h1 className="mt-3 text-4xl font-light tracking-[0.06em] text-foreground sm:text-5xl">
              Auditor de Seguridad Web
            </h1>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-steel-300">
              Inspección en tiempo real de encabezados defensivos (HSTS, CSP, X-Frame-Options),
              verificación de protocolo HTTPS y cálculo automatizado de puntuación de cumplimiento.
            </p>
          </div>
          <div className="flex items-center gap-3 font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-[0.22em] text-steel-400">
            <Fingerprint className="h-4 w-4 text-crimson-400" aria-hidden />
            Canal cifrado · API Next.js Activa
          </div>
        </header>

        {/* Sección de Entrada y Disparo de Inspección */}
        <section className="border border-crimson-800/50 bg-ink-900/80 p-5 shadow-glow backdrop-blur-sm sm:p-7">
          <form
            onSubmit={handleInspect}
            className="flex flex-col gap-4 lg:flex-row lg:items-stretch"
          >
            <label className="sr-only" htmlFor="audit-url">
              URL a inspeccionar
            </label>
            <div className="relative flex-1">
              <Search
                className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-steel-400"
                aria-hidden
              />
              <input
                id="audit-url"
                name="url"
                type="text"
                autoComplete="url"
                placeholder="https://ejemplo.com o github.com"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                disabled={isInspecting}
                className="h-14 w-full border border-steel-600/50 bg-ink-950/80 pl-12 pr-4 font-[family-name:var(--font-geist-mono)] text-sm text-foreground outline-none transition placeholder:text-steel-500 focus:border-crimson-500 focus:shadow-[0_0_0_1px_rgba(196,30,58,0.45)] disabled:opacity-60"
              />
            </div>
            <button
              type="submit"
              disabled={isInspecting}
              className="inline-flex h-14 items-center justify-center gap-3 bg-crimson-500 px-8 font-[family-name:var(--font-geist-mono)] text-xs uppercase tracking-[0.28em] text-white transition hover:bg-crimson-400 disabled:cursor-wait disabled:opacity-70"
            >
              {isInspecting ? (
                <>
                  <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden />
                  <span>Inspeccionando...</span>
                </>
              ) : (
                <>
                  <Radar className="h-4 w-4" aria-hidden />
                  <span>Iniciar Inspección</span>
                </>
              )}
            </button>
          </form>

          {/* Estado de Error */}
          {error ? (
            <div
              role="alert"
              className="mt-4 flex items-start gap-3 border border-crimson-600/40 bg-crimson-950/30 p-3.5 text-sm text-crimson-300"
            >
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-crimson-400" aria-hidden />
              <div>
                <p className="font-semibold text-crimson-200">Error durante la inspección</p>
                <p className="mt-0.5 text-xs text-crimson-300/90">{error}</p>
              </div>
            </div>
          ) : (
            <p className="mt-4 text-xs text-steel-400">
              Analiza en tiempo real contra la ruta interna{" "}
              <code className="rounded bg-ink-950 px-1.5 py-0.5 font-[family-name:var(--font-geist-mono)] text-steel-300">
                app/api/audit/route.ts
              </code>
              . Protegido con controles Anti-SSRF y liberación de recursos.
            </p>
          )}
        </section>

        {/* Indicador de Carga Extendido */}
        {isInspecting && (
          <section className="flex flex-col items-center justify-center gap-4 border border-steel-600/40 bg-ink-900/60 p-10 text-center backdrop-blur-md">
            <div className="relative flex h-14 w-14 items-center justify-center">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-crimson-500/20" />
              <LoaderCircle className="h-8 w-8 animate-spin text-crimson-400" aria-hidden />
            </div>
            <div>
              <p className="font-[family-name:var(--font-geist-mono)] text-xs uppercase tracking-[0.26em] text-crimson-400">
                Petición HTTP en progreso
              </p>
              <h3 className="mt-1 text-base text-steel-200">
                Conectando con el objetivo y evaluando directivas de cabeceras...
              </h3>
              <p className="mt-1 text-xs text-steel-400">
                Verificando HSTS, CSP, X-Frame-Options, X-Content-Type-Options y Referrer-Policy
              </p>
            </div>
          </section>
        )}

        {/* Panel de Resultados: Puntaje y Métricas */}
        {auditData && scoreConfig && !isInspecting && (
          <>
            <section
              className={`border p-6 backdrop-blur-sm transition-all sm:p-8 ${scoreConfig.borderClass} ${scoreConfig.bgClass} ${scoreConfig.glowClass}`}
            >
              <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                {/* Lado izquierdo: Objetivo y Protocolo */}
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 border px-2.5 py-1 font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-wider ${scoreConfig.badgeClass}`}
                    >
                      <scoreConfig.icon className="h-3.5 w-3.5" aria-hidden />
                      {scoreConfig.label}
                    </span>

                    {auditData.isHttps ? (
                      <span className="inline-flex items-center gap-1.5 border border-emerald-500/40 bg-emerald-950/30 px-2.5 py-1 font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-wider text-emerald-300">
                        <Lock className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
                        HTTPS Activo
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 border border-amber-500/40 bg-amber-950/30 px-2.5 py-1 font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-wider text-amber-300">
                        <Unlock className="h-3.5 w-3.5 text-amber-400" aria-hidden />
                        HTTP No Seguro
                      </span>
                    )}
                  </div>

                  <h2 className="flex items-center gap-2 font-[family-name:var(--font-geist-mono)] text-xl font-light text-foreground sm:text-2xl">
                    <Globe className="h-5 w-5 text-steel-400" aria-hidden />
                    <span className="break-all">{auditData.target}</span>
                  </h2>

                  <p className="max-w-xl text-xs leading-relaxed text-steel-300">
                    {scoreConfig.description}
                  </p>
                </div>

                {/* Lado derecho: Puntaje Numérico y Barra */}
                <div className="flex flex-col items-start gap-2 border-t border-steel-600/30 pt-4 lg:items-end lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
                  <span className="font-[family-name:var(--font-geist-mono)] text-[11px] uppercase tracking-[0.24em] text-steel-400">
                    Puntaje Global de Blindaje
                  </span>
                  <div className="flex items-baseline gap-2">
                    <span
                      className={`text-6xl font-extralight tracking-tight sm:text-7xl ${scoreConfig.colorClass}`}
                    >
                      {auditData.score}
                    </span>
                    <span className="font-[family-name:var(--font-geist-mono)] text-lg text-steel-500">
                      / 100
                    </span>
                  </div>

                  {/* Barra de Progreso Visual */}
                  <div className="mt-1 h-2 w-full min-w-[200px] overflow-hidden rounded-full bg-ink-950/90 lg:w-48">
                    <div
                      className={`h-full transition-all duration-700 ease-out ${scoreConfig.progressBarClass}`}
                      style={{ width: `${Math.max(5, auditData.score)}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Estadísticas Cuantitativas */}
              {stats && (
                <div className="mt-7 grid grid-cols-2 gap-3 border-t border-steel-600/30 pt-5 sm:grid-cols-4">
                  <div className="border border-steel-600/30 bg-ink-900/60 p-3">
                    <p className="font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider text-steel-400">
                      Evaluados
                    </p>
                    <p className="mt-1 text-xl font-light text-foreground">{stats.total}</p>
                  </div>
                  <div className="border border-emerald-500/30 bg-emerald-950/20 p-3">
                    <p className="font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider text-emerald-400">
                      Superados (PASS)
                    </p>
                    <p className="mt-1 text-xl font-light text-emerald-300">{stats.passed}</p>
                  </div>
                  <div className="border border-red-500/30 bg-red-950/20 p-3">
                    <p className="font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider text-red-400">
                      Fallidos (FAIL)
                    </p>
                    <p className="mt-1 text-xl font-light text-red-300">{stats.failed}</p>
                  </div>
                  <div className="border border-crimson-600/40 bg-crimson-950/20 p-3">
                    <p className="font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider text-crimson-400">
                      Severidad Alta
                    </p>
                    <p className="mt-1 text-xl font-light text-crimson-300">{stats.highRisk}</p>
                  </div>
                </div>
              )}
            </section>

            {/* Tabla Descriptiva con Hallazgos y Recomendaciones */}
            <section className="border border-steel-600/30 bg-ink-900/80 shadow-panel backdrop-blur-sm">
              <header className="flex flex-col gap-2 border-b border-steel-600/30 bg-ink-900/90 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="font-[family-name:var(--font-geist-mono)] text-sm uppercase tracking-[0.24em] text-steel-200">
                    Matriz de Vectores y Recomendaciones
                  </h3>
                  <p className="mt-1 text-xs text-steel-400">
                    Detalle técnico de cada encabezado inspeccionado y su protocolo de remediación
                  </p>
                </div>
                <span className="font-[family-name:var(--font-geist-mono)] text-[11px] text-steel-400">
                  {new Date(auditData.timestamp).toLocaleTimeString()} UTC
                </span>
              </header>

              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm">
                  <thead className="border-b border-steel-600/30 bg-ink-950/70 font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-widest text-steel-400">
                    <tr>
                      <th className="px-5 py-3.5">Encabezado / Vector</th>
                      <th className="px-5 py-3.5">Estado</th>
                      <th className="px-5 py-3.5">Severidad</th>
                      <th className="px-5 py-3.5">Valor Detectado</th>
                      <th className="px-5 py-3.5">Diagnóstico y Recomendación</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-700/60 font-sans">
                    {auditData.checks.map((item) => {
                      const isPass = item.status === "PASS";
                      return (
                        <tr
                          key={item.header}
                          className="transition hover:bg-ink-800/40"
                        >
                          {/* Encabezado */}
                          <td className="px-5 py-4 align-top">
                            <span className="font-[family-name:var(--font-geist-mono)] text-xs font-medium text-steel-200">
                              {item.header}
                            </span>
                          </td>

                          {/* Estado PASS / FAIL */}
                          <td className="px-5 py-4 align-top">
                            {isPass ? (
                              <span className="inline-flex items-center gap-1.5 border border-emerald-500/40 bg-emerald-950/30 px-2.5 py-1 font-[family-name:var(--font-geist-mono)] text-[11px] font-medium uppercase tracking-wider text-emerald-300">
                                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                                PASS
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1.5 border border-red-500/40 bg-red-950/30 px-2.5 py-1 font-[family-name:var(--font-geist-mono)] text-[11px] font-medium uppercase tracking-wider text-red-300">
                                <XCircle className="h-3.5 w-3.5 text-red-400" />
                                FAIL
                              </span>
                            )}
                          </td>

                          {/* Severidad */}
                          <td className="px-5 py-4 align-top">
                            <span
                              className={`inline-block border px-2 py-0.5 font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider ${
                                item.severity === "HIGH"
                                  ? "border-crimson-600/40 bg-crimson-950/30 text-crimson-300"
                                  : item.severity === "MEDIUM"
                                    ? "border-amber-500/40 bg-amber-950/30 text-amber-300"
                                    : "border-steel-500/40 bg-steel-900/30 text-steel-300"
                              }`}
                            >
                              {item.severity}
                            </span>
                          </td>

                          {/* Valor Detectado */}
                          <td className="max-w-[220px] px-5 py-4 align-top">
                            {item.value ? (
                              <code className="block max-h-24 overflow-y-auto break-all rounded border border-steel-600/30 bg-ink-950/80 p-2 font-[family-name:var(--font-geist-mono)] text-xs text-steel-200">
                                {item.value}
                              </code>
                            ) : (
                              <span className="font-[family-name:var(--font-geist-mono)] text-xs italic text-steel-500">
                                No detectado / Ausente
                              </span>
                            )}
                          </td>

                          {/* Diagnóstico y Recomendación */}
                          <td className="px-5 py-4 align-top">
                            <p className="text-xs leading-relaxed text-steel-300">
                              {item.description}
                            </p>
                            {!isPass ? (
                              <div className="mt-2.5 border-l-2 border-crimson-500 bg-ink-950/60 p-2.5 text-xs text-crimson-200">
                                <span className="font-[family-name:var(--font-geist-mono)] text-[10px] uppercase tracking-wider text-crimson-400">
                                  Remediación:
                                </span>{" "}
                                {item.recommendation}
                              </div>
                            ) : (
                              <p className="mt-2 text-[11px] text-emerald-400">
                                ✓ Cabecera configurada conforme a recomendaciones técnicas.
                              </p>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        {/* Estado Vacío Antes de Iniciar Inspección */}
        {!auditData && !isInspecting && (
          <section className="flex min-h-[320px] flex-col items-center justify-center border border-dashed border-steel-600/40 bg-ink-900/30 px-6 py-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center border border-steel-600/50 bg-ink-800 text-steel-400">
              <Shield className="h-6 w-6" aria-hidden />
            </div>
            <h3 className="mt-4 font-[family-name:var(--font-geist-mono)] text-xs uppercase tracking-[0.28em] text-steel-300">
              Expediente en Espera
            </h3>
            <p className="mt-2 max-w-md text-sm text-steel-400">
              Introduce una dirección URL en el buscador superior y presiona{" "}
              <strong className="text-crimson-400 font-normal">Iniciar Inspección</strong> para
              ejecutar el análisis de seguridad y calcular el puntaje de cumplimiento.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
