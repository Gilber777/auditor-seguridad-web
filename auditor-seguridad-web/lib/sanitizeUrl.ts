export function sanitizeAuditUrl(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    const withProtocol = /^https?:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;
    const url = new URL(withProtocol);

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }

    const host = url.hostname.toLowerCase();
    if (!host || host === "localhost" || host.endsWith(".local")) {
      return null;
    }

    if (!host.includes(".")) {
      return null;
    }

    url.hash = "";
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return null;
  }
}
