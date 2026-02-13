import { DEFAULT_MAX_LINKS } from "./defaults.js";

// Remove markdown link syntax so only bare URLs are considered.
const MARKDOWN_LINK_RE = /\[[^\]]*]\((https?:\/\/\S+?)\)/gi;
const BARE_LINK_RE = /https?:\/\/\S+/gi;

function stripMarkdownLinks(message: string): string {
  return message.replace(MARKDOWN_LINK_RE, " ");
}

function resolveMaxLinks(value?: number): number {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  return DEFAULT_MAX_LINKS;
}

function isAllowedUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }
    if (isBlockedHost(parsed.hostname)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Block loopback, private, link-local, and metadata addresses. */
function isBlockedHost(hostname: string): boolean {
  // Normalize IPv6 brackets
  const host = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  const lower = host.toLowerCase();

  // Block common loopback hostnames
  if (lower === "localhost" || lower === "localhost.localdomain") {
    return true;
  }

  // Block IPv6 loopback
  if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") {
    return true;
  }

  // Block 0.0.0.0
  if (lower === "0.0.0.0") {
    return true;
  }

  // Parse as IPv4 dotted-quad
  const ipv4Parts = lower.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d{1,3}$/.test(p))) {
    const octets = ipv4Parts.map(Number);
    if (octets.some((o) => o > 255)) {
      return true; // invalid IP
    }
    const [a, b] = octets;
    // 127.0.0.0/8 - loopback
    if (a === 127) return true;
    // 10.0.0.0/8 - private
    if (a === 10) return true;
    // 172.16.0.0/12 - private
    if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 - private
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 - link-local (includes cloud metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // 100.64.0.0/10 - CGNAT (used by Tailscale)
    if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true;
  }

  return false;
}

export function extractLinksFromMessage(message: string, opts?: { maxLinks?: number }): string[] {
  const source = message?.trim();
  if (!source) {
    return [];
  }

  const maxLinks = resolveMaxLinks(opts?.maxLinks);
  const sanitized = stripMarkdownLinks(source);
  const seen = new Set<string>();
  const results: string[] = [];

  for (const match of sanitized.matchAll(BARE_LINK_RE)) {
    const raw = match[0]?.trim();
    if (!raw) {
      continue;
    }
    if (!isAllowedUrl(raw)) {
      continue;
    }
    if (seen.has(raw)) {
      continue;
    }
    seen.add(raw);
    results.push(raw);
    if (results.length >= maxLinks) {
      break;
    }
  }

  return results;
}
