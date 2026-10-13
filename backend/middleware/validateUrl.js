/**
 * SSRF Prevention — URL Validator  (middleware/validateUrl.js)
 *
 * Blocks requests to:
 *  - Private / loopback IP ranges (RFC 1918, RFC 4193, link-local)
 *  - Cloud metadata endpoints (169.254.169.254, etc.)
 *  - Internal hostnames (localhost, *.local, *.internal)
 *  - Non-HTTP/HTTPS schemes (file://, gopher://, dict://, ftp://, etc.)
 *  - Arbitrary HTTP methods (only a safe allowlist is permitted)
 *
 * Call validateExternalUrl(rawUrl) before any outbound axios request.
 * It returns the parsed URL if valid, or throws an Error with a safe message.
 */

import dns from 'dns/promises';
import net from 'net';

// ── Blocked IP ranges (SSRF / CSRF protection) ────────────────────────────────

const BLOCKED_CIDRS = [
  // IPv4 loopback
  { start: ipToLong('127.0.0.0'),     end: ipToLong('127.255.255.255') },
  // RFC 1918 private ranges
  { start: ipToLong('10.0.0.0'),      end: ipToLong('10.255.255.255')  },
  { start: ipToLong('172.16.0.0'),    end: ipToLong('172.31.255.255')  },
  { start: ipToLong('192.168.0.0'),   end: ipToLong('192.168.255.255') },
  // Link-local / APIPA (cloud metadata endpoints use this!)
  { start: ipToLong('169.254.0.0'),   end: ipToLong('169.254.255.255') },
  // Unique local (IPv6-style carried in IPv4-mapped)
  { start: ipToLong('100.64.0.0'),    end: ipToLong('100.127.255.255') },
  // Broadcast
  { start: ipToLong('255.255.255.255'), end: ipToLong('255.255.255.255') },
  // Unspecified
  { start: ipToLong('0.0.0.0'),       end: ipToLong('0.255.255.255')   },
];

const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.intranet$/i,
  /\.corp$/i,
  /^metadata\.google\.internal$/i,
];

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// ── Allowed HTTP methods for the API analyzer ─────────────────────────────────
export const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

// ── Helpers ───────────────────────────────────────────────────────────────────

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isBlockedIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const long = ipToLong(ip);
  return BLOCKED_CIDRS.some(({ start, end }) => long >= start && long <= end);
}

function isBlockedIPv6(ip) {
  const cleaned = ip.replace(/[\[\]]/g, '');
  // Block loopback (::1), unspecified (::), link-local (fe80::/10)
  return (
    cleaned === '::1' ||
    cleaned === '::' ||
    /^fe80:/i.test(cleaned) ||
    /^fc00:/i.test(cleaned) ||
    /^fd00:/i.test(cleaned) ||
    // IPv4-mapped IPv6 addresses like ::ffff:169.254.x.x
    /^::ffff:/i.test(cleaned)
  );
}

// ── Main validator ────────────────────────────────────────────────────────────

/**
 * Validate that a URL is safe for outbound requests from this server.
 * Resolves the hostname to an IP and checks it against blocked ranges.
 *
 * @param {string} rawUrl  URL string from user input
 * @returns {Promise<URL>} The parsed URL object if safe
 * @throws {Error}         Descriptive error if the URL is blocked or invalid
 */
export async function validateExternalUrl(rawUrl) {
  // 1. Must be a string
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new Error('URL must be a non-empty string');
  }

  // 2. Parse and validate structure
  let parsed;
  try {
    // Prepend https:// if no scheme provided
    const withScheme = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
    parsed = new URL(withScheme);
  } catch {
    throw new Error('Invalid URL format — please provide a valid URL (e.g. https://example.com)');
  }

  // 3. Scheme must be http or https
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    throw new Error(`Scheme "${parsed.protocol}" is not allowed — only http:// and https:// are permitted`);
  }

  const hostname = parsed.hostname;

  // 4. Block known-bad hostnames before DNS resolution
  if (BLOCKED_HOSTNAME_PATTERNS.some(p => p.test(hostname))) {
    throw new Error(`Hostname "${hostname}" is not allowed — internal hostnames are blocked`);
  }

  // 5. If the hostname is already an IP, check it directly
  if (net.isIPv4(hostname)) {
    if (isBlockedIPv4(hostname)) {
      throw new Error(`IP address "${hostname}" is in a blocked private/reserved range`);
    }
    return parsed;
  }

  if (net.isIPv6(hostname)) {
    if (isBlockedIPv6(hostname)) {
      throw new Error(`IPv6 address "${hostname}" is in a blocked private/reserved range`);
    }
    return parsed;
  }

  // 6. Resolve hostname to IPs and check each resolved address
  let addresses;
  try {
    addresses = await dns.resolve4(hostname).catch(() => []);
    const v6 = await dns.resolve6(hostname).catch(() => []);
    addresses = [...addresses, ...v6];
  } catch {
    throw new Error(`Could not resolve hostname "${hostname}"`);
  }

  if (addresses.length === 0) {
    throw new Error(`Hostname "${hostname}" could not be resolved to any IP address`);
  }

  for (const addr of addresses) {
    if (net.isIPv4(addr) && isBlockedIPv4(addr)) {
      throw new Error(`Hostname "${hostname}" resolves to a blocked private IP (${addr})`);
    }
    if (net.isIPv6(addr) && isBlockedIPv6(addr)) {
      throw new Error(`Hostname "${hostname}" resolves to a blocked private IPv6 (${addr})`);
    }
  }

  return parsed;
}

/**
 * Validate that a method string is in the safe allowlist.
 * @param {string} method
 * @returns {string} Uppercase method if valid
 * @throws {Error}   If not in allowlist
 */
export function validateMethod(method) {
  const upper = typeof method === 'string' ? method.trim().toUpperCase() : '';
  if (!ALLOWED_METHODS.has(upper)) {
    throw new Error(`HTTP method "${method}" is not allowed — permitted: ${[...ALLOWED_METHODS].join(', ')}`);
  }
  return upper;
}

/**
 * Sanitize user-supplied headers before forwarding.
 * Strips any hop-by-hop headers and limits what can be forwarded.
 * @param {object} rawHeaders  Headers from req.body.headers
 * @returns {object}           Safe, filtered headers object
 */
export function sanitizeForwardedHeaders(rawHeaders) {
  if (!rawHeaders || typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) return {};

  // Only allow these safe, non-sensitive headers to be forwarded
  const ALLOWED_FORWARD_HEADERS = new Set([
    'accept',
    'accept-language',
    'accept-encoding',
    'content-type',
    'cache-control',
    'x-requested-with',
  ]);

  const safe = {};
  for (const [key, value] of Object.entries(rawHeaders)) {
    const lowerKey = String(key).toLowerCase().trim();
    // Only forward explicitly allowed headers
    if (ALLOWED_FORWARD_HEADERS.has(lowerKey)) {
      // Prevent CRLF injection in header values
      const safeValue = String(value).replace(/[\r\n]/g, '');
      safe[lowerKey] = safeValue;
    }
  }
  return safe;
}
