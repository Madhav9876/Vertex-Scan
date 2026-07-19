// Vertex Scan - Input Validation & SSRF Protection
const dns = require('dns').promises;
const net = require('net');

const PRIVATE_RANGES = [
  { start: '10.0.0.0', end: '10.255.255.255' },
  { start: '127.0.0.0', end: '127.255.255.255' },
  { start: '169.254.0.0', end: '169.254.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' },
  { start: '0.0.0.0', end: '0.255.255.255' },
  { start: '100.64.0.0', end: '100.127.255.255' },
  { start: '192.0.0.0', end: '192.0.0.255' },
  { start: '192.0.2.0', end: '192.0.2.255' },
  { start: '198.18.0.0', end: '198.19.255.255' },
  { start: '198.51.100.0', end: '198.51.100.255' },
  { start: '203.0.113.0', end: '203.0.113.255' },
  { start: '224.0.0.0', end: '255.255.255.255' },
];

function ipToLong(ip) {
  if (!net.isIPv4(ip)) return null;
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function isPrivateIp(ip) {
  const long = ipToLong(ip);
  if (long === null) return false;
  return PRIVATE_RANGES.some(range => {
    const s = ipToLong(range.start);
    const e = ipToLong(range.end);
    return long >= s && long <= e;
  });
}

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) {
    return true;
  }
  return false;
}

// Validate URL format and enforce http/https only
function parseTargetUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { valid: false, error: 'Target URL is required' };
  }
  const candidate = raw.trim().startsWith('http') ? raw.trim() : `https://${raw.trim()}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only http and https targets are allowed' };
  }
  if (!parsed.hostname) {
    return { valid: false, error: 'URL must include a hostname' };
  }
  return { valid: true, url: parsed, normalized: candidate };
}

// Resolve hostname and ensure it does not point to a private/loopback/link-local address (SSRF guard).
// We RESOLVE ONCE and pin the validated address so the scanners connect to the exact
// IP we vetted (prevents DNS-rebinding / TOCTOU SSRF bypasses).
async function assertPublicTarget(raw) {
  const { valid, error, url, normalized } = parseTargetUrl(raw);
  if (!valid) return { valid: false, error };

  const hostname = url.hostname;
  const protocol = url.protocol;
  const port = url.port || (protocol === 'https:' ? 443 : 80);

  // Literal IP target
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      return { valid: false, error: 'Target resolves to a non-public address and is not allowed' };
    }
    return {
      valid: true,
      url,
      normalized,
      hostname,
      port: Number(port),
      resolvedAddress: hostname,
      family: net.isIPv6(hostname) ? 6 : 4,
    };
  }

  if (isBlockedHostname(hostname)) {
    return { valid: false, error: 'Target hostname is not allowed' };
  }

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    return { valid: false, error: 'Unable to resolve target hostname' };
  }

  if (!addresses.length) {
    return { valid: false, error: 'Unable to resolve target hostname' };
  }

  // Pick the first publicly-routable address; reject if all are private/blocked.
  for (const { address, family } of addresses) {
    if (net.isIPv6(address)) {
      if (address === '::1' || address.startsWith('fc') || address.startsWith('fd') ||
          address.startsWith('fe80') || address.startsWith('::')) {
        continue;
      }
    } else if (isPrivateIp(address)) {
      continue;
    }
    return {
      valid: true,
      url,
      normalized,
      hostname,
      port: Number(port),
      resolvedAddress: address,
      family: family === 6 || net.isIPv6(address) ? 6 : 4,
    };
  }

  return { valid: false, error: 'Target resolves to a non-public address and is not allowed' };
}

function isValidEmail(email) {
  return typeof email === 'string' &&
    email.length <= 255 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password) {
  return typeof password === 'string' &&
    password.length >= 8 &&
    password.length <= 128;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Build a request URL whose hostname is the SSRF-vetted resolved address, while
// preserving the original hostname in `target.hostname` for SNI/Host headers.
function buildPinnedUrl(target, forceProtocol) {
  const normalized = typeof target === 'string' ? target : target.normalized;
  const parsed = new URL(normalized);
  if (forceProtocol) parsed.protocol = forceProtocol;
  if (target && target.resolvedAddress) {
    parsed.hostname = target.resolvedAddress;
  }
  return parsed.toString();
}

// Pin an http(s) request `options` object to the resolved address so no further
// DNS lookup occurs against the (possibly attacker-controlled) original hostname.
function applyPinnedTarget(options, target) {
  if (target && target.resolvedAddress) {
    options.host = target.resolvedAddress;
    options.hostname = target.resolvedAddress;
    options.port = target.port;
    options.family = target.family;
    if (target.hostname) {
      options.servername = target.hostname;
      const defaultPort = parsed => parsed.protocol === 'https:' ? 443 : 80;
      const p = new URL(typeof target === 'string' ? target : target.normalized);
      const isDefault = !target.port || Number(target.port) === defaultPort(p);
      options.headers = options.headers || {};
      options.headers.Host = target.hostname + (isDefault ? '' : `:${target.port}`);
    }
  }
  return options;
}

module.exports = {
  parseTargetUrl,
  assertPublicTarget,
  buildPinnedUrl,
  applyPinnedTarget,
  isValidEmail,
  isValidPassword,
  isPrivateIp,
  escapeHtml,
};
