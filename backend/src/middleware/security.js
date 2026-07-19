// Vertex Scan - Security & Audit Logging Middleware
const crypto = require('crypto');
const db = require('../db/connection');

const SENSITIVE_KEYS = new Set([
  'password', 'password_hash', 'token', 'authorization', 'x-api-key',
  'api_key', 'apikey', 'secret', 'jwt', 'cookie', 'refresh_token'
]);

function redact(value) {
  if (value === undefined || value === null) return value;
  if (typeof value === 'string') {
    return value.length > 8 ? value.slice(0, 4) + '…[redacted]' : '…[redacted]';
  }
  return value;
}

// Attach a correlation id and capture the real client IP
function requestContext(req, res, next) {
  req.requestId = crypto.randomUUID();
  req.clientIp = req.ip ||
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket.remoteAddress;
  res.setHeader('X-Request-Id', req.requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  next();
}

// Structured security event logger. Never logs secrets.
async function logSecurityEvent(event, details = {}) {
  const safe = {};
  for (const [k, v] of Object.entries(details)) {
    safe[k] = SENSITIVE_KEYS.has(k.toLowerCase()) ? redact(v) : v;
  }
  const row = {
    event,
    ip: safe.ip,
    email: safe.email,
    user_id: safe.user_id,
    details: JSON.stringify(safe),
    created_at: new Date().toISOString(),
  };
  try {
    await db.query(
      `INSERT INTO security_events (event, ip, email, user_id, details, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [row.event, row.ip || null, row.email || null, row.user_id || null, row.details, row.created_at]
    );
  } catch (err) {
    // Logging must never break the request path
    console.error('Security event log failed:', err.message);
  }
  if (process.env.NODE_ENV !== 'test') {
    console.warn(`[SECURITY] ${event}`, row.details);
  }
}

// Generic error handler: never leak implementation details in production
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  // CORS rejection already handled separately; re-check here for safety
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Not allowed by CORS' });
  }

  const status = err.status || 500;
  const isProd = process.env.NODE_ENV === 'production';

  if (status >= 500) {
    logSecurityEvent('server_error', {
      ip: req.clientIp,
      requestId: req.requestId,
      path: req.originalUrl,
      method: req.method,
      message: isProd ? undefined : err.message,
    }).catch(() => {});
  }

  res.status(status).json({
    error: isProd ? 'Internal server error' : (err.message || 'Internal server error'),
  });
}

// 404 handler for unknown API routes
function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Not found' });
}

module.exports = {
  requestContext,
  logSecurityEvent,
  errorHandler,
  notFoundHandler,
  SENSITIVE_KEYS,
  redact,
};
