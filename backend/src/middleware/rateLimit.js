// Vertex Scan - Rate Limiting Middleware
const rateLimit = require('express-rate-limit');

const standardHeaders = true;
const legacyHeaders = false;

// Global limiter: protects the whole API from abuse / DoS
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders,
  legacyHeaders,
  message: { error: 'Too many requests, please try again later.' },
});

// Strict limiter for authentication endpoints (brute-force / credential stuffing protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders,
  legacyHeaders,
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts, please try again later.' },
});

// Limiter for scan creation (resource abuse / cost control)
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders,
  legacyHeaders,
  message: { error: 'Scan creation rate limit exceeded, please slow down.' },
});

// Limiter for password reset endpoints (abuse / token bombing protection)
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders,
  legacyHeaders,
  message: { error: 'Too many password reset attempts, please try again later.' },
});

module.exports = { globalLimiter, authLimiter, scanLimiter, passwordResetLimiter };
