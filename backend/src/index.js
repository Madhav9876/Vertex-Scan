// Vertex Scan - Main Server Entry Point
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');

const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const { globalLimiter } = require('./middleware/rateLimit');
const { requestContext, errorHandler, notFoundHandler, logSecurityEvent } = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 3001;

const isProduction = process.env.NODE_ENV === 'production';

// Middleware
app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  } : false,
  crossOriginEmbedderPolicy: false,
  hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
}));

const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  maxAge: 600,
  optionsSuccessStatus: 204,
}));

// Per-request context: correlation id, client IP, security headers
app.use(requestContext);

// Structured request logging (morgan) — safe, no body logging
app.use(morgan('dev', {
  skip: (req) => req.path === '/api/health',
}));

// Body parsing with strict size + content-type enforcement
app.use(express.json({
  limit: '1mb',
  type: ['application/json'],
  verify: (req, res, buf) => {
    if (buf.length > 1024 * 1024) {
      const err = new Error('Request payload too large');
      err.status = 413;
      throw err;
    }
  },
}));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Reject non-JSON bodies on API routes that expect JSON
app.use('/api', (req, res, next) => {
  if (['POST', 'PATCH', 'PUT'].includes(req.method) &&
      req.headers['content-type'] &&
      !req.headers['content-type'].includes('application/json')) {
    return res.status(415).json({ error: 'Content-Type must be application/json' });
  }
  next();
});

// Apply global rate limiting to all API routes
app.use('/api', globalLimiter);

// API Routes (unversioned base + /v1 alias for safe future evolution)
const apiRouter = express.Router();
apiRouter.use('/auth', authRoutes);
apiRouter.use('/scans', scanRoutes);
apiRouter.use('/reports', reportRoutes);
app.use('/api', apiRouter);
app.use('/api/v1', apiRouter);

// Health check
app.get('/api/health', healthHandler);
app.get('/api/v1/health', healthHandler);

function healthHandler(req, res) {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
}

// Unknown API routes -> 404 (no implementation details)
app.use('/api', notFoundHandler);

// Serve static frontend in production
if (process.env.NODE_ENV === 'production') {
  // Enforce HTTPS: redirect plain HTTP to HTTPS
  app.use((req, res, next) => {
    const proto = req.headers['x-forwarded-proto'];
    if (proto && proto !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
  app.use(express.static(path.join(__dirname, '../../frontend/dist')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/dist/index.html'));
  });
}

// Centralized, non-leaking error handler
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║          Vertex Scan v1.0.0              ║
║     Web Security Scanning Tool           ║
║──────────────────────────────────────────║
║  Server: http://localhost:${PORT}          ║
║  API:    http://localhost:${PORT}/api      ║
║  Health: http://localhost:${PORT}/api/health ║
╚══════════════════════════════════════════╝
  `);
  if (!isProduction) {
    logSecurityEvent('server_start', { env: process.env.NODE_ENV || 'development' }).catch(() => {});
  }
});

module.exports = app;