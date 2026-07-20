// Vertex Scan - Authentication Middleware
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db/connection');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start with a weak default.');
  process.exit(1);
}
// Dedicated secret for refresh tokens (falls back to the access secret if unset).
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
const JWT_ISSUER = process.env.JWT_ISSUER || 'vertex-scan';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'vertex-scan-client';
const JWT_REFRESH_ISSUER = `${JWT_ISSUER}-refresh`;

function generateToken(user) {
  const version = user.token_version != null ? user.token_version : 0;
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: `${user.id}:${version}`,
    },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }
  );
}

function generateRefreshToken(user) {
  const version = user.token_version != null ? user.token_version : 0;
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: `${user.id}:${version}`,
    },
    JWT_REFRESH_SECRET,
    {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
      issuer: JWT_REFRESH_ISSUER,
      audience: JWT_AUDIENCE,
    }
  );
}

function generateApiKey() {
  return 'vs_' + crypto.randomBytes(32).toString('hex');
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    // Check for API key
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      try {
        const result = await db.query(
          'SELECT id, email, role, full_name FROM users WHERE api_key = $1 AND is_active = true',
          [apiKey]
        );
        if (result.rows.length > 0) {
          req.user = result.rows[0];
          return next();
        }
      } catch (err) {
        return res.status(401).json({ error: 'Invalid API key' });
      }
    }
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    const result = await db.query(
      'SELECT id, email, role, full_name, token_version FROM users WHERE id = $1 AND is_active = true',
      [decoded.id]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    // Revocation: a bumped token_version invalidates all previously issued tokens.
    const expectedJti = `${result.rows[0].id}:${result.rows[0].token_version}`;
    if (decoded.jti !== expectedJti) {
      return res.status(401).json({ error: 'Token revoked. Please log in again.' });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Bump the user's token_version so all existing tokens are rejected.
async function revokeUserTokens(userId) {
  await db.query('UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = $1', [userId]);
}

// Validate a refresh token (stateless, same token_version revocation check).
// Returns the decoded payload or throws. Does NOT set req.user.
function verifyRefreshToken(token) {
  return jwt.verify(token, JWT_REFRESH_SECRET, {
    issuer: JWT_REFRESH_ISSUER,
    audience: JWT_AUDIENCE,
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = {
  generateToken,
  generateRefreshToken,
  generateApiKey,
  authenticateToken,
  verifyRefreshToken,
  requireRole,
  revokeUserTokens,
  JWT_SECRET,
};