// Vertex Scan - Authentication Routes
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { generateToken, generateRefreshToken, generateApiKey, authenticateToken, verifyRefreshToken, revokeUserTokens } = require('../middleware/auth');
const { authLimiter, passwordResetLimiter } = require('../middleware/rateLimit');
const { isValidEmail, isValidPassword } = require('../utils/validation');
const { logSecurityEvent } = require('../middleware/security');
const { sendMail, buildResetEmail } = require('../utils/mailer');

const MAX_LOGIN_FAILURES = 10;
const LOCKOUT_WINDOW_MINUTES = 15;
const RESET_TOKEN_BYTES = 32;
const RESET_TOKEN_TTL_MINUTES = Number(process.env.PASSWORD_RESET_TTL_MINUTES || 30);

// Set the httpOnly refresh-token cookie. Works across the Vite dev proxy
// (same-origin /api) and in production.
function setRefreshCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('vs_refresh', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/api',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('vs_refresh', { path: '/api', httpOnly: true });
}

// Count recent failed logins for an email (brute-force / anomaly detection)
async function recentFailureCount(email) {
  const res = await db.query(
    `SELECT COUNT(*) AS c FROM security_events
     WHERE event = 'login_failed' AND email = $1
       AND created_at > NOW() - ($2 || ' minutes')::interval`,
    [email, LOCKOUT_WINDOW_MINUTES]
  );
  return parseInt(res.rows[0].c, 10);
}

const router = express.Router();

// POST /api/auth/register
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password, full_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8-128 characters long' });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    // Check if user exists
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      await logSecurityEvent('register_duplicate', { ip: req.clientIp, email: normalizedEmail });
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(password, salt);

    // Create user - explicitly set auth_provider to 'local' and get all needed fields including token_version
    const result = await db.query(
      `INSERT INTO users (email, password_hash, full_name, auth_provider, updated_at) 
       VALUES ($1, $2, $3, 'local', NOW()) RETURNING id, email, full_name, role, token_version, created_at`,
      [normalizedEmail, password_hash, (full_name && String(full_name).slice(0, 100)) || null]
    );

    const user = result.rows[0];
    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);
    setRefreshCookie(res, refreshToken);

    await logSecurityEvent('register_success', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token,
      refresh_token: refreshToken,
    });
  } catch (err) {
    console.error('Registration error:', err);

    // Surface safe, actionable errors instead of a generic 500 so the client
    // can show a meaningful message (e.g. duplicate email, DB connection issue).
    const code = err && err.code;
    const isDev = process.env.NODE_ENV !== 'production';
    
    if (code === '23505') {
      const normalizedEmail = String(email || '').toLowerCase().trim();
      await logSecurityEvent('register_duplicate', { ip: req.clientIp, email: normalizedEmail }).catch(() => {});
      return res.status(409).json({ error: 'Email already registered' });
    }
    if (code === '42P01' || code === '42703') {
      return res.status(500).json({ error: 'Database schema is missing. Run `npm run migrate`.' });
    }
    if (code === 'ECONNREFUSED' || code === 'ETIMEDOUT' || code === '57P01' || (err && /connection/i.test(err.message || ''))) {
      return res.status(503).json({ error: 'Unable to reach the database. Please try again later.' });
    }
    if (err && err.message) {
      // Return specific error in development for debugging
      const details = isDev ? err.message : 'Please try again.';
      const hint = isDev && err.code === '42P01'
        ? ' The users table may not exist. Run `npm run migrate` to create it.'
        : '';
      return res.status(500).json({ error: `Registration failed: ${details}${hint}` });
    }

    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// POST /api/auth/login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!isValidEmail(email) || !isValidPassword(password)) {
      await logSecurityEvent('login_invalid_input', { ip: req.clientIp, email: String(email).toLowerCase().trim() });
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    // Brute-force / anomaly protection: temporary lockout
    const failures = await recentFailureCount(normalizedEmail);
    if (failures >= MAX_LOGIN_FAILURES) {
      await logSecurityEvent('login_lockout', { ip: req.clientIp, email: normalizedEmail, failures });
      return res.status(429).json({
        error: `Too many failed attempts. Account temporarily locked for ${LOCKOUT_WINDOW_MINUTES} minutes.`
      });
    }

    // Find user - include token_version for proper token generation
    const result = await db.query(
      'SELECT id, email, password_hash, full_name, role, is_active, token_version FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      await logSecurityEvent('login_failed', { ip: req.clientIp, email: normalizedEmail, reason: 'no_such_user' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      await logSecurityEvent('login_failed', { ip: req.clientIp, email: normalizedEmail, reason: 'inactive' });
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      await logSecurityEvent('login_failed', { ip: req.clientIp, email: normalizedEmail, reason: 'bad_password' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Successful login: clear failure counter by logging success, update last login
    await db.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);
    await logSecurityEvent('login_success', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);
    setRefreshCookie(res, refreshToken);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token,
      refresh_token: refreshToken,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/forgot-password — generate a reset token and email it to the user.
// Always returns 200 (same response whether or not the email exists) to avoid
// leaking which addresses are registered.
router.post('/forgot-password', passwordResetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = email ? String(email).toLowerCase().trim() : '';

    if (isValidEmail(normalizedEmail)) {
      const result = await db.query(
        'SELECT id, email, full_name, auth_provider FROM users WHERE email = $1 AND is_active = true',
        [normalizedEmail]
      );

      if (result.rows.length > 0) {
        const user = result.rows[0];
        // Only local accounts have a password to reset.
        if (user.auth_provider === 'local') {
          const token = crypto.randomBytes(RESET_TOKEN_BYTES).toString('hex');
          const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000);

          await db.query(
            'UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = NOW() WHERE id = $3',
            [token, expiresAt, user.id]
          );

          const baseUrl = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
          const resetUrl = `${baseUrl}/reset-password?token=${token}`;
          const mail = buildResetEmail({ email: user.email, resetUrl, expiresMinutes: RESET_TOKEN_TTL_MINUTES });
          try {
            await sendMail({ to: user.email, ...mail });
          } catch (mailErr) {
            console.error('Reset email send failed:', mailErr);
            await logSecurityEvent('password_reset_email_failed', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });
          }
          await logSecurityEvent('password_reset_requested', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });
        } else {
          await logSecurityEvent('password_reset_unsupported_provider', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });
        }
      } else {
        await logSecurityEvent('password_reset_unknown_email', { ip: req.clientIp, email: normalizedEmail });
      }
    }

    res.json({ message: 'If an account exists for that email, a password reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Unable to process request. Please try again later.' });
  }
});

// POST /api/auth/reset-password — verify token and set a new password.
router.post('/reset-password', passwordResetLimiter, async (req, res) => {
  try {
    const { token, new_password } = req.body;

    if (!token || !new_password) {
      return res.status(400).json({ error: 'Reset token and new password are required' });
    }
    if (!isValidPassword(new_password)) {
      return res.status(400).json({ error: 'New password must be 8-128 characters long' });
    }

    const result = await db.query(
      'SELECT id, email, password_reset_token, password_reset_expires_at FROM users WHERE password_reset_token = $1',
      [String(token)]
    );

    if (result.rows.length === 0) {
      await logSecurityEvent('password_reset_invalid_token', { ip: req.clientIp });
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const user = result.rows[0];
    if (!user.password_reset_expires_at || new Date(user.password_reset_expires_at).getTime() < Date.now()) {
      await db.query('UPDATE users SET password_reset_token = NULL, password_reset_expires_at = NULL WHERE id = $1', [user.id]);
      await logSecurityEvent('password_reset_expired_token', { ip: req.clientIp, user_id: user.id });
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(new_password, salt);

    await db.query(
      'UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL, token_version = COALESCE(token_version, 0) + 1, updated_at = NOW() WHERE id = $2',
      [password_hash, user.id]
    );

    await logSecurityEvent('password_reset_success', { ip: req.clientIp, email: user.email, user_id: user.id });

    res.json({ message: 'Password has been reset. You can now sign in with your new password.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Unable to reset password. Please try again later.' });
  }
});

// GET /api/auth/me
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, email, full_name, role, is_active, email_verified, created_at, last_login_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout — invalidate all of the user's current tokens
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await revokeUserTokens(req.user.id);
    clearRefreshCookie(res);
    await logSecurityEvent('logout', { ip: req.clientIp, user_id: req.user.id });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh — exchange a valid refresh cookie for a new access token.
// Used by the frontend automatically when the short-lived access token expires,
// so users stay signed in without re-entering credentials.
router.post('/refresh', async (req, res) => {
  try {
    // Prefer the httpOnly cookie, but fall back to a body/header refresh token
    // so the flow also works when cookies are blocked (e.g. cross-origin prod).
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.match(/(?:^|;\s*)vs_refresh=([^;]+)/);
    const cookieToken = match ? decodeURIComponent(match[1]) : null;
    const refreshToken = cookieToken || req.body?.refresh_token || req.headers['x-refresh-token'] || null;

    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token. Please log in again.' });
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired session. Please log in again.' });
    }

    // Confirm the user still exists and the token hasn't been revoked.
    const result = await db.query(
      'SELECT id, email, full_name, role, is_active, token_version FROM users WHERE id = $1 AND is_active = true',
      [decoded.id]
    );
    if (result.rows.length === 0) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    const expectedJti = `${result.rows[0].id}:${result.rows[0].token_version}`;
    if (decoded.jti !== expectedJti) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Session revoked. Please log in again.' });
    }

    const user = result.rows[0];
    const newToken = generateToken(user);
    const newRefresh = generateRefreshToken(user);
    setRefreshCookie(res, newRefresh);

    res.json({
      token: newToken,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Unable to refresh session. Please log in again.' });
  }
});

// POST /api/auth/api-key — generate (or rotate) the user's API key.
// Rotating the key also revokes all existing JWT sessions (token_version bump)
// so a leaked session cannot keep using the API after the key changes.
router.post('/api-key', authenticateToken, async (req, res) => {
  try {
    const apiKey = generateApiKey();
    const result = await db.query(
      `UPDATE users SET api_key = $1, token_version = COALESCE(token_version, 0) + 1, updated_at = NOW()
       WHERE id = $2 RETURNING api_key`,
      [apiKey, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    await logSecurityEvent('api_key_generated', { ip: req.clientIp, user_id: req.user.id });
    res.json({ message: 'API key generated', api_key: result.rows[0].api_key });
  } catch (err) {
    console.error('API key generation error:', err);
    res.status(500).json({ error: 'Unable to generate API key. Please try again.' });
  }
});

// PATCH /api/auth/password — change password (revokes all sessions after success)
router.patch('/password', authenticateToken, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    if (!isValidPassword(new_password)) {
      return res.status(400).json({ error: 'New password must be 8-128 characters long' });
    }

    const result = await db.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const valid = await bcrypt.compare(current_password, result.rows[0].password_hash);
    if (!valid) {
      await logSecurityEvent('password_change_failed', { ip: req.clientIp, user_id: req.user.id, reason: 'bad_current' });
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(new_password, salt);

    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [password_hash, req.user.id]);
    await revokeUserTokens(req.user.id);
    await logSecurityEvent('password_changed', { ip: req.clientIp, user_id: req.user.id });

    res.json({ message: 'Password updated successfully. Please log in again.' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;