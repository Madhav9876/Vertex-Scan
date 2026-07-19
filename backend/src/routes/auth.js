// Vertex Scan - Authentication Routes
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { generateToken, generateApiKey, authenticateToken, revokeUserTokens } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const { isValidEmail, isValidPassword } = require('../utils/validation');
const { logSecurityEvent } = require('../middleware/security');

const MAX_LOGIN_FAILURES = 10;
const LOCKOUT_WINDOW_MINUTES = 15;

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

    // Create user
    const result = await db.query(
      `INSERT INTO users (email, password_hash, full_name) 
       VALUES ($1, $2, $3) RETURNING id, email, full_name, role, created_at`,
      [normalizedEmail, password_hash, (full_name && String(full_name).slice(0, 100)) || null]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    await logSecurityEvent('register_success', { ip: req.clientIp, email: normalizedEmail, user_id: user.id });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
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

    // Find user
    const result = await db.query(
      'SELECT id, email, password_hash, full_name, role, is_active FROM users WHERE email = $1',
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

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
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
    await logSecurityEvent('logout', { ip: req.clientIp, user_id: req.user.id });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error' });
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