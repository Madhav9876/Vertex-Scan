// Vertex Scan - OAuth Routes (Google)
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db/connection');
const { logSecurityEvent } = require('../middleware/security');
const { authLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Google OAuth callback handler
// POST /api/oauth/google
router.post('/google', authLimiter, async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: 'Google credential is required' });
    }

    // Verify the Google token
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (!googleRes.ok) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const googleData = await googleRes.json();

    const email = googleData.email;
    const googleId = googleData.sub;
    const fullName = googleData.name || '';
    const emailVerified = googleData.email_verified === 'true' || googleData.email_verified === true;

    // Check if user exists with this Google provider ID
    let userResult = await db.query(
      'SELECT id, email, full_name, role, is_active, email_verified FROM users WHERE provider_id = $1 AND auth_provider = $2',
      [googleId, 'google']
    );

    let user;
    let isNewUser = false;

    if (userResult.rows.length > 0) {
      // Existing Google OAuth user
      user = userResult.rows[0];

      // Update last login
      await db.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);
    } else {
      // Check if user exists with this email (link accounts or create new)
      userResult = await db.query('SELECT id, email, full_name, role, is_active, email_verified FROM users WHERE email = $1', [email]);

      if (userResult.rows.length > 0) {
        // User exists with email - link Google account
        user = userResult.rows[0];

        if (!user.is_active) {
          await logSecurityEvent('google_oauth_failed', { ip: req.clientIp, email, reason: 'inactive' });
          return res.status(403).json({ error: 'Account is deactivated' });
        }

        // Link Google OAuth to existing account
        await db.query(
          'UPDATE users SET provider_id = $1, auth_provider = $2, email_verified = $3 WHERE id = $4',
          [googleId, 'google', emailVerified, user.id]
        );

        await db.query(
          'INSERT INTO oauth_accounts (user_id, provider, provider_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, provider_id) DO NOTHING',
          [user.id, 'google', googleId, email]
        );
      } else {
        // Create new user with Google OAuth
        isNewUser = true;
        const result = await db.query(
          `INSERT INTO users (email, full_name, auth_provider, provider_id, email_verified, password_hash)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, email, full_name, role, is_active, email_verified`,
          [email, fullName, 'google', googleId, emailVerified, null]
        );
        user = result.rows[0];

        // Insert into oauth_accounts
        await db.query(
          'INSERT INTO oauth_accounts (user_id, provider, provider_id, email) VALUES ($1, $2, $3, $4)',
          [user.id, 'google', googleId, email]
        );
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    // Log the event
    await logSecurityEvent(
      'google_oauth_success',
      { ip: req.clientIp, email, user_id: user.id, is_new_user: isNewUser }
    );

    res.json({
      message: isNewUser ? 'Account created with Google' : 'Logged in with Google',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.error('Google OAuth error:', err);
    await logSecurityEvent('google_oauth_failed', { ip: req.clientIp, error: err.message });
    res.status(500).json({ error: 'Authentication failed' });
  }
});

module.exports = router;