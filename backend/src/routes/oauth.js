// Vertex Scan - OAuth Routes (Google)
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db/connection');
const { generateToken } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/security');
const { authLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Google's public signing keys (JWKS) are cached for 1h to avoid re-fetching
// on every login. Re-fetched automatically once stale or on key rotation.
let cachedKeys = null;
let cachedKeysAt = 0;
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const KEYS_TTL_MS = 60 * 60 * 1000;

async function getGooglePublicKeys() {
  if (cachedKeys && Date.now() - cachedKeysAt < KEYS_TTL_MS) {
    return cachedKeys;
  }
  const res = await fetch(GOOGLE_CERTS_URL, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    throw new Error('Failed to fetch Google signing keys');
  }
  const data = await res.json();
  const keys = {};
  for (const k of data.keys || []) {
    keys[k.kid] = k;
  }
  cachedKeys = keys;
  cachedKeysAt = Date.now();
  return keys;
}

// Verify a Google-issued ID token against Google's public certs.
// Returns the decoded payload, or throws a specific, actionable error.
async function verifyGoogleIdToken(idToken) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error('GOOGLE_CLIENT_ID is not configured on the server');
  }

  // Decode header without verifying to find the key id (kid).
  const decodedHeader = jwt.decode(idToken, { complete: true });
  if (!decodedHeader || !decodedHeader.header || !decodedHeader.header.kid) {
    throw new Error('Malformed Google token');
  }

  const keys = await getGooglePublicKeys();
  const jwk = keys[decodedHeader.header.kid];
  if (!jwk) {
    throw new Error('Unknown Google signing key');
  }

  // Convert JWK to a PEM public key that jsonwebtoken can use.
  const pem = crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' });

  let payload;
  try {
    payload = jwt.verify(idToken, pem, {
      algorithms: ['RS256'],
      issuer: ['accounts.google.com', 'https://accounts.google.com'],
      audience: clientId,
    });
  } catch (err) {
    let hint = err.message;
    // The most common production failure is a frontend/backend client-ID mismatch.
    if (/audience/i.test(err.message)) {
      hint += ' — the token was issued for a different OAuth client ID than GOOGLE_CLIENT_ID. ' +
        'Ensure the frontend VITE_GOOGLE_CLIENT_ID and backend GOOGLE_CLIENT_ID are identical.';
    }
    throw new Error('Google token verification failed: ' + hint);
  }

  if (!payload.email) {
    throw new Error('Google token is missing an email');
  }

  return payload;
}

// Google OAuth callback handler
// POST /api/oauth/google
router.post('/google', authLimiter, async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: 'Google credential is required' });
    }

    // Verify the Google ID token cryptographically using Google's public keys.
    let googleData;
    try {
      googleData = await verifyGoogleIdToken(credential);
    } catch (verifyErr) {
      console.error('Google token verification failed:', verifyErr.message);
      await logSecurityEvent('google_oauth_failed', { ip: req.clientIp, reason: 'token_verify', error: verifyErr.message });
      const devDetail = process.env.NODE_ENV !== 'production' ? ` (${verifyErr.message})` : '';
      return res.status(401).json({ error: `Invalid Google token${devDetail}` });
    }

    const email = googleData.email;
    const googleId = googleData.sub;
    const fullName = googleData.name || '';
    const emailVerified = googleData.email_verified === true;

    // Check if user exists with this Google provider ID
    let userResult = await db.query(
      'SELECT id, email, full_name, role, is_active, email_verified, token_version FROM users WHERE provider_id = $1 AND auth_provider = $2',
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
      userResult = await db.query('SELECT id, email, full_name, role, is_active, email_verified, token_version FROM users WHERE email = $1', [email]);

      if (userResult.rows.length > 0) {
        const existing = userResult.rows[0];

        if (!existing.is_active) {
          await logSecurityEvent('google_oauth_failed', { ip: req.clientIp, email, reason: 'inactive' });
          return res.status(403).json({ error: 'Account is deactivated' });
        }

        // Account-linking takeover protection: only merge the Google identity into
        // the existing account when Google has actually verified ownership of this
        // email. An unverified Google email must not be allowed to hijack a local
        // (password-based) account that uses the same address.
        if (!emailVerified) {
          await logSecurityEvent('google_oauth_failed', {
            ip: req.clientIp, email, reason: 'email_unverified_link_blocked',
          });
          return res.status(403).json({
            error: 'This Google account email is not verified. Please use a verified Google account or sign in with your password.',
          });
        }

        // Link Google OAuth to existing account
        user = existing;
        await db.query(
          'UPDATE users SET provider_id = $1, auth_provider = $2, email_verified = $3 WHERE id = $4',
          [googleId, 'google', emailVerified, user.id]
        );

        await db.query(
          'INSERT INTO oauth_accounts (user_id, provider, provider_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, provider_id) DO NOTHING',
          [user.id, 'google', googleId, email]
        );

        // Refresh user data to include token_version
        userResult = await db.query(
          'SELECT id, email, full_name, role, is_active, email_verified, token_version FROM users WHERE id = $1',
          [user.id]
        );
        user = userResult.rows[0];
      } else {
        // Create new user with Google OAuth
        isNewUser = true;
        const result = await db.query(
          `INSERT INTO users (email, full_name, auth_provider, provider_id, email_verified)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, email, full_name, role, is_active, email_verified, token_version`,
          [email, fullName, 'google', googleId, emailVerified]
        );
        user = result.rows[0];

        // Insert into oauth_accounts
        await db.query(
          'INSERT INTO oauth_accounts (user_id, provider, provider_id, email) VALUES ($1, $2, $3, $4)',
          [user.id, 'google', googleId, email]
        );
      }
    }

    // Generate JWT token using the shared function (ensures consistent token format)
    const token = generateToken(user);

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
    const isDev = process.env.NODE_ENV !== 'production';
    const detail = isDev && err && err.message ? `: ${err.message}` : '';
    res.status(500).json({ error: `Authentication failed${detail}` });
  }
});

module.exports = router;