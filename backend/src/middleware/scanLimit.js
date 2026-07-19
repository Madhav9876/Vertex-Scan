// Vertex Scan - Scan abuse protection (concurrency + daily quota)
const db = require('../db/connection');
const { logSecurityEvent } = require('../middleware/security');

const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS, 10) || 3;
const MAX_SCANS_PER_USER_PER_DAY = parseInt(process.env.MAX_SCANS_PER_USER_PER_DAY, 10) || 50;

// Reject if the user already has too many scans running concurrently
// (prevents one user from saturating outbound scanning / abuse).
async function enforceScanQuota(req, res, next) {
  try {
    const running = await db.query(
      `SELECT COUNT(*) AS c FROM scans
       WHERE user_id = $1 AND status IN ('pending', 'running')`,
      [req.user.id]
    );
    if (parseInt(running.rows[0].c, 10) >= MAX_CONCURRENT_SCANS) {
      await logSecurityEvent('scan_quota_exceeded', {
        ip: req.clientIp, user_id: req.user.id, reason: 'concurrency',
      });
      return res.status(429).json({
        error: `Too many scans in progress. Limit ${MAX_CONCURRENT_SCANS} concurrent scans.`,
      });
    }

    const today = await db.query(
      `SELECT COUNT(*) AS c FROM scans
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 day'`,
      [req.user.id]
    );
    if (parseInt(today.rows[0].c, 10) >= MAX_SCANS_PER_USER_PER_DAY) {
      await logSecurityEvent('scan_quota_exceeded', {
        ip: req.clientIp, user_id: req.user.id, reason: 'daily',
      });
      return res.status(429).json({
        error: `Daily scan limit reached (${MAX_SCANS_PER_USER_PER_DAY}). Try again tomorrow.`,
      });
    }

    next();
  } catch (err) {
    console.error('Scan quota error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = { enforceScanQuota, MAX_CONCURRENT_SCANS, MAX_SCANS_PER_USER_PER_DAY };
