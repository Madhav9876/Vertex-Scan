// Vertex Scan - Scan Routes
const express = require('express');
const db = require('../db/connection');
const { authenticateToken } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimit');
const { enforceScanQuota } = require('../middleware/scanLimit');
const { assertPublicTarget, isValidEmail } = require('../utils/validation');
const { runScan } = require('../scanners/orchestrator');
const { logSecurityEvent } = require('../middleware/security');

const router = express.Router();

// GET /api/scans - List user's scans
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 25, offset = 0 } = req.query;
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 25, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);
    let query = 'SELECT * FROM scans WHERE user_id = $1';
    const params = [req.user.id];

    if (status) {
      query += ' AND status = $2';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    params.push(safeLimit, safeOffset);

    const result = await db.query(query, params);

    // Get total count
    let countQuery = 'SELECT COUNT(*) FROM scans WHERE user_id = $1';
    const countParams = [req.user.id];
    if (status) {
      countQuery += ' AND status = $2';
      countParams.push(status);
    }
    const countResult = await db.query(countQuery, countParams);

    res.json({
      scans: result.rows,
      total: parseInt(countResult.rows[0].count),
      limit: safeLimit,
      offset: safeOffset
    });
  } catch (err) {
    console.error('List scans error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/scans - Create a new scan
router.post('/', authenticateToken, scanLimiter, enforceScanQuota, async (req, res) => {
  try {
    const { target_url, modules, options } = req.body;

    if (!target_url) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    // SSRF guard: resolve and reject non-public targets
    const target = await assertPublicTarget(target_url);
    if (!target.valid) {
      await logSecurityEvent('scan_ssrf_blocked', {
        ip: req.clientIp, user_id: req.user.id, target: String(target_url), reason: target.error,
      });
      return res.status(400).json({ error: target.error });
    }

    // Validate and constrain modules. Default all on when omitted.
    const allowedModules = ['headers', 'tls', 'directories'];
    const sourceModules = modules && typeof modules === 'object' ? modules : { headers: true, tls: true, directories: true };
    const scanModules = allowedModules.reduce((acc, m) => {
      acc[m] = Boolean(sourceModules[m]);
      return acc;
    }, {});

    if (!allowedModules.some(m => scanModules[m])) {
      return res.status(400).json({ error: 'At least one scanning module must be enabled' });
    }

    // Validate options
    const scanOptions = {};
    if (options && typeof options === 'object') {
      const timeout = Number(options.timeout);
      scanOptions.timeout = Number.isFinite(timeout)
        ? Math.min(Math.max(Math.trunc(timeout), 5), 120)
        : 30;
      if (typeof options.user_agent === 'string') {
        scanOptions.user_agent = options.user_agent.slice(0, 256);
      }
    }

    const scan = (await db.query(
      `INSERT INTO scans (user_id, target_url, modules, options, status)
       VALUES ($1, $2, $3, $4, 'pending') RETURNING *`,
      [req.user.id, target.normalized, JSON.stringify(scanModules), JSON.stringify(scanOptions)]
    )).rows[0];

    // Log scan creation
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)',
      [scan.id, 'created', req.user.id, req.ip, req.get('user-agent')]
    );

    // Start scan asynchronously
    runScan(scan.id, req.user.id).catch(err => {
      console.error(`Background scan ${scan.id} failed:`, err);
    });

    res.status(201).json({
      message: 'Scan created successfully',
      scan
    });
  } catch (err) {
    console.error('Create scan error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/scans/stats - Get scan statistics
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await db.query(`
      SELECT 
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
        COUNT(*) FILTER (WHERE status = 'running') as running_scans,
        COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
        ROUND(AVG(score)) as average_score,
        COUNT(*) FILTER (WHERE score >= 90) as a_grade_count,
        COUNT(*) FILTER (WHERE score >= 80 AND score < 90) as b_grade_count,
        COUNT(*) FILTER (WHERE score < 80) as below_b_count
      FROM scans WHERE user_id = $1
    `, [req.user.id]);

    // Get critical findings count
    const criticalFindings = await db.query(`
      SELECT COUNT(*) as count FROM findings f
      JOIN scans s ON f.scan_id = s.id
      WHERE s.user_id = $1 AND f.severity = 'critical' AND f.is_resolved = false
    `, [req.user.id]);

    // Get last scan
    const lastScan = await db.query(
      'SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [req.user.id]
    );

    res.json({
      stats: {
        ...stats.rows[0],
        critical_findings: parseInt(criticalFindings.rows[0].count),
        last_scan: lastScan.rows[0] || null
      }
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/scans/:id - Get scan details
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const scan = result.rows[0];

    // Get findings
    const findings = await db.query(
      `SELECT * FROM findings WHERE scan_id = $1 ORDER BY 
       CASE severity 
         WHEN 'critical' THEN 1 
         WHEN 'high' THEN 2 
         WHEN 'medium' THEN 3 
         WHEN 'low' THEN 4 
         WHEN 'info' THEN 5 
       END, created_at ASC`,
      [req.params.id]
    );

    // Get modules
    const modules = await db.query(
      'SELECT * FROM scan_modules WHERE scan_id = $1',
      [req.params.id]
    );

    // Get history
    const history = await db.query(
      'SELECT * FROM scan_history WHERE scan_id = $1 ORDER BY created_at ASC',
      [req.params.id]
    );

    res.json({
      scan,
      findings: findings.rows,
      modules: modules.rows,
      history: history.rows
    });
  } catch (err) {
    console.error('Get scan error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/scans/:id - Delete a scan
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM scans WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Log deletion
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by) VALUES ($1, $2, $3)',
      [req.params.id, 'deleted', req.user.id]
    );

    res.json({ message: 'Scan deleted successfully' });
  } catch (err) {
    console.error('Delete scan error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/scans/:id/findings/:findingId - Update finding (mark resolved/false positive)
router.patch('/:id/findings/:findingId', authenticateToken, async (req, res) => {
  try {
    const { is_resolved, is_false_positive } = req.body;
    
    const result = await db.query(
      `UPDATE findings SET 
        is_resolved = COALESCE($1, is_resolved),
        is_false_positive = COALESCE($2, is_false_positive)
       WHERE id = $3 AND scan_id IN (SELECT id FROM scans WHERE id = $4 AND user_id = $5)
       RETURNING *`,
      [is_resolved, is_false_positive, req.params.findingId, req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    res.json({ finding: result.rows[0] });
  } catch (err) {
    console.error('Update finding error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;