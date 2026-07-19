// Vertex Scan - Reports Routes
const express = require('express');
const db = require('../db/connection');
const { authenticateToken } = require('../middleware/auth');
const { escapeHtml } = require('../utils/validation');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const router = express.Router();

// GET /api/reports - List reports for user's scans
router.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT r.*, s.target_url, s.grade, s.score
      FROM reports r
      JOIN scans s ON r.scan_id = s.id
      WHERE s.user_id = $1
      ORDER BY r.created_at DESC
      LIMIT 50
    `, [req.user.id]);

    res.json({ reports: result.rows });
  } catch (err) {
    console.error('List reports error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/reports - Generate a report for a scan
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { scan_id, format } = req.body;

    if (!scan_id || !format) {
      return res.status(400).json({ error: 'Scan ID and format are required' });
    }

    if (!UUID_RE.test(String(scan_id))) {
      return res.status(400).json({ error: 'Invalid scan ID' });
    }

    if (!['pdf', 'json', 'csv', 'html'].includes(format)) {
      return res.status(400).json({ error: 'Invalid format. Must be pdf, json, csv, or html' });
    }

    // Verify scan belongs to user
    const scanResult = await db.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scan_id, req.user.id]
    );

    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const scan = scanResult.rows[0];

    // Get findings
    const findingsResult = await db.query(
      'SELECT * FROM findings WHERE scan_id = $1 ORDER BY severity, created_at',
      [scan_id]
    );

    const findings = findingsResult.rows;

    // Generate report based on format
    let reportData;
    let filePath;
    let fileSize;

    switch (format) {
      case 'json':
        reportData = generateJSONReport(scan, findings);
        filePath = `/reports/${scan_id}.json`;
        fileSize = Buffer.byteLength(JSON.stringify(reportData));
        break;
      case 'csv':
        reportData = generateCSVReport(scan, findings);
        filePath = `/reports/${scan_id}.csv`;
        fileSize = Buffer.byteLength(reportData);
        break;
      case 'html':
        reportData = generateHTMLReport(scan, findings);
        filePath = `/reports/${scan_id}.html`;
        fileSize = Buffer.byteLength(reportData);
        break;
      case 'pdf':
        reportData = { message: 'PDF generation requires PDFKit integration' };
        filePath = `/reports/${scan_id}.pdf`;
        fileSize = 0;
        break;
    }

    // Save report record
    const result = await db.query(
      `INSERT INTO reports (scan_id, format, file_path, file_size)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [scan_id, format, filePath, fileSize]
    );

    res.status(201).json({
      message: 'Report generated successfully',
      report: result.rows[0],
      data: reportData
    });
  } catch (err) {
    console.error('Generate report error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

function generateJSONReport(scan, findings) {
  return {
    tool: 'Vertex Scan',
    version: '1.0.0',
    generated_at: new Date().toISOString(),
    scan: {
      id: scan.id,
      target_url: scan.target_url,
      status: scan.status,
      grade: scan.grade,
      score: scan.score,
      duration_ms: scan.duration_ms,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      modules: scan.modules
    },
    summary: {
      total_findings: findings.length,
      by_severity: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length
      },
      by_category: {
        headers: findings.filter(f => f.category === 'headers').length,
        tls: findings.filter(f => f.category === 'tls').length,
        directories: findings.filter(f => f.category === 'directories').length
      }
    },
    findings: findings.map(f => ({
      id: f.id,
      category: f.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      impact: f.impact,
      remediation: f.remediation,
      current_value: f.current_value,
      recommended_value: f.recommended_value,
      cwe_id: f.cwe_id,
      confidence: f.confidence
    }))
  };
}

function generateCSVReport(scan, findings) {
  const header = 'Severity,Category,Title,Description,Impact,Remediation,Current Value,Recommended Value,CWE ID,Confidence\n';
  const rows = findings.map(f => {
    const escape = (str) => `"${(str || '').replace(/"/g, '""')}"`;
    return [
      f.severity,
      f.category,
      escape(f.title),
      escape(f.description),
      escape(f.impact),
      escape(f.remediation),
      escape(f.current_value),
      escape(f.recommended_value),
      f.cwe_id || '',
      f.confidence
    ].join(',');
  }).join('\n');
  
  return `Vertex Scan Report - ${scan.target_url}\nGrade: ${scan.grade} | Score: ${scan.score}\nGenerated: ${new Date().toISOString()}\n\n${header}${rows}`;
}

function generateHTMLReport(scan, findings) {
  const severityColors = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#2563EB',
    info: '#6B7280'
  };

  const findingsHtml = findings.map(f => `
    <div class="finding" style="border-left: 4px solid ${severityColors[f.severity] || '#6B7280'}; margin: 10px 0; padding: 15px; background: #f9fafb; border-radius: 4px;">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h3 style="margin: 0; color: #111827;">${escapeHtml(f.title)}</h3>
        <span style="background: ${severityColors[f.severity] || '#6B7280'}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase;">${escapeHtml(f.severity)}</span>
      </div>
      <p style="color: #374151; margin-top: 10px;">${escapeHtml(f.description)}</p>
      ${f.impact ? `<p style="color: #6B7280;"><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>` : ''}
      ${f.remediation ? `<div style="background: #e0f2fe; padding: 10px; border-radius: 4px; margin-top: 10px;"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
      ${f.cwe_id ? `<p style="color: #6B7280; font-size: 12px; margin-top: 8px;">CWE: ${escapeHtml(f.cwe_id)}</p>` : ''}
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vertex Scan Report - ${escapeHtml(scan.target_url)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f3f4f6; color: #111827; }
    .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 30px; }
    .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
    .grade { font-size: 48px; font-weight: bold; margin: 10px 0; }
    .grade-A { color: #059669; } .grade-B { color: #D97706; } .grade-C { color: #F59E0B; } .grade-D { color: #EA580C; } .grade-F { color: #DC2626; }
    .score { font-size: 24px; color: #6B7280; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
    .stat { text-align: center; padding: 15px; background: #f9fafb; border-radius: 8px; }
    .stat-value { font-size: 28px; font-weight: bold; }
    .stat-label { font-size: 12px; color: #6B7280; text-transform: uppercase; }
    .findings { margin-top: 20px; }
    h2 { color: #111827; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Vertex Scan Security Report</h1>
      <p style="color: #6B7280;">Target: ${escapeHtml(scan.target_url)}</p>
      <p style="color: #6B7280;">Generated: ${escapeHtml(new Date().toISOString())}</p>
      <div class="grade grade-${escapeHtml(scan.grade ? scan.grade.charAt(0) : 'N')}">${escapeHtml(scan.grade || 'N/A')}</div>
      <div class="score">Score: ${escapeHtml(scan.score || 0)}/100</div>
      <p style="color: #6B7280;">Duration: ${scan.duration_ms ? Math.round(scan.duration_ms / 1000) + 's' : 'N/A'}</p>
    </div>
    
    <div class="summary">
      <div class="stat"><div class="stat-value" style="color: #DC2626;">${findings.filter(f => f.severity === 'critical').length}</div><div class="stat-label">Critical</div></div>
      <div class="stat"><div class="stat-value" style="color: #EA580C;">${findings.filter(f => f.severity === 'high').length}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-value" style="color: #D97706;">${findings.filter(f => f.severity === 'medium').length}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-value" style="color: #2563EB;">${findings.filter(f => f.severity === 'low').length}</div><div class="stat-label">Low</div></div>
      <div class="stat"><div class="stat-value" style="color: #6B7280;">${findings.filter(f => f.severity === 'info').length}</div><div class="stat-label">Info</div></div>
    </div>
    
    <div class="findings">
      <h2>Findings (${findings.length})</h2>
      ${findingsHtml}
    </div>
  </div>
</body>
</html>`;
}

module.exports = router;