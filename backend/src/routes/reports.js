// Vertex Scan - Reports Routes
// v2.0 - Enhanced reports with score breakdowns, fingerprint data, and deep scan findings
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

    // Get scan history for metadata (includes score breakdown and fingerprint)
    const historyResult = await db.query(
      `SELECT details FROM scan_history 
       WHERE scan_id = $1 AND action = 'completed' 
       ORDER BY created_at DESC LIMIT 1`,
      [scan_id]
    );
    const scanMetadata = historyResult.rows.length > 0 ? historyResult.rows[0].details : null;

    // Get modules
    const modulesResult = await db.query(
      'SELECT * FROM scan_modules WHERE scan_id = $1',
      [scan_id]
    );
    const modules = modulesResult.rows;

    // Generate report based on format
    let reportData;
    let filePath;
    let fileSize;

    switch (format) {
      case 'json':
        reportData = generateJSONReport(scan, findings, scanMetadata, modules);
        filePath = `/reports/${scan_id}.json`;
        fileSize = Buffer.byteLength(JSON.stringify(reportData));
        break;
      case 'csv':
        reportData = generateCSVReport(scan, findings, scanMetadata);
        filePath = `/reports/${scan_id}.csv`;
        fileSize = Buffer.byteLength(reportData);
        break;
      case 'html':
        reportData = generateHTMLReport(scan, findings, scanMetadata, modules);
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

function generateJSONReport(scan, findings, scanMetadata, modules) {
  const metadata = scanMetadata || {};
  const scoreBreakdown = metadata.score_breakdown || null;
  const fingerprint = metadata.fingerprint || null;

  return {
    tool: 'Vertex Scan',
    version: '2.0.0',
    generated_at: new Date().toISOString(),
    scan: {
      id: scan.id,
      target_url: scan.target_url,
      status: scan.status,
      grade: scan.grade,
      score: scan.score,
      precisionScore: metadata.precisionScore || scan.score,
      duration_ms: scan.duration_ms,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      modules: scan.modules
    },
    score_breakdown: scoreBreakdown ? {
      overall: scoreBreakdown.overall,
      weighted_score: scoreBreakdown.weightedScore,
      penalty: scoreBreakdown.penalty,
      vulnerability_density: scoreBreakdown.vulnerabilityDensity,
      redundant_penalty: scoreBreakdown.redundantPenalty,
      unique_vulnerability_bonus: scoreBreakdown.uniqueVulnerabilityBonus,
      by_severity: scoreBreakdown.bySeverity,
      by_module: scoreBreakdown.byModule,
      confidence_adjusted: scoreBreakdown.confidenceAdjusted,
      deep_scan_enabled: scoreBreakdown.deepScanEnabled
    } : null,
    fingerprint: fingerprint ? {
      cms: fingerprint.cms,
      cms_version: fingerprint.cmsVersion,
      server: fingerprint.server,
      server_version: fingerprint.serverVersion,
      framework: fingerprint.framework,
      hosting: fingerprint.hosting,
      technologies: fingerprint.technologies,
      missing_security_txt: fingerprint.missingSecurityTxt
    } : null,
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
        directories: findings.filter(f => f.category === 'directories').length,
        deepScan: findings.filter(f => f.category === 'deepScan').length
      },
      deep_scan: {
        total_findings: metadata.deep_scan_findings || 0,
        unique_vulnerabilities: metadata.unique_vulnerabilities || 0
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
      confidence: f.confidence,
      is_resolved: f.is_resolved,
      is_false_positive: f.is_false_positive,
      metadata: f.metadata
    }))
  };
}

function generateCSVReport(scan, findings, scanMetadata) {
  const metadata = scanMetadata || {};
  const scoreBreakdown = metadata.score_breakdown || {};
  const fingerprint = metadata.fingerprint || {};

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

  // Build enhanced metadata section
  const metadataLines = [
    `Vertex Scan Report - ${scan.target_url}`,
    `Grade: ${scan.grade} | Score: ${scan.score}/100`,
    `Generated: ${new Date().toISOString()}`,
    '',
    '--- SCORE BREAKDOWN ---',
    `Overall Score: ${scoreBreakdown.overall || scan.score}`,
    `Weighted Score: ${scoreBreakdown.weightedScore || 'N/A'}`,
    `Penalty: ${scoreBreakdown.penalty || 'N/A'}`,
    `Vulnerability Density: ${scoreBreakdown.vulnerabilityDensity || 'N/A'}`,
    `Redundant Penalty: ${scoreBreakdown.redundantPenalty || 'N/A'}`,
    `Unique Vulnerability Bonus: ${scoreBreakdown.uniqueVulnerabilityBonus || 'N/A'}`,
    '',
    '--- FINGERPRINT ---',
    `CMS: ${fingerprint.cms || 'Not detected'}`,
    `CMS Version: ${fingerprint.cmsVersion || 'N/A'}`,
    `Server: ${fingerprint.server || 'Not detected'}`,
    `Server Version: ${fingerprint.serverVersion || 'N/A'}`,
    `Framework: ${fingerprint.framework || 'Not detected'}`,
    `Hosting: ${fingerprint.hosting || 'Not detected'}`,
    `Missing Security.txt: ${fingerprint.missingSecurityTxt !== undefined ? fingerprint.missingSecurityTxt : 'N/A'}`,
    '',
    '--- DEEP SCAN ---',
    `Deep Scan Findings: ${metadata.deep_scan_findings || 0}`,
    `Unique Vulnerabilities: ${metadata.unique_vulnerabilities || 0}`,
    '',
    '--- FINDINGS ---',
    header,
    rows
  ].join('\n');

  return metadataLines;
}

function getScoreClass(score) {
  if (score >= 90) return 'grade-a';
  if (score >= 80) return 'grade-b';
  if (score >= 70) return 'grade-c';
  if (score >= 60) return 'grade-d';
  return 'grade-f';
}

function generateHTMLReport(scan, findings, scanMetadata, modules) {
  const metadata = scanMetadata || {};
  const scoreBreakdown = metadata.score_breakdown || {};
  const fingerprint = metadata.fingerprint || {};

  const severityColors = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#2563EB',
    info: '#6B7280'
  };

  // Build score breakdown HTML
  const scoreBreakdownHtml = scoreBreakdown.overall !== undefined ? `
    <div class="score-breakdown">
      <h2>Score Breakdown</h2>
      <div class="score-grid">
        <div class="score-item">
          <div class="score-label">Overall Score</div>
          <div class="score-value ${getScoreClass(scoreBreakdown.overall)}">${scoreBreakdown.overall.toFixed(1)}</div>
        </div>
        <div class="score-item">
          <div class="score-label">Weighted Score</div>
          <div class="score-value">${scoreBreakdown.weightedScore !== undefined ? scoreBreakdown.weightedScore.toFixed(1) : 'N/A'}</div>
        </div>
        <div class="score-item">
          <div class="score-label">Penalty</div>
          <div class="score-value penalty">-${scoreBreakdown.penalty !== undefined ? scoreBreakdown.penalty.toFixed(1) : 'N/A'}</div>
        </div>
        <div class="score-item">
          <div class="score-label">Vulnerability Density</div>
          <div class="score-value">${scoreBreakdown.vulnerabilityDensity !== undefined ? scoreBreakdown.vulnerabilityDensity.toFixed(1) : 'N/A'}</div>
        </div>
        <div class="score-item">
          <div class="score-label">Redundant Penalty</div>
          <div class="score-value penalty">-${scoreBreakdown.redundantPenalty !== undefined ? scoreBreakdown.redundantPenalty.toFixed(1) : 'N/A'}</div>
        </div>
        <div class="score-item">
          <div class="score-label">Unique Vuln. Bonus</div>
          <div class="score-value bonus">+${scoreBreakdown.uniqueVulnerabilityBonus !== undefined ? scoreBreakdown.uniqueVulnerabilityBonus.toFixed(1) : 'N/A'}</div>
        </div>
      </div>
      ${scoreBreakdown.byModule ? `
      <h3>Per-Module Scores</h3>
      <div class="module-scores">
        ${Object.entries(scoreBreakdown.byModule).map(([mod, modScore]) => `
          <div class="module-score-item">
            <span class="module-name">${escapeHtml(mod)}</span>
            <div class="module-score-bar">
              <div class="module-score-fill ${getScoreClass(modScore)}" style="width: ${modScore}%"></div>
            </div>
            <span class="module-score-value ${getScoreClass(modScore)}">${modScore.toFixed(1)}</span>
          </div>
        `).join('')}
      </div>
      ` : ''}
      ${scoreBreakdown.bySeverity ? `
      <h3>Severity Distribution</h3>
      <div class="severity-bars">
        ${Object.entries(scoreBreakdown.bySeverity).map(([sev, count]) => `
          <div class="severity-bar-item">
            <span class="severity-name" style="color: ${severityColors[sev] || '#6B7280'}">${escapeHtml(sev)}</span>
            <div class="severity-bar-track">
              <div class="severity-bar-fill" style="width: ${Math.min(100, (count / Math.max(...Object.values(scoreBreakdown.bySeverity))) * 100)}%; background: ${severityColors[sev] || '#6B7280'}"></div>
            </div>
            <span class="severity-count">${count}</span>
          </div>
        `).join('')}
      </div>
      ` : ''}
    </div>
  ` : '';

  // Build fingerprint HTML
  const fingerprintHtml = fingerprint.cms || fingerprint.server ? `
    <div class="fingerprint-section">
      <h2>Technology Fingerprint</h2>
      <div class="fingerprint-grid">
        ${fingerprint.cms ? `<div class="fingerprint-item"><strong>CMS:</strong> ${escapeHtml(fingerprint.cms)} ${fingerprint.cmsVersion ? `(v${escapeHtml(fingerprint.cmsVersion)})` : ''}</div>` : ''}
        ${fingerprint.server ? `<div class="fingerprint-item"><strong>Server:</strong> ${escapeHtml(fingerprint.server)} ${fingerprint.serverVersion ? `(v${escapeHtml(fingerprint.serverVersion)})` : ''}</div>` : ''}
        ${fingerprint.framework ? `<div class="fingerprint-item"><strong>Framework:</strong> ${escapeHtml(fingerprint.framework)}</div>` : ''}
        ${fingerprint.hosting ? `<div class="fingerprint-item"><strong>Hosting:</strong> ${escapeHtml(fingerprint.hosting)}</div>` : ''}
        ${fingerprint.missingSecurityTxt !== undefined ? `<div class="fingerprint-item"><strong>Security.txt:</strong> ${fingerprint.missingSecurityTxt ? '<span class="badge badge-warning">Missing</span>' : '<span class="badge badge-success">Present</span>'}</div>` : ''}
      </div>
      ${fingerprint.technologies && fingerprint.technologies.length > 0 ? `
      <h3>Detected Technologies</h3>
      <div class="tech-list">
        ${fingerprint.technologies.map(tech => `
          <div class="tech-item ${tech.isOutdated ? 'outdated' : ''}">
            <span class="tech-name">${escapeHtml(tech.name)}</span>
            ${tech.version ? `<span class="tech-version">v${escapeHtml(tech.version)}</span>` : ''}
            <span class="tech-type">${escapeHtml(tech.type)}</span>
            ${tech.isOutdated ? '<span class="badge badge-danger">OUTDATED</span>' : ''}
          </div>
        `).join('')}
      </div>
      ` : ''}
    </div>
  ` : '';

  // Build deep scan summary
  const deepScanHtml = metadata.deep_scan_findings > 0 ? `
    <div class="deep-scan-section">
      <h2>Deep Scan Results</h2>
      <div class="deep-scan-grid">
        <div class="deep-scan-item">
          <div class="deep-scan-value">${metadata.deep_scan_findings}</div>
          <div class="deep-scan-label">Total Deep Scan Findings</div>
        </div>
        <div class="deep-scan-item">
          <div class="deep-scan-value unique">${metadata.unique_vulnerabilities || 0}</div>
          <div class="deep-scan-label">Unique Vulnerabilities</div>
        </div>
      </div>
    </div>
  ` : '';

  const findingsHtml = findings.map(f => `
    <div class="finding" style="border-left: 4px solid ${severityColors[f.severity] || '#6B7280'}; margin: 10px 0; padding: 15px; background: #f9fafb; border-radius: 4px;">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h3 style="margin: 0; color: #111827;">${escapeHtml(f.title)}</h3>
        <div style="display: flex; gap: 8px; align-items: center;">
          ${f.category === 'deepScan' ? '<span class="badge badge-deep">DEEP</span>' : ''}
          <span style="background: ${severityColors[f.severity] || '#6B7280'}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase;">${escapeHtml(f.severity)}</span>
        </div>
      </div>
      <p style="color: #374151; margin-top: 10px;">${escapeHtml(f.description)}</p>
      ${f.impact ? `<p style="color: #6B7280;"><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>` : ''}
      ${f.remediation ? `<div style="background: #e0f2fe; padding: 10px; border-radius: 4px; margin-top: 10px;"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
      <div style="display: flex; gap: 15px; margin-top: 8px; font-size: 12px; color: #6B7280;">
        ${f.cwe_id ? `<span>CWE: ${escapeHtml(f.cwe_id)}</span>` : ''}
        <span>Confidence: ${escapeHtml(f.confidence)}</span>
        <span>Category: ${escapeHtml(f.category)}</span>
      </div>
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
    .container { max-width: 1000px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 30px; }
    .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
    .grade { font-size: 48px; font-weight: bold; margin: 10px 0; }
    .grade-a { color: #059669; } .grade-b { color: #D97706; } .grade-c { color: #F59E0B; } .grade-d { color: #EA580C; } .grade-f { color: #DC2626; }
    .score { font-size: 24px; color: #6B7280; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
    .stat { text-align: center; padding: 15px; background: #f9fafb; border-radius: 8px; }
    .stat-value { font-size: 28px; font-weight: bold; }
    .stat-label { font-size: 12px; color: #6B7280; text-transform: uppercase; }
    .badge { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
    .badge-warning { background: #fef3c7; color: #92400e; }
    .badge-success { background: #d1fae5; color: #065f46; }
    .badge-danger { background: #fee2e2; color: #991b1b; }
    .badge-deep { background: #e0e7ff; color: #3730a3; }
    .score-breakdown, .fingerprint-section, .deep-scan-section { margin: 20px 0; padding: 20px; background: #f9fafb; border-radius: 8px; }
    .score-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
    .score-item { text-align: center; padding: 10px; background: white; border-radius: 6px; }
    .score-label { font-size: 11px; color: #6B7280; text-transform: uppercase; }
    .score-value { font-size: 24px; font-weight: bold; }
    .score-value.penalty { color: #DC2626; }
    .score-value.bonus { color: #059669; }
    .module-scores { margin-top: 15px; }
    .module-score-item { display: flex; align-items: center; gap: 10px; margin: 5px 0; }
    .module-name { min-width: 120px; font-size: 13px; }
    .module-score-bar { flex: 1; height: 20px; background: #e5e7eb; border-radius: 10px; overflow: hidden; }
    .module-score-fill { height: 100%; border-radius: 10px; transition: width 0.3s; }
    .module-score-fill.grade-a { background: #059669; }
    .module-score-fill.grade-b { background: #D97706; }
    .module-score-fill.grade-c { background: #F59E0B; }
    .module-score-fill.grade-d { background: #EA580C; }
    .module-score-fill.grade-f { background: #DC2626; }
    .module-score-value { min-width: 50px; text-align: right; font-weight: bold; }
    .severity-bars { margin-top: 15px; }
    .severity-bar-item { display: flex; align-items: center; gap: 10px; margin: 5px 0; }
    .severity-name { min-width: 70px; font-size: 13px; font-weight: bold; text-transform: uppercase; }
    .severity-bar-track { flex: 1; height: 20px; background: #e5e7eb; border-radius: 10px; overflow: hidden; }
    .severity-bar-fill { height: 100%; border-radius: 10px; transition: width 0.3s; }
    .severity-count { min-width: 30px; text-align: right; font-weight: bold; }
    .fingerprint-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
    .fingerprint-item { padding: 8px; background: white; border-radius: 6px; font-size: 13px; }
    .tech-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .tech-item { padding: 6px 12px; background: white; border-radius: 16px; font-size: 12px; display: flex; align-items: center; gap: 6px; }
    .tech-item.outdated { border: 2px solid #DC2626; }
    .tech-name { font-weight: bold; }
    .tech-version { color: #6B7280; }
    .tech-type { color: #6B7280; font-size: 10px; text-transform: uppercase; }
    .deep-scan-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
    .deep-scan-item { text-align: center; padding: 15px; background: white; border-radius: 8px; }
    .deep-scan-value { font-size: 36px; font-weight: bold; color: #3730a3; }
    .deep-scan-value.unique { color: #059669; }
    .deep-scan-label { font-size: 12px; color: #6B7280; text-transform: uppercase; }
    .findings { margin-top: 20px; }
    h2 { color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }
    h3 { color: #374151; font-size: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Vertex Scan Security Report</h1>
      <p style="color: #6B7280;">Target: ${escapeHtml(scan.target_url)}</p>
      <p style="color: #6B7280;">Generated: ${escapeHtml(new Date().toISOString())}</p>
      <div class="grade grade-${(scan.grade && scan.grade.charAt(0).toLowerCase()) || 'n'}">${escapeHtml(scan.grade || 'N/A')}</div>
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

    ${scoreBreakdownHtml}
    ${fingerprintHtml}
    ${deepScanHtml}

    <div class="findings">
      <h2>Findings (${findings.length})</h2>
      ${findingsHtml}
    </div>
  </div>
</body>
</html>`;
}

module.exports = router;