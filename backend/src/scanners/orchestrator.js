// Vertex Scan - Scan Orchestrator
// Coordinates multi-module scanning, grading, and result aggregation

const { scanHeaders } = require('./headers');
const { scanTLS } = require('./tls');
const { scanDirectories } = require('./directories');
const { assertPublicTarget } = require('../utils/validation');
const db = require('../db/connection');

const SEVERITY_WEIGHTS = {
  critical: 10,
  high: 5,
  medium: 3,
  low: 1,
  info: 0
};

const MAX_SCORE = 100;

async function runScan(scanId, userId) {
  console.log(`[Orchestrator] Starting scan ${scanId}`);

  try {
    // Get scan details
    const scanResult = await db.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scanId, userId]
    );

    if (scanResult.rows.length === 0) {
      throw new Error('Scan not found');
    }

    const scan = scanResult.rows[0];
    const targetUrl = scan.target_url;
    const enabledModules = scan.modules || {};
    const startTime = Date.now();

    // Re-validate and pin the target's resolved address at scan time (SSRF guard,
    // closes DNS-rebind / TOCTOU between creation and execution).
    const pinned = await assertPublicTarget(targetUrl);
    if (!pinned.valid) {
      throw new Error(`Target is not allowed: ${pinned.error}`);
    }

    // Update scan status to running
    await db.query(
      'UPDATE scans SET status = $1, started_at = NOW() WHERE id = $2',
      ['running', scanId]
    );

    // Log scan start
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by) VALUES ($1, $2, $3)',
      [scanId, 'started', userId]
    );

    const allFindings = [];
    const moduleResults = {};

    // Run enabled modules
    if (enabledModules.headers) {
      moduleResults.headers = await runModule('headers', scanId, pinned, allFindings);
    }

    if (enabledModules.tls) {
      moduleResults.tls = await runModule('tls', scanId, pinned, allFindings);
    }

    if (enabledModules.directories) {
      moduleResults.directories = await runModule('directories', scanId, pinned, allFindings);
    }

    // Calculate score and grade
    const { score, grade } = calculateGrade(allFindings);

    // Save all findings to database
    for (const finding of allFindings) {
      await db.query(
        `INSERT INTO findings (scan_id, category, severity, title, description, current_value, 
         recommended_value, impact, remediation, code_snippets, cwe_id, cve_id, confidence, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          scanId, finding.category, finding.severity, finding.title, finding.description,
          finding.current_value || null, finding.recommended_value || null,
          finding.impact || null, finding.remediation || null,
          finding.code_snippets ? JSON.stringify(finding.code_snippets) : null,
          finding.cwe_id || null, finding.cve_id || null,
          finding.confidence || 'high',
          finding.metadata ? JSON.stringify(finding.metadata) : '{}'
        ]
      );
    }

    const durationMs = Date.now() - startTime;

    // Update scan with results
    await db.query(
      `UPDATE scans SET status = $1, grade = $2, score = $3, completed_at = NOW(), 
       duration_ms = $4 WHERE id = $5`,
      ['completed', grade, score, durationMs, scanId]
    );

    // Log scan completion
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by, details) VALUES ($1, $2, $3, $4)',
      [scanId, 'completed', userId, JSON.stringify({
        score,
        grade,
        total_findings: allFindings.length,
        duration_ms: durationMs
      })]
    );

    console.log(`[Orchestrator] Scan ${scanId} completed: Grade ${grade}, Score ${score}, ${allFindings.length} findings`);

    return {
      scanId,
      status: 'completed',
      grade,
      score,
      totalFindings: allFindings.length,
      durationMs,
      moduleResults
    };

  } catch (err) {
    console.error(`[Orchestrator] Scan ${scanId} failed:`, err.message);

    // Update scan status to failed
    await db.query(
      'UPDATE scans SET status = $1, error_message = $2, completed_at = NOW() WHERE id = $3',
      ['failed', err.message, scanId]
    );

    // Log scan failure
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by, details) VALUES ($1, $2, $3, $4)',
      [scanId, 'failed', userId, JSON.stringify({ error: err.message })]
    );

    throw err;
  }
}

async function runModule(moduleType, scanId, target, allFindings) {
  console.log(`[Orchestrator] Running module: ${moduleType}`);

  const startTime = Date.now();

  // Create module record
  const moduleResult = await db.query(
    `INSERT INTO scan_modules (scan_id, module_type, status, started_at)
     VALUES ($1, $2, 'running', NOW()) RETURNING id`,
    [scanId, moduleType]
  );
  const moduleId = moduleResult.rows[0].id;

  try {
    let findings = [];

    switch (moduleType) {
      case 'headers':
        findings = await scanHeaders(target);
        break;
      case 'tls':
        findings = await scanTLS(target);
        break;
      case 'directories':
        findings = await scanDirectories(target);
        break;
    }

    // Add findings to the aggregate list
    allFindings.push(...findings);

    const durationMs = Date.now() - startTime;

    // Update module record
    await db.query(
      `UPDATE scan_modules SET status = 'completed', completed_at = NOW(), 
       findings_count = $1, raw_output = $2 WHERE id = $3`,
      [findings.length, JSON.stringify({ count: findings.length, duration_ms: durationMs }), moduleId]
    );

    console.log(`[Orchestrator] Module ${moduleType} completed: ${findings.length} findings`);

    return {
      moduleType,
      status: 'completed',
      findingsCount: findings.length,
      durationMs
    };

  } catch (err) {
    console.error(`[Orchestrator] Module ${moduleType} failed:`, err.message);

    await db.query(
      `UPDATE scan_modules SET status = 'failed', completed_at = NOW(), 
       error_message = $1 WHERE id = $2`,
      [err.message, moduleId]
    );

    return {
      moduleType,
      status: 'failed',
      error: err.message
    };
  }
}

function calculateGrade(findings) {
  if (findings.length === 0) {
    return { score: 100, grade: 'A+' };
  }

  // Calculate weighted penalty
  let totalPenalty = 0;
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const finding of findings) {
    const weight = SEVERITY_WEIGHTS[finding.severity] || 0;
    totalPenalty += weight;
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
  }

  // Calculate score (100 - penalty, minimum 0)
  let score = Math.max(0, MAX_SCORE - totalPenalty);

  // Apply severity-based deductions
  if (severityCounts.critical > 0) score -= 15;
  if (severityCounts.high > 0) score -= 10;
  if (severityCounts.medium > 0) score -= 5;

  score = Math.max(0, Math.min(100, score));

  // Determine grade
  let grade;
  if (score >= 90) grade = severityCounts.critical === 0 && severityCounts.high === 0 ? 'A+' : 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  return { score, grade };
}

module.exports = { runScan, calculateGrade };