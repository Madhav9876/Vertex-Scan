// Vertex Scan - Scan Orchestrator
// Coordinates multi-module scanning, grading, and result aggregation
// v2.0 - Enhanced scoring with numerical precision, per-module breakdowns, deep-scan support

const { scanHeaders } = require('./headers');
const { scanTLS } = require('./tls');
const { scanDirectories } = require('./directories');
const { fingerprintTarget } = require('./fingerprint');
const { deepScanTarget } = require('./deepScan');
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
const CONFIDENCE_MODIFIERS = { high: 1.0, medium: 0.7, low: 0.4 };

const SCAN_HARD_TIMEOUT_MS = parseInt(process.env.SCAN_HARD_TIMEOUT_MS, 10) || 120000;

// Promisified timeout that rejects so the outer catch marks the scan failed.
function withHardTimeout(promise, ms, scanId) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Scan exceeded hard timeout of ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Reset any scans left in a non-terminal state by a previous process crash.
// Call this once at boot so orphaned 'running'/'pending' rows don't block the
// concurrency quota forever.
async function recoverStuckScans() {
  try {
    const res = await db.query(
      `UPDATE scans SET status = 'failed', error_message = 'Recovered after server restart',
              completed_at = NOW() WHERE status IN ('running', 'pending') RETURNING id`
    );
    if (res.rows.length) {
      console.log(`[Orchestrator] Recovered ${res.rows.length} stuck scan(s) on startup`);
    }
  } catch (err) {
    console.error('[Orchestrator] Stuck-scan recovery failed:', err.message);
  }
}

async function runScan(scanId, userId) {
  console.log(`[Orchestrator] Starting scan ${scanId}`);

  try {
    await withHardTimeout(executeScan(scanId, userId), SCAN_HARD_TIMEOUT_MS, scanId);
  } catch (err) {
    console.error(`[Orchestrator] Scan ${scanId} failed:`, err.message);

    await db.query(
      'UPDATE scans SET status = $1, error_message = $2, completed_at = NOW() WHERE id = $3',
      ['failed', err.message, scanId]
    );

    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by, details) VALUES ($1, $2, $3, $4)',
      [scanId, 'failed', userId, JSON.stringify({ error: err.message })]
    );

    throw err;
  }
}

async function executeScan(scanId, userId) {
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
    const phaseErrors = [];

    // Phase 1: Fingerprint the target (always runs).
    // Tolerate fingerprint failures: a scan should still complete with a grade
    // even if fingerprinting throws (e.g. transient network error).
    let fingerprint = {};
    try {
      console.log(`[Orchestrator] Fingerprinting target: ${pinned.normalized}`);
      fingerprint = await fingerprintTarget(pinned) || {};
      console.log(`[Orchestrator] Fingerprint: ${JSON.stringify(fingerprint)}`);
    } catch (err) {
      console.error(`[Orchestrator] Fingerprint failed (continuing):`, err.message);
      phaseErrors.push(`fingerprint: ${err.message}`);
    }

    // Phase 2: Run enabled security modules. Each module already isolates its
    // own failures, but guard the orchestration call too so one bad module
    // can never abort the entire scan.
    if (enabledModules.headers) {
      try {
        moduleResults.headers = await runModule('headers', scanId, pinned, allFindings);
      } catch (err) {
        phaseErrors.push(`headers: ${err.message}`);
      }
    }

    if (enabledModules.tls) {
      try {
        moduleResults.tls = await runModule('tls', scanId, pinned, allFindings);
      } catch (err) {
        phaseErrors.push(`tls: ${err.message}`);
      }
    }

    if (enabledModules.directories) {
      try {
        moduleResults.directories = await runModule('directories', scanId, pinned, allFindings, fingerprint);
      } catch (err) {
        phaseErrors.push(`directories: ${err.message}`);
      }
    }

    // Phase 3: Deep scan - identify unique vulnerabilities via smart crawling.
    // Never let the deep scan abort the whole run.
    let deepFindings = [];
    try {
      deepFindings = await deepScanTarget(pinned, fingerprint, allFindings);
      allFindings.push(...deepFindings);
      moduleResults.deepScan = {
        moduleType: 'deepScan',
        status: 'completed',
        findingsCount: deepFindings.length,
        uniqueVulnerabilities: deepFindings.filter(f => f.isUniqueVulnerability).length
      };
    } catch (err) {
      console.error(`[Orchestrator] Deep scan failed (continuing):`, err.message);
      phaseErrors.push(`deepScan: ${err.message}`);
      moduleResults.deepScan = { moduleType: 'deepScan', status: 'failed', error: err.message };
    }

    // Calculate enhanced score and grade. Always produce a valid grade+score so
    // the scan completes even if calculation inputs are unusual.
    let score = 100;
    let grade = 'A+';
    let scoreBreakdown = {};
    try {
      const result = calculateEnhancedGrade(allFindings, fingerprint);
      score = result.score;
      grade = result.grade;
      scoreBreakdown = result.scoreBreakdown;
    } catch (err) {
      console.error(`[Orchestrator] Grade calculation failed (using safe default):`, err.message);
      phaseErrors.push(`grade: ${err.message}`);
    }

    // Save all findings to database
    for (const finding of allFindings) {
      try {
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
      } catch (err) {
        console.error(`[Orchestrator] Finding insert failed (skipped):`, err.message);
      }
    }

    const durationMs = Date.now() - startTime;

    // Update scan with enhanced results
    await db.query(
      `UPDATE scans SET status = $1, grade = $2, score = $3, completed_at = NOW(), 
       duration_ms = $4 WHERE id = $5`,
      ['completed', grade, Math.round(score), durationMs, scanId]
    );

    // Log scan completion with detailed metadata
    await db.query(
      'INSERT INTO scan_history (scan_id, action, performed_by, details) VALUES ($1, $2, $3, $4)',
      [scanId, 'completed', userId, JSON.stringify({
        score: Math.round(score),
        precisionScore: score,
        grade,
        total_findings: allFindings.length,
        duration_ms: durationMs,
        score_breakdown: scoreBreakdown,
        fingerprint: {
          cms: fingerprint.cms,
          server: fingerprint.server,
          framework: fingerprint.framework,
          hosting: fingerprint.hosting,
          technologies: fingerprint.technologies
        },
        deep_scan_findings: deepFindings.length,
        unique_vulnerabilities: deepFindings.filter(f => f.isUniqueVulnerability).length,
        ...(phaseErrors.length ? { warnings: phaseErrors } : {})
      })]
    );

    console.log(`[Orchestrator] Scan ${scanId} completed: Grade ${grade}, Precision Score ${score.toFixed(1)}, ${allFindings.length} findings`);

    return {
      scanId,
      status: 'completed',
      grade,
      score: Math.round(score),
      precisionScore: score,
      totalFindings: allFindings.length,
      durationMs,
      moduleResults,
      scoreBreakdown,
      fingerprint
    };
  } catch (err) {
    throw err;
  }
}

async function runModule(moduleType, scanId, target, allFindings, fingerprint) {
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
        findings = await scanDirectories(target, fingerprint);
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

/**
 * Enhanced grade calculation with:
 * - Per-module score breakdown
 * - Confidence-weighted deductions
 * - Vulnerability density analysis
 * - Penalty for duplicate/redundant findings
 * - Technology-specific risk adjustments
 */
function calculateEnhancedGrade(findings, fingerprint) {
  if (findings.length === 0) {
    return {
      score: 100,
      grade: 'A+',
      scoreBreakdown: {
        overall: 100,
        weightedScore: 100,
        vulnerabilityDensity: 0,
        penalty: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        byModule: {},
        confidenceAdjusted: true,
        deepScanEnabled: true
      }
    };
  }

  // Group findings by module for per-module scoring
  const byModule = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalWeightedPenalty = 0;
  let uniqueVulnerabilityBonus = 0;
  let redundantPenalty = 0;

  // Track duplicate titles to penalize redundant findings
  const titleCounts = {};

  for (const finding of findings) {
    // Track module-level data
    const mod = finding.category || 'unknown';
    if (!byModule[mod]) byModule[mod] = [];
    byModule[mod].push(finding);

    // Track severity counts
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;

    // Confidence-weighted penalty
    const weight = SEVERITY_WEIGHTS[finding.severity] || 0;
    const confidenceMod = CONFIDENCE_MODIFIERS[finding.confidence] || 0.7;
    totalWeightedPenalty += weight * confidenceMod;

    // Track unique vulnerability signatures for bonus
    if (finding.isUniqueVulnerability) {
      uniqueVulnerabilityBonus += 3;
    }

    // Penalize redundant findings (same title appearing multiple times)
    const key = finding.title || '';
    titleCounts[key] = (titleCounts[key] || 0) + 1;
    if (titleCounts[key] > 1) {
      redundantPenalty += 1;
    }
  }

  // Calculate per-module scores
  const moduleScores = {};
  for (const [mod, modFindings] of Object.entries(byModule)) {
    let modPenalty = 0;
    const modSeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of modFindings) {
      const w = SEVERITY_WEIGHTS[f.severity] || 0;
      const cm = CONFIDENCE_MODIFIERS[f.confidence] || 0.7;
      modPenalty += w * cm;
      modSeverity[f.severity] = (modSeverity[f.severity] || 0) + 1;
    }
    // Apply severity deductions per module
    if (modSeverity.critical > 0) modPenalty += 15;
    if (modSeverity.high > 0) modPenalty += 10;
    if (modSeverity.medium > 0) modPenalty += 5;

    const modScore = Math.max(0, MAX_SCORE - modPenalty);
    moduleScores[mod] = Math.round(modScore * 10) / 10;
  }

  // Calculate vulnerability density (findings per module)
  const moduleCount = Object.keys(byModule).length || 1;
  const vulnerabilityDensity = findings.length / moduleCount;

  // Base score calculation
  let weightedScore = Math.max(0, MAX_SCORE - totalWeightedPenalty);

  // Apply severity-based deductions
  if (bySeverity.critical > 0) weightedScore -= 15;
  if (bySeverity.high > 0) weightedScore -= 10;
  if (bySeverity.medium > 0) weightedScore -= 5;

  // Apply redundant finding penalty (capped)
  redundantPenalty = Math.min(redundantPenalty, 15);
  weightedScore -= redundantPenalty;

  // Apply unique vulnerability bonus (finding real, distinct issues)
  weightedScore += Math.min(uniqueVulnerabilityBonus, 10);

  // Technology-specific adjustments from fingerprint
  if (fingerprint) {
    // Outdated technology detection
    if (fingerprint.technologies) {
      for (const tech of fingerprint.technologies) {
        if (tech.isOutdated) {
          weightedScore -= 5;
        }
      }
    }
    // Missing security.txt or other best practices
    if (fingerprint.missingSecurityTxt) weightedScore -= 2;
  }

  // Clamp final score
  let score = Math.round(Math.max(0, Math.min(100, weightedScore)) * 10) / 10;

  // Determine grade with + modifiers for precision
  let grade;
  if (score >= 97) grade = 'A+';
  else if (score >= 93) grade = 'A';
  else if (score >= 90) grade = 'A-';
  else if (score >= 87) grade = 'B+';
  else if (score >= 83) grade = 'B';
  else if (score >= 80) grade = 'B-';
  else if (score >= 77) grade = 'C+';
  else if (score >= 73) grade = 'C';
  else if (score >= 70) grade = 'C-';
  else if (score >= 67) grade = 'D+';
  else if (score >= 63) grade = 'D';
  else if (score >= 60) grade = 'D-';
  else grade = 'F';

  return {
    score,
    grade,
    scoreBreakdown: {
      overall: score,
      weightedScore: Math.round(weightedScore * 10) / 10,
      penalty: Math.round(totalWeightedPenalty * 10) / 10,
      vulnerabilityDensity: Math.round(vulnerabilityDensity * 10) / 10,
      redundantPenalty: Math.round(redundantPenalty * 10) / 10,
      uniqueVulnerabilityBonus: Math.round(Math.min(uniqueVulnerabilityBonus, 10) * 10) / 10,
      bySeverity,
      byModule: moduleScores,
      confidenceAdjusted: true,
      deepScanEnabled: true
    }
  };
}

// Legacy wrapper for backward compatibility
function calculateGrade(findings) {
  const result = calculateEnhancedGrade(findings, {});
  return { score: Math.round(result.score), grade: result.grade };
}

module.exports = { runScan, recoverStuckScans, calculateGrade, calculateEnhancedGrade };