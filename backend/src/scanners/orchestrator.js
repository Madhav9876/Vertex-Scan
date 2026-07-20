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
const CONFIDENCE_MODIFIERS = { high: 1.0, medium: 0.6, low: 0.2 };

// Weight applied to "recommendation" findings (best-practice hardening gaps and
// low-confidence heuristics). These are NOT exploitable vulnerabilities, so they
// must not dominate the score the way a real vuln does.
const RECOMMENDATION_WEIGHT = 0.25;

// How aggressively real vulnerability penalty grows. Higher = more forgiving,
// prevents a single issue from nuking the score to F (diminishing returns).
const VULN_SOFTENING = 38;

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
 * Risk-proportionate grade calculation.
 *
 * Key principle: distinguish EXPLOITABLE VULNERABILITIES from BEST-PRACTICE
 * RECOMMENDATIONS.
 *   - A vulnerability (exposed .env, HTTPS downgrade, expired cert, weak TLS,
 *     critical CVE) is penalised fully and drives the grade down.
 *   - A recommendation (missing security header, missing cookie flag, missing
 *     security.txt, low-confidence heuristic guess) is a hardening gap, not a
 *     breach. It is penalised only lightly and never triggers the harsh flat
 *     severity deductions.
 *
 * Penalties use diminishing returns so a single issue cannot crater a site to F,
 * and genuine good posture (HSTS, TLS 1.3, HTTPS) is rewarded, producing
 * realistic, differentiating scores.
 */
function isRecommendation(finding) {
  if (finding.severity === 'info') return true;
  // Low-confidence heuristics (reflected-XSS probe, open-redirect probe, generic
  // CSRF guess, etc.) are guesses, not confirmed issues.
  if (finding.confidence === 'low') return true;
  const t = String(finding.title || '').toLowerCase();
  // "Missing <header>", "Cookie X Missing ...", "No Exposed Directories" etc.
  if (t.includes('missing') || t.startsWith('no ')) return true;
  return false;
}

function calculateEnhancedGrade(findings, fingerprint) {
  const emptyBreakdown = {
    overall: 100,
    weightedScore: 100,
    penalty: 0,
    vulnerabilityDensity: 0,
    redundantPenalty: 0,
    uniqueVulnerabilityBonus: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byModule: {},
    vulnerabilities: 0,
    recommendations: 0,
    confidenceAdjusted: true,
    deepScanEnabled: true
  };

  if (!findings || findings.length === 0) {
    return { score: 100, grade: 'A+', scoreBreakdown: emptyBreakdown };
  }

  const byModule = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let vulnerabilityPenalty = 0;   // full weight, drives grade
  let recommendationPenalty = 0;  // light weight, hardening gaps
  let uniqueVulnerabilityBonus = 0;
  let redundantPenalty = 0;
  let postureBonus = 0;
  let vulnCount = 0;
  let recCount = 0;
  let confirmedCritical = 0;
  let confirmedHigh = 0;

  const titleCounts = {};
  const positiveSignals = [
    'hsts implemented', 'tls 1.3 supported', 'strong certificate key',
    'https supported'
  ];

  for (const finding of findings) {
    const mod = finding.category || 'unknown';
    if (!byModule[mod]) byModule[mod] = [];
    byModule[mod].push(finding);

    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;

    const weight = SEVERITY_WEIGHTS[finding.severity] || 0;
    const confMod = CONFIDENCE_MODIFIERS[finding.confidence] || 0.2;
    const eff = weight * confMod;

    const isRec = isRecommendation(finding);
    if (isRec) {
      recCount++;
      recommendationPenalty += eff * RECOMMENDATION_WEIGHT;
    } else {
      vulnCount++;
      vulnerabilityPenalty += eff;
      // Track confirmed (medium+ confidence) vulns for the modest flat deduction.
      if (finding.severity === 'critical' && finding.confidence !== 'low') confirmedCritical++;
      if (finding.severity === 'high' && finding.confidence !== 'low') confirmedHigh++;
    }

    if (finding.isUniqueVulnerability) uniqueVulnerabilityBonus += 2;

    const key = finding.title || '';
    titleCounts[key] = (titleCounts[key] || 0) + 1;
    if (titleCounts[key] > 1) redundantPenalty += 1;

    // Reward genuine good posture so well-configured sites are not penalised.
    const tl = String(finding.title || '').toLowerCase();
    if (finding.severity === 'info' && positiveSignals.some(s => tl.includes(s))) {
      postureBonus += 2;
    }
  }

  // Diminishing returns on real-vulnerability penalty: score approaches but
  // never instantly hits 0 from a single issue.
  const softVuln = MAX_SCORE * (1 - Math.exp(-vulnerabilityPenalty / VULN_SOFTENING));
  let score = MAX_SCORE - softVuln - recommendationPenalty;

  // Flat deductions ONLY for confirmed vulnerabilities (not heuristics/recos).
  if (confirmedCritical > 0) score -= 6;
  if (confirmedHigh > 0) score -= 3;

  redundantPenalty = Math.min(redundantPenalty, 10);
  score -= redundantPenalty;
  score += Math.min(uniqueVulnerabilityBonus, 8);
  score += Math.min(postureBonus, 10);

  if (fingerprint && fingerprint.technologies) {
    let outdated = 0;
    for (const tech of fingerprint.technologies) {
      if (tech.isOutdated) outdated++;
    }
    score -= Math.min(outdated * 3, 9);
  }
  if (fingerprint && fingerprint.missingSecurityTxt) score -= 1;

  const scoreRounded = Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;

  // Realistic, differentiating grade bands (similar to industry scanners).
  let grade;
  if (scoreRounded >= 96) grade = 'A+';
  else if (scoreRounded >= 90) grade = 'A';
  else if (scoreRounded >= 86) grade = 'A-';
  else if (scoreRounded >= 82) grade = 'B+';
  else if (scoreRounded >= 78) grade = 'B';
  else if (scoreRounded >= 74) grade = 'B-';
  else if (scoreRounded >= 70) grade = 'C+';
  else if (scoreRounded >= 65) grade = 'C';
  else if (scoreRounded >= 60) grade = 'C-';
  else if (scoreRounded >= 55) grade = 'D+';
  else if (scoreRounded >= 50) grade = 'D';
  else if (scoreRounded >= 45) grade = 'D-';
  else if (scoreRounded >= 35) grade = 'E';
  else grade = 'F';

  // Per-module score breakdown (for reporting/differentiation).
  const moduleScores = {};
  for (const [mod, modFindings] of Object.entries(byModule)) {
    let mp = 0;
    for (const f of modFindings) {
      const w = SEVERITY_WEIGHTS[f.severity] || 0;
      const cm = CONFIDENCE_MODIFIERS[f.confidence] || 0.2;
      mp += isRecommendation(f) ? w * cm * RECOMMENDATION_WEIGHT : w * cm;
    }
    const soft = MAX_SCORE * (1 - Math.exp(-mp / VULN_SOFTENING));
    moduleScores[mod] = Math.round((MAX_SCORE - soft) * 10) / 10;
  }

  const moduleCount = Object.keys(byModule).length || 1;
  const vulnerabilityDensity = Math.round((findings.length / moduleCount) * 10) / 10;

  return {
    score: scoreRounded,
    grade,
    scoreBreakdown: {
      overall: scoreRounded,
      weightedScore: Math.round(scoreRounded * 10) / 10,
      penalty: Math.round((softVuln + recommendationPenalty) * 10) / 10,
      vulnerabilityDensity,
      redundantPenalty: Math.round(redundantPenalty * 10) / 10,
      uniqueVulnerabilityBonus: Math.round(Math.min(uniqueVulnerabilityBonus, 8) * 10) / 10,
      postureBonus: Math.round(Math.min(postureBonus, 10) * 10) / 10,
      vulnerabilities: vulnCount,
      recommendations: recCount,
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