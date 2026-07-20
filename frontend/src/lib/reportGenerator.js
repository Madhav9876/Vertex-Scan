// Vertex Scan - Client-side report generation & download
// Produces JSON, CSV, self-contained HTML, and print-to-PDF reports from the
// actual scan + findings fetched from the API. No third-party dependencies.

function severityColor(severity) {
  switch (severity) {
    case 'critical': return '#DC2626';
    case 'high': return '#EA580C';
    case 'medium': return '#D97706';
    case 'low': return '#2563EB';
    case 'info': return '#6B7280';
    default: return '#6B7280';
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}

function safeDownload(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function slugify(url) {
  return String(url || 'scan')
    .replace(/^https?:\/\//i, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase() || 'scan';
}

export function generateJSON(scan, findings) {
  const report = {
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
      modules: scan.modules,
    },
    summary: {
      total_findings: findings.length,
      by_severity: severityCounts(findings),
      by_category: {
        headers: findings.filter(f => f.category === 'headers').length,
        tls: findings.filter(f => f.category === 'tls').length,
        directories: findings.filter(f => f.category === 'directories').length,
      },
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
    })),
  };
  return JSON.stringify(report, null, 2);
}

export function generateCSV(scan, findings) {
  const header =
    'Severity,Category,Title,Description,Impact,Remediation,Current Value,Recommended Value,CWE ID,Confidence\n';
  const rows = findings
    .map(f => {
      const esc = str => `"${(str || '').toString().replace(/"/g, '""')}"`;
      return [
        f.severity,
        f.category,
        esc(f.title),
        esc(f.description),
        esc(f.impact),
        esc(f.remediation),
        esc(f.current_value),
        esc(f.recommended_value),
        f.cwe_id || '',
        f.confidence,
      ].join(',');
    })
    .join('\n');
  return `Vertex Scan Report - ${scan.target_url}\nGrade: ${scan.grade} | Score: ${scan.score}\nGenerated: ${new Date().toISOString()}\n\n${header}${rows}`;
}

export function generateHTML(scan, findings) {
  const counts = severityCounts(findings);
  const findingsHtml = findings
    .map(f => {
      const color = severityColor(f.severity);
      return `
      <div class="finding">
        <div class="finding-head">
          <h3>${escapeHtml(f.title)}</h3>
          <span class="badge" style="background:${color}">${escapeHtml(f.severity)}</span>
        </div>
        <p class="desc">${escapeHtml(f.description)}</p>
        ${f.impact ? `<p class="kv"><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>` : ''}
        ${f.current_value ? `<p class="kv"><strong>Current Value:</strong> <code>${escapeHtml(f.current_value)}</code></p>` : ''}
        ${f.recommended_value ? `<p class="kv"><strong>Recommended:</strong> <code>${escapeHtml(f.recommended_value)}</code></p>` : ''}
        ${f.remediation ? `<div class="remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
        ${f.cwe_id ? `<p class="meta">CWE: ${escapeHtml(f.cwe_id)} | Confidence: ${escapeHtml(f.confidence || 'n/a')}</p>` : ''}
      </div>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vertex Scan Report - ${escapeHtml(scan.target_url)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: #f3f4f6; color: #111827; line-height: 1.5; }
  .container { max-width: 920px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 32px; }
  .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
  .header h1 { margin: 0 0 8px; color: #111827; }
  .target { color: #6B7280; word-break: break-all; margin: 4px 0; }
  .grade { font-size: 48px; font-weight: bold; margin: 10px 0; }
  .grade-A { color: #059669; } .grade-B { color: #D97706; } .grade-C { color: #F59E0B; } .grade-D { color: #EA580C; } .grade-F { color: #DC2626; }
  .score { font-size: 22px; color: #6B7280; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 14px; margin: 24px 0; }
  .stat { text-align: center; padding: 14px; background: #f9fafb; border-radius: 8px; }
  .stat-value { font-size: 26px; font-weight: bold; }
  .stat-label { font-size: 12px; color: #6B7280; text-transform: uppercase; }
  .findings h2 { color: #111827; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
  .finding { border-left: 4px solid #6B7280; margin: 12px 0; padding: 14px 16px; background: #f9fafb; border-radius: 4px; page-break-inside: avoid; }
  .finding-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  .finding-head h3 { margin: 0; color: #111827; font-size: 16px; }
  .badge { color: #fff; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; white-space: nowrap; }
  .desc { color: #374151; margin: 10px 0 6px; }
  .kv { color: #374151; margin: 4px 0; font-size: 14px; }
  .kv code, .remediation code { background: #eef2ff; padding: 1px 6px; border-radius: 4px; font-size: 13px; word-break: break-all; }
  .remediation { background: #e0f2fe; padding: 10px 12px; border-radius: 4px; margin-top: 10px; font-size: 14px; color: #075985; }
  .meta { color: #6B7280; font-size: 12px; margin-top: 8px; }
  .empty { text-align: center; color: #059669; padding: 24px; }
  @media print { body { background: #fff; padding: 0; } .container { box-shadow: none; } }
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Vertex Scan Security Report</h1>
      <p class="target">Target: ${escapeHtml(scan.target_url)}</p>
      <p class="target">Generated: ${escapeHtml(new Date().toLocaleString())}</p>
      <div class="grade grade-${escapeHtml(scan.grade ? scan.grade.charAt(0) : 'N')}">${escapeHtml(scan.grade || 'N/A')}</div>
      <div class="score">Score: ${escapeHtml(scan.score ?? 0)}/100</div>
      <p class="target">Duration: ${scan.duration_ms ? Math.round(scan.duration_ms / 1000) + 's' : 'N/A'}</p>
    </div>
    <div class="summary">
      <div class="stat"><div class="stat-value" style="color:#DC2626">${counts.critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat"><div class="stat-value" style="color:#EA580C">${counts.high}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-value" style="color:#D97706">${counts.medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-value" style="color:#2563EB">${counts.low}</div><div class="stat-label">Low</div></div>
      <div class="stat"><div class="stat-value" style="color:#6B7280">${counts.info}</div><div class="stat-label">Info</div></div>
    </div>
    <div class="findings">
      <h2>Findings (${findings.length})</h2>
      ${findings.length ? findingsHtml : '<div class="empty">No vulnerabilities detected for this target.</div>'}
    </div>
  </div>
</body>
</html>`;
}

export function downloadJSON(scan, findings) {
  safeDownload(`vertex-scan-${slugify(scan.target_url)}.json`, generateJSON(scan, findings), 'application/json');
}

export function downloadCSV(scan, findings) {
  safeDownload(`vertex-scan-${slugify(scan.target_url)}.csv`, generateCSV(scan, findings), 'text/csv');
}

export function downloadHTML(scan, findings) {
  safeDownload(`vertex-scan-${slugify(scan.target_url)}.html`, generateHTML(scan, findings), 'text/html');
}

// Print-to-PDF: open a clean, paginated report window and trigger the browser's
// native print dialog so the user can save as PDF. Proper CSS prevents overlap.
export function downloadPDF(scan, findings) {
  const html = generateHTML(scan, findings);
  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    alert('Please allow pop-ups to download the PDF report.');
    return;
  }
  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();
  printWindow.focus();
  const trigger = () => {
    printWindow.print();
  };
  if (printWindow.document.readyState === 'complete') {
    setTimeout(trigger, 300);
  } else {
    printWindow.onload = () => setTimeout(trigger, 300);
  }
}
