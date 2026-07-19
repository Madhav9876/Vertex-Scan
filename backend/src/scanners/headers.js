// Vertex Scan - Security Headers Scanner
// Analyzes HTTP security headers based on OWASP recommendations

const https = require('https');
const http = require('http');
const url = require('url');
const { buildPinnedUrl, applyPinnedTarget } = require('../utils/validation');

const SECURITY_HEADERS = {
  'strict-transport-security': {
    title: 'HTTP Strict Transport Security (HSTS)',
    severity: 'high',
    description: 'HSTS instructs browsers to only access the site via HTTPS, preventing downgrade attacks.',
    impact: 'Without HSTS, users are vulnerable to SSL stripping attacks and man-in-the-middle attacks.',
    remediation: 'Add the Strict-Transport-Security header with a max-age of at least 1 year (31536000 seconds) and include subdomains.',
    cwe_id: 'CWE-319',
    code_snippets: {
      nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      iis: '<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />',
      cloudflare: 'Enabled via SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS)'
    }
  },
  'content-security-policy': {
    title: 'Content Security Policy (CSP)',
    severity: 'critical',
    description: 'CSP controls which resources can be loaded, mitigating XSS and data injection attacks.',
    impact: 'Missing CSP leaves users vulnerable to cross-site scripting (XSS) and data injection attacks.',
    remediation: 'Implement a Content-Security-Policy header with appropriate directives for your application.',
    cwe_id: 'CWE-693',
    code_snippets: {
      nginx: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'" always;',
      apache: 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'"',
      iis: '<add name="Content-Security-Policy" value="default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'" />',
      cloudflare: 'Add CSP via Cloudflare Workers or Page Rules'
    }
  },
  'x-content-type-options': {
    title: 'X-Content-Type-Options',
    severity: 'medium',
    description: 'Prevents MIME type sniffing, reducing the risk of content-based attacks.',
    impact: 'Without this header, browsers may interpret files as a different MIME type, enabling XSS attacks.',
    remediation: 'Add the X-Content-Type-Options header with value "nosniff".',
    cwe_id: 'CWE-693',
    code_snippets: {
      nginx: 'add_header X-Content-Type-Options "nosniff" always;',
      apache: 'Header always set X-Content-Type-Options "nosniff"',
      iis: '<add name="X-Content-Type-Options" value="nosniff" />',
      cloudflare: 'Enabled automatically for proxied traffic'
    }
  },
  'x-frame-options': {
    title: 'X-Frame-Options',
    severity: 'medium',
    description: 'Prevents clickjacking by controlling whether the site can be embedded in frames.',
    impact: 'Without clickjacking protection, attackers can trick users into performing unintended actions.',
    remediation: 'Add the X-Frame-Options header with value "DENY" or "SAMEORIGIN".',
    cwe_id: 'CWE-1021',
    code_snippets: {
      nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
      apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
      iis: '<add name="X-Frame-Options" value="SAMEORIGIN" />',
      cloudflare: 'Add via Cloudflare Workers or Page Rules'
    }
  },
  'x-xss-protection': {
    title: 'X-XSS-Protection',
    severity: 'low',
    description: 'Enables the browser\'s XSS filter to block reflected XSS attacks.',
    impact: 'While modern browsers rely on CSP, this header provides an additional layer of XSS protection.',
    remediation: 'Add the X-XSS-Protection header with value "1; mode=block".',
    cwe_id: 'CWE-79',
    code_snippets: {
      nginx: 'add_header X-XSS-Protection "1; mode=block" always;',
      apache: 'Header always set X-XSS-Protection "1; mode=block"',
      iis: '<add name="X-XSS-Protection" value="1; mode=block" />'
    }
  },
  'referrer-policy': {
    title: 'Referrer-Policy',
    severity: 'low',
    description: 'Controls how much referrer information is included with requests.',
    impact: 'Missing Referrer-Policy can leak sensitive URL parameters to external sites.',
    remediation: 'Add the Referrer-Policy header with value "strict-origin-when-cross-origin".',
    cwe_id: 'CWE-200',
    code_snippets: {
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
      iis: '<add name="Referrer-Policy" value="strict-origin-when-cross-origin" />'
    }
  },
  'permissions-policy': {
    title: 'Permissions Policy',
    severity: 'low',
    description: 'Controls which browser features and APIs can be used on the site.',
    impact: 'Without Permissions Policy, sites can access sensitive device features without restriction.',
    remediation: 'Add the Permissions-Policy header to restrict access to features like camera, microphone, and geolocation.',
    cwe_id: 'CWE-693',
    code_snippets: {
      nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
      apache: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
      iis: '<add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=()" />'
    }
  },
  'access-control-allow-origin': {
    title: 'CORS (Access-Control-Allow-Origin)',
    severity: 'high',
    description: 'Controls cross-origin resource sharing. A wildcard (*) allows any site to access resources.',
    impact: 'Overly permissive CORS policies can lead to data theft via cross-origin requests.',
    remediation: 'Restrict Access-Control-Allow-Origin to specific trusted origins instead of wildcard.',
    cwe_id: 'CWE-942',
    code_snippets: {
      nginx: 'add_header Access-Control-Allow-Origin "https://trusted-site.com" always;',
      apache: 'Header always set Access-Control-Allow-Origin "https://trusted-site.com"',
      iis: '<add name="Access-Control-Allow-Origin" value="https://trusted-site.com" />'
    }
  },
  'cache-control': {
    title: 'Cache-Control for Sensitive Pages',
    severity: 'medium',
    description: 'Controls whether sensitive pages can be cached by the browser or proxies.',
    impact: 'Cached sensitive pages can be accessed by other users on shared computers.',
    remediation: 'Set Cache-Control: no-store for pages containing sensitive information.',
    cwe_id: 'CWE-525',
    code_snippets: {
      nginx: 'add_header Cache-Control "no-store, no-cache, must-revalidate" always;',
      apache: 'Header always set Cache-Control "no-store, no-cache, must-revalidate"',
      iis: '<add name="Cache-Control" value="no-store, no-cache, must-revalidate" />'
    }
  }
};

async function scanHeaders(target) {
  const findings = [];
  const parsedUrl = url.parse(typeof target === 'string' ? target : target.normalized);

  // Use a pinned, SSRF-vetted connection target to avoid DNS-rebind bypasses.
  const urlToScan = buildPinnedUrl(target, 'https:');
  const parsed = new URL(urlToScan);

  try {
    const headers = await fetchHeaders(parsed.toString(), target);
    
    if (!headers) {
      findings.push({
        category: 'headers',
        severity: 'high',
        title: 'Unable to Retrieve Headers',
        description: `Could not retrieve HTTP headers from ${parsed.toString()}. The server may be unreachable or not responding.`,
        impact: 'Unable to assess HTTP security header configuration.',
        remediation: 'Verify the target URL is accessible and resolves correctly.',
        current_value: 'No response',
        recommended_value: 'Accessible endpoint with security headers',
        confidence: 'high',
        cwe_id: null
      });
      return findings;
    }

    // Check each security header
    const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
    
    for (const [headerName, config] of Object.entries(SECURITY_HEADERS)) {
      const found = headers[headerName] || headers[headerName.toLowerCase()];
      
      if (!found) {
        findings.push({
          category: 'headers',
          severity: config.severity,
          title: `Missing ${config.title}`,
          description: config.description,
          impact: config.impact,
          remediation: config.remediation,
          current_value: 'Header not set',
          recommended_value: `${headerName}: ${getRecommendedValue(headerName)}`,
          cwe_id: config.cwe_id,
          code_snippets: config.code_snippets,
          confidence: 'high'
        });
      } else {
        // Check for weak configurations
        const headerFindings = analyzeHeaderValue(headerName, found, config);
        findings.push(...headerFindings);
      }
    }

    // Check for information disclosure
    const serverHeader = headers['server'];
    if (serverHeader && serverHeader.length > 0) {
      findings.push({
        category: 'headers',
        severity: 'low',
        title: 'Server Version Information Disclosure',
        description: `The server header reveals: "${serverHeader}". This exposes server technology and version information.`,
        impact: 'Attackers can use version information to target known vulnerabilities in specific server versions.',
        remediation: 'Remove or obfuscate the Server header to hide server technology details.',
        current_value: serverHeader,
        recommended_value: 'Server header removed or generic value',
        cwe_id: 'CWE-200',
        code_snippets: {
          nginx: 'server_tokens off; # Removes version from Server header',
          apache: 'ServerTokens Prod # Hides server version information',
          iis: '<rewrite><rules><rule name="Remove Server Header"><match serverVariable="RESPONSE_Server" pattern=".*" /><action type="Rewrite" value="" /></rule></rules></rewrite>'
        },
        confidence: 'medium'
      });
    }

    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      findings.push({
        category: 'headers',
        severity: 'info',
        title: 'X-Powered-By Header Disclosure',
        description: `The X-Powered-By header reveals: "${poweredBy}". This exposes the technology stack.`,
        impact: 'Minor information leakage that can aid attackers in fingerprinting the application.',
        remediation: 'Remove the X-Powered-By header in your application configuration.',
        current_value: poweredBy,
        recommended_value: 'Header removed',
        cwe_id: 'CWE-200',
        confidence: 'low'
      });
    }

  } catch (err) {
    findings.push({
      category: 'headers',
      severity: 'high',
      title: 'Header Scan Error',
      description: `An error occurred while scanning headers: ${err.message}`,
      impact: 'Unable to complete security header assessment.',
      remediation: 'Ensure the target URL is valid and accessible.',
      current_value: err.message,
      recommended_value: 'Successful header retrieval',
      confidence: 'high'
    });
  }

  return findings;
}

function fetchHeaders(urlStr, target) {
  return new Promise((resolve, reject) => {
    const isHttps = urlStr.startsWith('https');
    const client = isHttps ? https : http;

    const options = {
      timeout: 10000,
      headers: {
        'User-Agent': 'Vertex-Scan/1.0 (Security Scanner)',
        'Accept': '*/*'
      }
    };
    applyPinnedTarget(options, target);

    const req = client.get(urlStr, options, (res) => {
      // Consume response data to free up memory
      res.resume();
      resolve(res.headers);
    });
    
    req.on('error', (err) => {
      reject(err);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

function analyzeHeaderValue(headerName, value, config) {
  const findings = [];
  const lowerValue = String(value).toLowerCase();

  if (headerName === 'strict-transport-security') {
    const maxAgeMatch = lowerValue.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge < 31536000) {
        findings.push({
          category: 'headers',
          severity: 'medium',
          title: 'Weak HSTS max-age',
          description: `HSTS max-age is set to ${maxAge} seconds (${Math.floor(maxAge / 86400)} days). Recommended minimum is 31536000 seconds (1 year).`,
          impact: 'Short HSTS duration reduces protection against SSL stripping attacks.',
          remediation: 'Increase max-age to at least 31536000 seconds.',
          current_value: `max-age=${maxAge}`,
          recommended_value: 'max-age=31536000; includeSubDomains; preload',
          cwe_id: 'CWE-319',
          confidence: 'high'
        });
      }
      if (!lowerValue.includes('includesubdomains')) {
        findings.push({
          category: 'headers',
          severity: 'low',
          title: 'HSTS Missing includeSubDomains',
          description: 'HSTS does not include the includeSubDomains directive, leaving subdomains unprotected.',
          impact: 'Subdomains remain vulnerable to SSL stripping attacks.',
          remediation: 'Add the includeSubDomains directive to the HSTS header.',
          current_value: value,
          recommended_value: 'max-age=31536000; includeSubDomains; preload',
          cwe_id: 'CWE-319',
          confidence: 'medium'
        });
      }
    }
  }

  if (headerName === 'content-security-policy') {
    if (lowerValue.includes("unsafe-inline") && !lowerValue.includes("nonce-") && !lowerValue.includes("sha256-")) {
      findings.push({
        category: 'headers',
        severity: 'high',
        title: 'CSP Allows Inline Scripts (unsafe-inline)',
        description: 'CSP uses unsafe-inline without nonces or hashes, allowing arbitrary inline script execution.',
        impact: 'Reduces CSP protection against XSS attacks significantly.',
        remediation: 'Use nonces or hashes instead of unsafe-inline for script-src directives.',
        current_value: value,
        recommended_value: 'Use nonce-based or hash-based CSP',
        cwe_id: 'CWE-693',
        confidence: 'high'
      });
    }
  }

  if (headerName === 'access-control-allow-origin') {
    if (value === '*' || value === '*') {
      findings.push({
        category: 'headers',
        severity: 'high',
        title: 'Wildcard CORS Policy',
        description: 'CORS uses wildcard (*) origin, allowing any website to make cross-origin requests.',
        impact: 'Potential data theft and cross-origin attacks from malicious sites.',
        remediation: 'Restrict Access-Control-Allow-Origin to specific trusted origins.',
        current_value: '*',
        recommended_value: 'https://specific-trusted-domain.com',
        cwe_id: 'CWE-942',
        confidence: 'high'
      });
    }
  }

  return findings;
}

function getRecommendedValue(headerName) {
  const recommendations = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'content-security-policy': 'default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
    'x-xss-protection': '1; mode=block',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'access-control-allow-origin': 'https://trusted-site.com',
    'cache-control': 'no-store, no-cache, must-revalidate'
  };
  return recommendations[headerName] || 'Configure this security header';
}

module.exports = { scanHeaders };