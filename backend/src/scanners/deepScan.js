// Vertex Scan - Deep Scan Module
// Identifies unique, site-specific vulnerabilities through smart crawling
// and technology-aware analysis. Eliminates repetitive risk assessments
// by generating vulnerability signatures and detecting duplicates.
// v2.0 - Uses pinned request utility with proper timeout handling

const { pinnedGet } = require('../utils/request');

// CMS-specific vulnerability checks
const CMS_VULNERABILITY_CHECKS = {
  'WordPress': [
    {
      title: 'WordPress XML-RPC Enabled',
      severity: 'medium',
      path: '/xmlrpc.php',
      description: 'XML-RPC endpoint is accessible, which can be used for brute-force attacks and DDoS amplification.',
      impact: 'Attackers can use XML-RPC for credential stuffing, pingback attacks, and DDoS amplification.',
      remediation: 'Disable XML-RPC by adding \'add_filter(\'xmlrpc_enabled\', \'__return_false\');\' to wp-config.php or block /xmlrpc.php via .htaccess.',
      cwe_id: 'CWE-307',
      confidence: 'high'
    },
    {
      title: 'WordPress Readme File Exposed',
      severity: 'low',
      path: '/readme.html',
      description: 'The WordPress readme file is publicly accessible, revealing the installed version.',
      impact: 'Helps attackers identify the WordPress version to target known vulnerabilities.',
      remediation: 'Delete the readme.html file from the server root.',
      cwe_id: 'CWE-200',
      confidence: 'high'
    },
    {
      title: 'WordPress Debug Mode Enabled',
      severity: 'high',
      path: '/wp-config.php',
      description: 'WordPress debug mode may be enabled, exposing sensitive information in error messages.',
      impact: 'Debug output can reveal database credentials, file paths, and internal configuration.',
      remediation: 'Set WP_DEBUG to false in wp-config.php for production environments.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    },
    {
      title: 'WordPress User Enumeration Possible',
      severity: 'medium',
      path: '/?author=1',
      description: 'WordPress user enumeration via author parameter is possible, allowing username discovery.',
      impact: 'Attackers can discover valid usernames for brute-force attacks.',
      remediation: 'Restrict access to author archives or use a security plugin to block user enumeration.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    }
  ],
  'Drupal': [
    {
      title: 'Drupal CHANGELOG.txt Exposed',
      severity: 'low',
      path: '/CHANGELOG.txt',
      description: 'Drupal changelog is publicly accessible, revealing the installed version.',
      impact: 'Helps attackers identify the Drupal version to target known vulnerabilities.',
      remediation: 'Remove or restrict access to CHANGELOG.txt and other version disclosure files.',
      cwe_id: 'CWE-200',
      confidence: 'high'
    },
    {
      title: 'Drupal Install File Exists',
      severity: 'high',
      path: '/core/install.php',
      description: 'Drupal install script is accessible, which could allow site reinstallation.',
      impact: 'An attacker could potentially reinstall the site or gain unauthorized access.',
      remediation: 'Remove install.php or restrict access to it after installation is complete.',
      cwe_id: 'CWE-284',
      confidence: 'high'
    },
    {
      title: 'Drupal User Registration Open',
      severity: 'medium',
      path: '/user/register',
      description: 'Drupal user registration page is accessible, potentially allowing unauthorized account creation.',
      impact: 'Spam accounts and unauthorized access if registration is not properly configured.',
      remediation: 'Restrict user registration to administrators only or enable email verification.',
      cwe_id: 'CWE-284',
      confidence: 'medium'
    }
  ],
  'Joomla': [
    {
      title: 'Joomla Administrator Exposed',
      severity: 'high',
      path: '/administrator',
      description: 'Joomla admin panel is publicly accessible without additional protection.',
      impact: 'Attackers can attempt to access the admin panel for brute-force attacks.',
      remediation: 'Protect the /administrator path with IP whitelisting or additional authentication.',
      cwe_id: 'CWE-284',
      confidence: 'high'
    },
    {
      title: 'Joomla robots.txt Leaks Paths',
      severity: 'low',
      path: '/robots.txt',
      description: 'Joomla robots.txt may expose administrative and system paths.',
      impact: 'Provides attackers with a map of sensitive Joomla directories.',
      remediation: 'Review robots.txt and remove any sensitive path disclosures.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    }
  ],
  'Magento': [
    {
      title: 'Magento Admin Panel Exposed',
      severity: 'high',
      path: '/admin',
      description: 'Magento admin panel is accessible from the default path.',
      impact: 'Attackers can attempt admin panel brute-force attacks.',
      remediation: 'Change the admin panel URL from the default /admin to a custom path.',
      cwe_id: 'CWE-284',
      confidence: 'high'
    },
    {
      title: 'Magento Downloader Accessible',
      severity: 'critical',
      path: '/downloader',
      description: 'Magento downloader is accessible, which can allow file uploads and code execution.',
      impact: 'Critical security risk - attackers can upload malicious files and execute code.',
      remediation: 'Remove the /downloader directory or restrict access immediately.',
      cwe_id: 'CWE-434',
      confidence: 'high'
    }
  ],
  'Laravel': [
    {
      title: 'Laravel Debug Mode Enabled',
      severity: 'high',
      path: '/_debugbar/open',
      description: 'Laravel debug bar or debug mode may be enabled in production.',
      impact: 'Exposes sensitive application data including queries, logs, and configuration.',
      remediation: 'Set APP_DEBUG=false in the .env file for production environments.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    },
    {
      title: 'Laravel Environment File Accessible',
      severity: 'critical',
      path: '/.env',
      description: 'Laravel environment configuration file is accessible, exposing credentials.',
      impact: 'Database credentials, API keys, and application secrets are exposed.',
      remediation: 'Ensure .env is not publicly accessible. Configure web server to block .env files.',
      cwe_id: 'CWE-200',
      confidence: 'high'
    }
  ],
  'ASP.NET': [
    {
      title: 'ASP.NET Detailed Errors Enabled',
      severity: 'high',
      path: '/elm.axd',
      description: 'ASP.NET error logging may be exposed, revealing stack traces and application details.',
      impact: 'Detailed error messages can reveal sensitive application internals.',
      remediation: 'Disable custom errors in production and restrict access to error logs.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    },
    {
      title: 'ASP.NET Trace Enabled',
      severity: 'high',
      path: '/trace.axd',
      description: 'ASP.NET trace functionality is accessible, exposing request details.',
      impact: 'Trace output reveals form data, cookies, headers, and server variables.',
      remediation: 'Disable trace in web.config by setting <trace enabled="false" />.',
      cwe_id: 'CWE-200',
      confidence: 'high'
    }
  ],
  'Express.js': [
    {
      title: 'Express.js Stack Traces Exposed',
      severity: 'high',
      path: '/',
      description: 'Express.js may expose stack traces in error responses when NODE_ENV is not set to production.',
      impact: 'Stack traces reveal application structure, file paths, and potential vulnerabilities.',
      remediation: 'Set NODE_ENV=production and implement a custom error handler that does not expose stack traces.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    }
  ],
  'Django': [
    {
      title: 'Django DEBUG Mode Enabled',
      severity: 'high',
      path: '/',
      description: 'Django DEBUG mode may be enabled, exposing detailed error pages.',
      impact: 'Debug pages reveal settings, database queries, and application internals.',
      remediation: 'Set DEBUG=False in Django settings for production environments.',
      cwe_id: 'CWE-200',
      confidence: 'medium'
    },
    {
      title: 'Django Admin Interface Exposed',
      severity: 'medium',
      path: '/admin/',
      description: 'Django admin interface is accessible at the default path.',
      impact: 'Attackers can attempt to access the admin panel for unauthorized access.',
      remediation: 'Change the admin URL from /admin/ to a custom path and enforce strong authentication.',
      cwe_id: 'CWE-284',
      confidence: 'high'
    }
  ]
};

// Generic vulnerability checks applicable to any site
const GENERIC_DEEP_CHECKS = [
  {
    title: 'Cross-Site Scripting (XSS) via URL Parameters',
    severity: 'high',
    category: 'xss',
    description: 'The application may be vulnerable to reflected XSS if URL parameters are reflected without sanitization.',
    impact: 'Attackers can inject malicious scripts that execute in users\' browsers, leading to session theft and data exfiltration.',
    remediation: 'Implement proper input validation and output encoding. Use Content-Security-Policy headers.',
    cwe_id: 'CWE-79',
    confidence: 'low',
    checkType: 'reflected_xss'
  },
  {
    title: 'Open Redirect Vulnerability',
    severity: 'medium',
    category: 'redirect',
    description: 'The application may be vulnerable to open redirect attacks if redirect parameters are not validated.',
    impact: 'Attackers can use the site to redirect users to malicious websites, enabling phishing attacks.',
    remediation: 'Validate all redirect URLs against a whitelist of allowed destinations.',
    cwe_id: 'CWE-601',
    confidence: 'low',
    checkType: 'open_redirect'
  },
  {
    title: 'Directory Listing Enabled',
    severity: 'medium',
    category: 'disclosure',
    description: 'Directory listing may be enabled on the web server, exposing file structures.',
    impact: 'Attackers can browse directory contents to find sensitive files and understand application structure.',
    remediation: 'Disable directory listing in web server configuration.',
    cwe_id: 'CWE-548',
    confidence: 'medium',
    checkType: 'dir_listing'
  },
  {
    title: 'Form Without CSRF Protection',
    severity: 'medium',
    category: 'csrf',
    description: 'Forms detected without apparent CSRF tokens may be vulnerable to cross-site request forgery.',
    impact: 'Attackers can trick authenticated users into performing unintended actions.',
    remediation: 'Implement CSRF tokens on all state-changing forms.',
    cwe_id: 'CWE-352',
    confidence: 'low',
    checkType: 'csrf_missing'
  },
  {
    title: 'Insecure Cookie Configuration',
    severity: 'high',
    category: 'cookies',
    description: 'Cookies detected without Secure, HttpOnly, or SameSite flags may be vulnerable to theft.',
    impact: 'Attackers can steal session cookies via XSS or man-in-the-middle attacks.',
    remediation: 'Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all cookies.',
    cwe_id: 'CWE-614',
    confidence: 'medium',
    checkType: 'insecure_cookies'
  },
  {
    title: 'Missing Security Headers for API Endpoints',
    severity: 'medium',
    category: 'api',
    description: 'API endpoints may lack proper security headers, increasing attack surface.',
    impact: 'API endpoints without proper headers are more susceptible to various attacks.',
    remediation: 'Ensure all API endpoints return appropriate security headers including CORS, CSP, and X-Content-Type-Options.',
    cwe_id: 'CWE-693',
    confidence: 'medium',
    checkType: 'api_headers'
  }
];

// Maximum concurrent HTTP connections to prevent socket exhaustion
const MAX_CONCURRENT = 5;

async function deepScanTarget(target, fingerprint, existingFindings) {
  const normalized = typeof target === 'string' ? target : target.normalized;
  const baseUrl = normalized.startsWith('http') ? normalized : `https://${normalized}`;
  const parsed = new URL(baseUrl);
  const baseHost = `${parsed.protocol}//${parsed.host}`;

  const deepFindings = [];
  const vulnerabilitySignatures = new Set();

  // Build signatures from existing findings to avoid duplicates
  for (const f of existingFindings) {
    const sig = generateVulnerabilitySignature(f);
    vulnerabilitySignatures.add(sig);
  }

  console.log(`[DeepScan] Starting deep scan for ${baseHost} with ${vulnerabilitySignatures.size} existing signatures`);

  // Phase 1: CMS-specific vulnerability checks
  if (fingerprint && fingerprint.cms) {
    const cmsChecks = CMS_VULNERABILITY_CHECKS[fingerprint.cms];
    if (cmsChecks) {
      console.log(`[DeepScan] Running ${cmsChecks.length} CMS-specific checks for ${fingerprint.cms}`);
      for (const check of cmsChecks) {
        try {
          const finding = await performCMSDeepCheck(baseHost, target, check, fingerprint);
          if (finding) {
            const sig = generateVulnerabilitySignature(finding);
            if (!vulnerabilitySignatures.has(sig)) {
              finding.isUniqueVulnerability = true;
              deepFindings.push(finding);
              vulnerabilitySignatures.add(sig);
            }
          }
        } catch (e) {
          console.error(`[DeepScan] CMS check failed: ${check.title}`, e.message);
        }
      }
    }
  }

  // Phase 2: Discovered path analysis (from fingerprint)
  if (fingerprint && fingerprint.detectedPaths && fingerprint.detectedPaths.length > 0) {
    console.log(`[DeepScan] Analyzing ${fingerprint.detectedPaths.length} discovered paths`);
    const uniquePaths = fingerprint.detectedPaths.filter(p => {
      return !isCommonPath(p);
    });

    // Limit to at most 10 discovered paths to avoid hangs
    const pathsToCheck = uniquePaths.slice(0, 10);
    for (const path of pathsToCheck) {
      try {
        const finding = await analyzeDiscoveredPath(baseHost, target, path);
        if (finding) {
          const sig = generateVulnerabilitySignature(finding);
          if (!vulnerabilitySignatures.has(sig)) {
            finding.isUniqueVulnerability = true;
            deepFindings.push(finding);
            vulnerabilitySignatures.add(sig);
          }
        }
      } catch (e) {
        // Skip failed path checks silently
      }
    }
  }

  // Phase 3: Generic deep checks with limited concurrency
  for (const check of GENERIC_DEEP_CHECKS) {
    try {
      const finding = await performGenericDeepCheck(baseHost, target, check, fingerprint);
      if (finding) {
        const sig = generateVulnerabilitySignature(finding);
        if (!vulnerabilitySignatures.has(sig)) {
          finding.isUniqueVulnerability = true;
          deepFindings.push(finding);
          vulnerabilitySignatures.add(sig);
        }
      }
    } catch (e) {
      console.error(`[DeepScan] Generic check failed: ${check.title}`, e.message);
    }
  }

  // Phase 4: Cookie security analysis
  try {
    const cookieFindings = await analyzeCookieSecurity(baseHost, target);
    for (const finding of cookieFindings) {
      const sig = generateVulnerabilitySignature(finding);
      if (!vulnerabilitySignatures.has(sig)) {
        finding.isUniqueVulnerability = true;
        deepFindings.push(finding);
        vulnerabilitySignatures.add(sig);
      }
    }
  } catch (e) {
    console.error(`[DeepScan] Cookie analysis failed:`, e.message);
  }

  // Phase 5: Technology-specific outdated version warnings
  if (fingerprint && fingerprint.technologies) {
    for (const tech of fingerprint.technologies) {
      if (tech.isOutdated && tech.version) {
        const finding = {
          category: 'deepScan',
          severity: 'high',
          title: `Outdated ${tech.name} Version (${tech.version})`,
          description: `The site is running ${tech.name} version ${tech.version}, which may contain known vulnerabilities.`,
          impact: `Outdated software versions are prime targets for attackers who exploit publicly known vulnerabilities.`,
          remediation: `Update ${tech.name} to the latest stable version. Check the official ${tech.name} website for upgrade instructions.`,
          current_value: `${tech.name} ${tech.version}`,
          recommended_value: `${tech.name} latest stable version`,
          cwe_id: 'CWE-1104',
          confidence: 'high',
          isUniqueVulnerability: true,
          metadata: {
            technology: tech.name,
            version: tech.version,
            type: tech.type
          }
        };
        const sig = generateVulnerabilitySignature(finding);
        if (!vulnerabilitySignatures.has(sig)) {
          deepFindings.push(finding);
          vulnerabilitySignatures.add(sig);
        }
      }
    }
  }

  // Phase 6: Form analysis for security issues
  try {
    const formFindings = await analyzeFormSecurity(baseHost, target);
    for (const finding of formFindings) {
      const sig = generateVulnerabilitySignature(finding);
      if (!vulnerabilitySignatures.has(sig)) {
        finding.isUniqueVulnerability = true;
        deepFindings.push(finding);
        vulnerabilitySignatures.add(sig);
      }
    }
  } catch (e) {
    console.error(`[DeepScan] Form analysis failed:`, e.message);
  }

  console.log(`[DeepScan] Completed: ${deepFindings.length} unique findings from deep scan`);
  return deepFindings;
}

/**
 * Generate a deterministic signature for a vulnerability finding
 * to enable deduplication across scans and modules.
 */
function generateVulnerabilitySignature(finding) {
  const parts = [
    finding.category || 'unknown',
    finding.severity || 'info',
    (finding.title || '').toLowerCase().replace(/\s+/g, '_').substring(0, 100),
    (finding.cwe_id || 'none'),
    (finding.current_value || '').substring(0, 50)
  ];
  return parts.join('::');
}

async function performCMSDeepCheck(baseHost, target, check, fingerprint) {
  try {
    const data = await fetchUrlData(target, check.path);
    if (!data) return null;

    const isAccessible = data.statusCode >= 200 && data.statusCode < 400;

    if (isAccessible) {
      return {
        category: 'deepScan',
        severity: check.severity,
        title: check.title,
        description: check.description,
        impact: check.impact,
        remediation: check.remediation,
        current_value: `HTTP ${data.statusCode} - ${check.path} is accessible`,
        recommended_value: `HTTP 403/404 - ${check.path} should not be publicly accessible`,
        cwe_id: check.cwe_id,
        confidence: check.confidence,
        isUniqueVulnerability: true,
        metadata: {
          path: check.path,
          status_code: data.statusCode,
          cms: fingerprint.cms,
          check_type: 'cms_specific'
        }
      };
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function analyzeDiscoveredPath(baseHost, target, path) {
  try {
    const data = await fetchUrlData(target, path);
    if (!data || data.statusCode >= 400) return null;

    // Check if the discovered path reveals sensitive information
    const sensitivePatterns = [
      { pattern: /password|passwd|pwd|secret|key|api.?key|token|auth/i, severity: 'critical', type: 'credentials' },
      { pattern: /admin|dashboard|cpanel|phpmyadmin/i, severity: 'high', type: 'admin_panel' },
      { pattern: /config|configuration|setting|env/i, severity: 'high', type: 'config' },
      { pattern: /backup|dump|export|sql|db|database/i, severity: 'critical', type: 'backup' },
      { pattern: /log|debug|error|trace/i, severity: 'medium', type: 'log' },
      { pattern: /api|v1|v2|graphql|swagger/i, severity: 'medium', type: 'api' },
      { pattern: /\.git|\.svn|\.env|\.htaccess/i, severity: 'critical', type: 'vcs' },
      { pattern: /test|dev|staging|sandbox/i, severity: 'medium', type: 'environment' }
    ];

    for (const sp of sensitivePatterns) {
      if (sp.pattern.test(path)) {
        return {
          category: 'deepScan',
          severity: sp.severity,
          title: `Discovered Sensitive Path: ${path}`,
          description: `The path "${path}" was discovered during crawling and is publicly accessible (HTTP ${data.statusCode}). This appears to be a ${sp.type} endpoint.`,
          impact: `Exposed ${sp.type} endpoints can lead to data breaches, unauthorized access, or system compromise.`,
          remediation: `Review the ${path} endpoint. Restrict access, implement authentication, or remove if not needed.`,
          current_value: `HTTP ${data.statusCode} - ${path} is accessible`,
          recommended_value: `HTTP 403/404 - ${path} should not be publicly accessible`,
          cwe_id: sp.severity === 'critical' ? 'CWE-538' : 'CWE-200',
          confidence: 'medium',
          isUniqueVulnerability: true,
          metadata: {
            discovered_path: path,
            status_code: data.statusCode,
            path_type: sp.type
          }
        };
      }
    }

    // If path doesn't match sensitive patterns but is accessible, note it
    return {
      category: 'deepScan',
      severity: 'info',
      title: `Discovered Internal Path: ${path}`,
      description: `The path "${path}" was discovered during crawling and is publicly accessible.`,
      impact: 'May reveal application structure or unintended functionality.',
      remediation: 'Review if this path needs to be publicly accessible.',
      current_value: `HTTP ${data.statusCode} - ${path} is accessible`,
      recommended_value: 'Restrict access if not intended for public use',
      cwe_id: 'CWE-200',
      confidence: 'low',
      isUniqueVulnerability: true,
      metadata: {
        discovered_path: path,
        status_code: data.statusCode
      }
    };
  } catch (e) {
    return null;
  }
}

async function performGenericDeepCheck(baseHost, target, check, fingerprint) {
  switch (check.checkType) {
    case 'reflected_xss':
      return checkReflectedXSS(target);
    case 'open_redirect':
      return checkOpenRedirect(target);
    case 'dir_listing':
      return checkDirectoryListing(target);
    case 'csrf_missing':
      return checkCSRFProtection(target, fingerprint);
    case 'insecure_cookies':
      return null; // Handled separately in analyzeCookieSecurity
    case 'api_headers':
      return checkAPIHeaders(target);
    default:
      return null;
  }
}

async function checkReflectedXSS(target) {
  const testPayload = '<script>alert(1)</script>';

  try {
    const data = await fetchUrlData(target, `/?q=${encodeURIComponent(testPayload)}&search=${encodeURIComponent(testPayload)}`);
    if (!data || !data.body) return null;

    if (data.body.includes(testPayload)) {
      return {
        category: 'deepScan',
        severity: 'high',
        title: 'Potential Reflected XSS Vulnerability',
        description: 'URL parameters appear to be reflected in the page response without proper sanitization, which may indicate a reflected XSS vulnerability.',
        impact: 'Attackers can craft malicious links that execute JavaScript in victims\' browsers, potentially stealing sessions or credentials.',
        remediation: 'Implement proper output encoding for all user-controlled input reflected in responses. Use Content-Security-Policy headers as defense-in-depth.',
        current_value: 'Input reflected in response without sanitization',
        recommended_value: 'All user input should be properly encoded before reflection',
        cwe_id: 'CWE-79',
        confidence: 'low',
        isUniqueVulnerability: true,
        metadata: {
          test_payload: testPayload,
          reflected: true
        }
      };
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function checkOpenRedirect(target) {
  try {
    const data = await fetchUrlData(target, `/?redirect=${encodeURIComponent('https://evil.com')}&url=${encodeURIComponent('https://evil.com')}&next=${encodeURIComponent('https://evil.com')}`);
    if (!data) return null;

    if (data.statusCode >= 300 && data.statusCode < 400) {
      const location = getHeader(data.headers, 'location');
      if (location && location.includes('evil.com')) {
        return {
          category: 'deepScan',
          severity: 'medium',
          title: 'Potential Open Redirect Vulnerability',
          description: 'The application appears to redirect to URLs specified in query parameters without proper validation.',
          impact: 'Attackers can use this for phishing attacks by redirecting users from a trusted domain to malicious sites.',
          remediation: 'Validate all redirect URLs against a whitelist of allowed destinations. Avoid using user input in redirect logic.',
          current_value: 'Redirect parameter accepted without validation',
          recommended_value: 'Redirect only to whitelisted URLs',
          cwe_id: 'CWE-601',
          confidence: 'low',
          isUniqueVulnerability: true,
          metadata: {
            redirect_detected: true,
            location
          }
        };
      }
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function checkDirectoryListing(target) {
  const dirsToCheck = ['/images/', '/css/', '/js/', '/assets/', '/uploads/', '/static/'];

  for (const dir of dirsToCheck) {
    try {
      const data = await fetchUrlData(target, dir);
      if (!data || !data.body) continue;

      const listingIndicators = [
        /Index of /i,
        /<title>Index of /i,
        /Parent Directory/i,
        /Directory Listing/i,
        /\[DIR\]/i,
        /\[FILE\]/i
      ];

      for (const indicator of listingIndicators) {
        if (indicator.test(data.body)) {
          return {
            category: 'deepScan',
            severity: 'medium',
            title: `Directory Listing Enabled: ${dir}`,
            description: `Directory listing is enabled for ${dir}, exposing the file structure of the application.`,
            impact: 'Attackers can browse directory contents to discover sensitive files, backup files, or understand application structure.',
            remediation: 'Disable directory listing in your web server configuration (Options -Indexes for Apache, autoindex off for nginx).',
            current_value: `Directory listing enabled for ${dir}`,
            recommended_value: 'Directory listing disabled',
            cwe_id: 'CWE-548',
            confidence: 'high',
            isUniqueVulnerability: true,
            metadata: {
              directory: dir,
              listing_detected: true
            }
          };
        }
      }
    } catch (e) {
      continue;
    }
  }
  return null;
}

async function checkCSRFProtection(target, fingerprint) {
  try {
    const data = await fetchUrlData(target, '/');
    if (!data || !data.body) return null;

    const formRegex = /<form[^>]*>/gi;
    const csrfPatterns = [
      /csrf/i, /_token/i, /authenticity_token/i, /__RequestVerificationToken/i,
      /xsrf/i, /csrfmiddlewaretoken/i, /csrf_token/i, /token/i
    ];

    let formCount = 0;
    let formsWithoutCSRF = 0;
    let match;

    while ((match = formRegex.exec(data.body)) !== null) {
      formCount++;
      const formTag = match[0];

      const hasCSRF = csrfPatterns.some(p => p.test(formTag));
      if (!hasCSRF) {
        const formEnd = data.body.indexOf('</form>', match.index);
        const formContent = formEnd > -1
          ? data.body.substring(match.index, formEnd)
          : data.body.substring(match.index, match.index + 2000);

        const hasCSRFField = csrfPatterns.some(p => p.test(formContent));
        if (!hasCSRFField) {
          formsWithoutCSRF++;
        }
      }
    }

    if (formCount > 0 && formsWithoutCSRF === formCount) {
      return {
        category: 'deepScan',
        severity: 'medium',
        title: 'Forms Missing CSRF Protection',
        description: `All ${formCount} form(s) detected on the main page appear to lack CSRF protection tokens.`,
        impact: 'Attackers can trick authenticated users into submitting forms against their will (Cross-Site Request Forgery).',
        remediation: 'Implement CSRF tokens on all state-changing forms. Most frameworks provide built-in CSRF protection.',
        current_value: `${formsWithoutCSRF}/${formCount} forms without CSRF tokens`,
        recommended_value: 'All forms should include CSRF protection tokens',
        cwe_id: 'CWE-352',
        confidence: 'low',
        isUniqueVulnerability: true,
        metadata: {
          total_forms: formCount,
          forms_without_csrf: formsWithoutCSRF
        }
      };
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function checkAPIHeaders(target) {
  const apiPaths = ['/api', '/api/v1', '/api/v2', '/graphql'];

  for (const apiPath of apiPaths) {
    try {
      const data = await fetchUrlData(target, apiPath);
      if (!data || data.statusCode >= 400) continue;

      const headers = data.headers;
      const missingHeaders = [];

      if (!getHeader(headers, 'x-content-type-options')) {
        missingHeaders.push('X-Content-Type-Options');
      }
      if (!getHeader(headers, 'x-frame-options')) {
        missingHeaders.push('X-Frame-Options');
      }
      if (!getHeader(headers, 'cache-control')) {
        missingHeaders.push('Cache-Control');
      }

      if (missingHeaders.length > 0) {
        return {
          category: 'deepScan',
          severity: 'medium',
          title: `API Endpoint Missing Security Headers: ${apiPath}`,
          description: `The API endpoint ${apiPath} is missing ${missingHeaders.length} recommended security header(s): ${missingHeaders.join(', ')}.`,
          impact: 'Missing security headers on API endpoints can lead to content sniffing, clickjacking, and caching of sensitive data.',
          remediation: `Add the following headers to API responses: ${missingHeaders.join(', ')}.`,
          current_value: `Missing: ${missingHeaders.join(', ')}`,
          recommended_value: 'All security headers should be configured',
          cwe_id: 'CWE-693',
          confidence: 'medium',
          isUniqueVulnerability: true,
          metadata: {
            api_path: apiPath,
            missing_headers: missingHeaders
          }
        };
      }
    } catch (e) {
      continue;
    }
  }
  return null;
}

async function analyzeCookieSecurity(baseHost, target) {
  const findings = [];

  try {
    const data = await fetchUrlData(target, '/');
    if (!data || !data.headers) return findings;

    const setCookieHeaders = data.headers['set-cookie'] || [];
    const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

    for (const cookieStr of cookies) {
      if (!cookieStr) continue;

      const cookieName = cookieStr.split('=')[0];
      const hasSecure = /;\s*secure/i.test(cookieStr);
      const hasHttpOnly = /;\s*httponly/i.test(cookieStr);
      const hasSameSite = /;\s*samesite=/i.test(cookieStr);

      if (!hasSecure) {
        findings.push({
          category: 'deepScan',
          severity: 'high',
          title: `Cookie "${cookieName}" Missing Secure Flag`,
          description: `The cookie "${cookieName}" is set without the Secure flag, meaning it can be transmitted over unencrypted HTTP connections.`,
          impact: 'Attackers can intercept the cookie over unencrypted connections via man-in-the-middle attacks.',
          remediation: 'Add the Secure flag to all cookies to ensure they are only sent over HTTPS.',
          current_value: `Cookie ${cookieName} without Secure flag`,
          recommended_value: 'Set-Cookie: ...; Secure; HttpOnly; SameSite=Lax',
          cwe_id: 'CWE-614',
          confidence: 'high',
          isUniqueVulnerability: true,
          metadata: {
            cookie_name: cookieName,
            missing_flags: ['Secure']
          }
        });
      }

      if (!hasHttpOnly) {
        findings.push({
          category: 'deepScan',
          severity: 'medium',
          title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
          description: `The cookie "${cookieName}" is set without the HttpOnly flag, making it accessible to client-side JavaScript.`,
          impact: 'If the site has an XSS vulnerability, attackers can steal this cookie via JavaScript.',
          remediation: 'Add the HttpOnly flag to cookies that do not need to be accessed by JavaScript.',
          current_value: `Cookie ${cookieName} without HttpOnly flag`,
          recommended_value: 'Set-Cookie: ...; HttpOnly; Secure; SameSite=Lax',
          cwe_id: 'CWE-1004',
          confidence: 'medium',
          isUniqueVulnerability: true,
          metadata: {
            cookie_name: cookieName,
            missing_flags: ['HttpOnly']
          }
        });
      }

      if (!hasSameSite) {
        findings.push({
          category: 'deepScan',
          severity: 'low',
          title: `Cookie "${cookieName}" Missing SameSite Attribute`,
          description: `The cookie "${cookieName}" is set without the SameSite attribute, which helps prevent CSRF attacks.`,
          impact: 'The cookie may be sent in cross-site requests, increasing CSRF risk.',
          remediation: 'Add SameSite=Lax or SameSite=Strict to all cookies.',
          current_value: `Cookie ${cookieName} without SameSite attribute`,
          recommended_value: 'Set-Cookie: ...; SameSite=Lax; Secure; HttpOnly',
          cwe_id: 'CWE-1275',
          confidence: 'medium',
          isUniqueVulnerability: true,
          metadata: {
            cookie_name: cookieName,
            missing_flags: ['SameSite']
          }
        });
      }
    }
  } catch (e) {
    // Cookie analysis failed, skip
  }

  return findings;
}

async function analyzeFormSecurity(baseHost, target) {
  const findings = [];

  try {
    const data = await fetchUrlData(target, '/');
    if (!data || !data.body) return findings;

    // Check for password fields without proper attributes
    const passwordFieldRegex = /<input[^>]*type=["']password["'][^>]*>/gi;
    let match;

    while ((match = passwordFieldRegex.exec(data.body)) !== null) {
      const field = match[0];

      if (!/autocomplete\s*=\s*["']off["']/i.test(field)) {
        findings.push({
          category: 'deepScan',
          severity: 'low',
          title: 'Password Field Missing Autocomplete="off"',
          description: 'A password input field was detected without the autocomplete="off" attribute, which may allow browsers to autofill credentials in shared computer scenarios.',
          impact: 'In shared computer environments, previously saved credentials could be automatically filled.',
          remediation: 'Add autocomplete="off" or autocomplete="new-password" to password fields.',
          current_value: 'Password field without autocomplete restriction',
          recommended_value: 'autocomplete="new-password" on password fields',
          cwe_id: 'CWE-200',
          confidence: 'medium',
          isUniqueVulnerability: true,
          metadata: {
            field_html: field.substring(0, 200)
          }
        });
      }
    }

    const fileUploadRegex = /<input[^>]*type=["']file["'][^>]*>/gi;
    while ((match = fileUploadRegex.exec(data.body)) !== null) {
      const field = match[0];

      if (!/accept\s*=\s*["']/i.test(field)) {
        findings.push({
          category: 'deepScan',
          severity: 'medium',
          title: 'File Upload Field Missing Accept Restrictions',
          description: 'A file upload field was detected without accept attribute restrictions, allowing any file type to be uploaded.',
          impact: 'Unrestricted file upload can lead to arbitrary file upload vulnerabilities, potentially allowing code execution.',
          remediation: 'Restrict file upload types using the accept attribute and implement server-side validation.',
          current_value: 'File upload without type restrictions',
          recommended_value: 'accept=".jpg,.png,.pdf" with server-side validation',
          cwe_id: 'CWE-434',
          confidence: 'low',
          isUniqueVulnerability: true,
          metadata: {
            field_html: field.substring(0, 200)
          }
        });
      }
    }
  } catch (e) {
    // Form analysis failed, skip
  }

  return findings;
}

// Case-insensitive header lookup
function getHeader(headers, name) {
  if (!headers) return null;
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      return headers[key];
    }
  }
  return null;
}

function isCommonPath(path) {
  const commonPaths = [
    '/admin', '/administrator', '/wp-admin', '/wp-content', '/wp-includes',
    '/login', '/register', '/api', '/assets', '/css', '/js', '/images',
    '/uploads', '/files', '/static', '/public', '/download', '/favicon.ico',
    '/robots.txt', '/sitemap.xml', '/.env', '/.git', '/config', '/backup',
    '/.well-known', '/server-status', '/phpmyadmin', '/dashboard'
  ];
  return commonPaths.some(cp => path.startsWith(cp));
}

/**
 * Fetch URL data using the pinned request utility with guaranteed timeout.
 * Uses pinnedGet which sets a hard timeout on the socket to prevent hangs.
 */
async function fetchUrlData(target, path) {
  try {
    const result = await pinnedGet(target, path, { timeout: 8000, maxBodySize: 100000 });
    return result;
  } catch (e) {
    return null;
  }
}

module.exports = { deepScanTarget, generateVulnerabilitySignature };