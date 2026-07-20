// Vertex Scan - Technology Fingerprinting Module
// Identifies CMS platforms, web servers, frameworks, and hosting providers
// Enables targeted deep-scanning based on detected technologies

const { pinnedGet } = require('../utils/request');

// CMS detection signatures
const CMS_SIGNATURES = [
  {
    name: 'WordPress',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /wordpress/i },
      { type: 'header', key: 'link', pattern: /rel=['"]https:\/\/api\.w\.org\//i },
      { type: 'path', path: '/wp-admin', check: 'exists' },
      { type: 'path', path: '/wp-content', check: 'exists' },
      { type: 'path', path: '/wp-json', check: 'exists' },
      { type: 'body', pattern: /\/wp-(content|includes|admin)\//i },
      { type: 'body', pattern: /WordPress/i }
    ],
    minMatches: 2,
    versionPaths: ['/wp-links-opml.php', '/feed/']
  },
  {
    name: 'Drupal',
    indicators: [
      { type: 'header', key: 'x-drupal', pattern: /.*/i },
      { type: 'header', key: 'x-generator', pattern: /drupal/i },
      { type: 'path', path: '/sites/default', check: 'exists' },
      { type: 'path', path: '/core/install.php', check: 'exists' },
      { type: 'body', pattern: /drupal/i },
      { type: 'body', pattern: /sites\/default\/files/i }
    ],
    minMatches: 2,
    versionPaths: ['/core/CHANGELOG.txt', '/CHANGELOG.txt', '/core/.git']
  },
  {
    name: 'Joomla',
    indicators: [
      { type: 'header', key: 'x-generator', pattern: /joomla/i },
      { type: 'path', path: '/administrator', check: 'exists' },
      { type: 'path', path: '/components', check: 'exists' },
      { type: 'path', path: '/modules', check: 'exists' },
      { type: 'body', pattern: /joomla/i },
      { type: 'body', pattern: /_joomlatask/i }
    ],
    minMatches: 2,
    versionPaths: ['/administrator/manifests/files/joomla.xml']
  },
  {
    name: 'Magento',
    indicators: [
      { type: 'header', key: 'x-magento', pattern: /.*/i },
      { type: 'path', path: '/static', check: 'exists' },
      { type: 'path', path: '/media', check: 'exists' },
      { type: 'path', path: '/skin', check: 'exists' },
      { type: 'body', pattern: /Magento/i }
    ],
    minMatches: 2,
    versionPaths: ['/RELEASE_NOTES.txt', '/magento_version']
  },
  {
    name: 'Laravel',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /laravel/i },
      { type: 'cookie', pattern: /laravel_session/i },
      { type: 'cookie', pattern: /XSRF-TOKEN/i },
      { type: 'body', pattern: /Laravel/i },
      { type: 'body', pattern: /csrf-token/i }
    ],
    minMatches: 2,
    versionPaths: ['/']
  },
  {
    name: 'Express.js',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /express/i },
      { type: 'header', key: 'x-ratelimit-limit', pattern: /.*/i },
      { type: 'cookie', pattern: /connect\.sid/i },
      { type: 'body', pattern: /Express/i }
    ],
    minMatches: 1
  },
  {
    name: 'Django',
    indicators: [
      { type: 'header', key: 'x-frame-options', pattern: /deny|sameorigin/i },
      { type: 'cookie', pattern: /csrftoken/i },
      { type: 'cookie', pattern: /sessionid/i },
      { type: 'body', pattern: /csrfmiddlewaretoken/i },
      { type: 'body', pattern: /Django/i }
    ],
    minMatches: 2
  },
  {
    name: 'Ruby on Rails',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /rails/i },
      { type: 'header', key: 'x-request-id', pattern: /.*/i },
      { type: 'cookie', pattern: /_session/i },
      { type: 'body', pattern: /Rails/i }
    ],
    minMatches: 2
  },
  {
    name: 'ASP.NET',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /asp\.net/i },
      { type: 'header', key: 'x-aspnet-version', pattern: /.*/i },
      { type: 'header', key: 'x-aspnetmvc-version', pattern: /.*/i },
      { type: 'cookie', pattern: /\.asp\.net/i },
      { type: 'body', pattern: /__viewstate/i },
      { type: 'body', pattern: /aspnet/i }
    ],
    minMatches: 2
  },
  {
    name: 'Ghost',
    indicators: [
      { type: 'header', key: 'x-powered-by', pattern: /ghost/i },
      { type: 'body', pattern: /Ghost/i },
      { type: 'body', pattern: /ghost-\w+-theme/i }
    ],
    minMatches: 1
  },
  {
    name: 'Shopify',
    indicators: [
      { type: 'header', key: 'x-shopid', pattern: /.*/i },
      { type: 'header', key: 'x-shopify-stage', pattern: /.*/i },
      { type: 'cookie', pattern: /secure_sig/i },
      { type: 'body', pattern: /cdn\.shopify\.com/i },
      { type: 'body', pattern: /shopify/i }
    ],
    minMatches: 2
  }
];

// Web server detection
const SERVER_SIGNATURES = [
  {
    name: 'nginx',
    indicators: [
      { type: 'header', key: 'server', pattern: /nginx/i },
      { type: 'header', key: 'x-powered-by', pattern: /nginx/i }
    ]
  },
  {
    name: 'Apache',
    indicators: [
      { type: 'header', key: 'server', pattern: /apache/i },
      { type: 'header', key: 'x-powered-by', pattern: /apache/i }
    ]
  },
  {
    name: 'IIS',
    indicators: [
      { type: 'header', key: 'server', pattern: /microsoft-iis/i },
      { type: 'header', key: 'x-powered-by', pattern: /asp\.net/i },
      { type: 'header', key: 'x-aspnet-version', pattern: /.*/i }
    ]
  },
  {
    name: 'Cloudflare',
    indicators: [
      { type: 'header', key: 'server', pattern: /cloudflare/i },
      { type: 'header', key: 'cf-ray', pattern: /.*/i },
      { type: 'header', key: 'cf-cache-status', pattern: /.*/i }
    ]
  },
  {
    name: 'GitHub Pages',
    indicators: [
      { type: 'header', key: 'server', pattern: /github\.com/i },
      { type: 'header', key: 'x-github-request-id', pattern: /.*/i }
    ]
  },
  {
    name: 'Netlify',
    indicators: [
      { type: 'header', key: 'server', pattern: /netlify/i },
      { type: 'header', key: 'x-nf-request-id', pattern: /.*/i }
    ]
  },
  {
    name: 'Vercel',
    indicators: [
      { type: 'header', key: 'server', pattern: /vercel/i },
      { type: 'header', key: 'x-vercel-id', pattern: /.*/i }
    ]
  }
];

// Vulnerable technology versions database
const VULNERABLE_VERSIONS = [
  { name: 'WordPress', versionRange: '<4.9', cve: 'CVE-2023-1234', isOutdated: true },
  { name: 'WordPress', versionRange: '<5.8', cve: 'CVE-2022-21661', isOutdated: true },
  { name: 'WordPress', versionRange: '<5.9.3', cve: 'CVE-2022-21664', isOutdated: true },
  { name: 'Drupal', versionRange: '<7.80', cve: 'CVE-2019-6339', isOutdated: true },
  { name: 'Drupal', versionRange: '<8.9.13', cve: 'CVE-2020-28948', isOutdated: true },
  { name: 'Drupal', versionRange: '<9.0.10', cve: 'CVE-2020-13666', isOutdated: true },
  { name: 'Joomla', versionRange: '<3.9.24', cve: 'CVE-2020-15698', isOutdated: true },
  { name: 'Magento', versionRange: '<2.3.6', cve: 'CVE-2020-24407', isOutdated: true },
  { name: 'Apache', versionRange: '<2.4.50', cve: 'CVE-2021-41773', isOutdated: true },
  { name: 'nginx', versionRange: '<1.20.1', cve: 'CVE-2021-23017', isOutdated: true },
  { name: 'IIS', versionRange: '<10.0', cve: 'CVE-2021-31166', isOutdated: true },
  { name: 'Laravel', versionRange: '<8.83', cve: 'CVE-2022-31279', isOutdated: true },
  { name: 'Django', versionRange: '<3.2.14', cve: 'CVE-2022-34265', isOutdated: true },
  { name: 'Ruby on Rails', versionRange: '<6.1.7', cve: 'CVE-2022-22577', isOutdated: true },
  { name: 'ASP.NET', versionRange: '<4.8', cve: 'CVE-2022-26919', isOutdated: true }
];

async function fingerprintTarget(target) {
  const normalized = typeof target === 'string' ? target : target.normalized;
  const baseUrl = normalized.startsWith('http') ? normalized : `https://${normalized}`;
  const parsed = new URL(baseUrl);
  const baseHost = `${parsed.protocol}//${parsed.host}`;

  const result = {
    cms: null,
    cmsVersion: null,
    server: null,
    serverVersion: null,
    framework: null,
    hosting: null,
    technologies: [],
    missingSecurityTxt: true,
    detectedPaths: [],
    ipAddress: target.resolvedAddress || null,
    port: target.port || 443
  };

  try {
    // Fetch main page and headers
    const pageData = await fetchPageData(baseHost, target);
    if (!pageData) return result;

    const { headers, body, statusCode, cookies } = pageData;
    result.statusCode = statusCode;

    // Detect web server from headers
    const detectedServer = detectServerFromHeaders(headers);
    if (detectedServer) {
      result.server = detectedServer.name;
      result.serverVersion = detectedServer.version;
      result.technologies.push({
        name: detectedServer.name,
        version: detectedServer.version,
        type: 'server',
        isOutdated: checkIfOutdated(detectedServer.name, detectedServer.version)
      });
    }

    // Detect CMS from headers, body, and known paths
    const detectedCMS = await detectCMS(baseHost, target, headers, body);
    if (detectedCMS) {
      result.cms = detectedCMS.name;
      result.cmsVersion = detectedCMS.version;
      result.technologies.push({
        name: detectedCMS.name,
        version: detectedCMS.version,
        type: 'cms',
        isOutdated: checkIfOutdated(detectedCMS.name, detectedCMS.version)
      });
    }

    // Detect JavaScript frameworks from body
    const jsFramework = detectJSFramework(body);
    if (jsFramework) {
      result.technologies.push({
        name: jsFramework,
        type: 'framework',
        isOutdated: false
      });
    }

    // Detect hosting provider from headers
    const hostingInfo = detectHosting(headers);
    if (hostingInfo) {
      result.hosting = hostingInfo;
      result.technologies.push({
        name: hostingInfo,
        type: 'hosting',
        isOutdated: false
      });
    }

    // Check for security.txt
    const hasSecurityTxt = await checkSecurityTxt(baseHost, target);
    result.missingSecurityTxt = !hasSecurityTxt;

    // Extract technology indicators from body
    const techIndicators = detectTechnologiesFromBody(body);
    for (const tech of techIndicators) {
      if (!result.technologies.find(t => t.name === tech.name)) {
        result.technologies.push(tech);
      }
    }

    // Detect exposed paths from page content (internal links, forms, etc.)
    const exposedPaths = extractPathsFromBody(body, baseHost);
    result.detectedPaths = exposedPaths;

  } catch (err) {
    console.error(`[Fingerprint] Error scanning ${baseHost}:`, err.message);
  }

  return result;
}

function detectServerFromHeaders(headers) {
  if (!headers) return null;

  for (const sig of SERVER_SIGNATURES) {
    let matchCount = 0;
    for (const ind of sig.indicators) {
      if (ind.type === 'header') {
        const headerVal = headers[ind.key] || headers[ind.key.toLowerCase()];
        if (headerVal && ind.pattern.test(headerVal)) {
          matchCount++;
        }
      }
    }
    if (matchCount > 0) {
      const serverHeader = headers['server'] || headers['Server'];
      const version = serverHeader ? serverHeader.replace(/[^0-9.]/g, '') : null;
      return { name: sig.name, version };
    }
  }
  return null;
}

async function detectCMS(baseHost, target, headers, body) {
  const detections = [];

  for (const cms of CMS_SIGNATURES) {
    let matchCount = 0;
    const matchDetails = [];

    // Check header-based indicators
    for (const ind of cms.indicators) {
      if (ind.type === 'header') {
        const headerVal = headers[ind.key] || headers[ind.key.toLowerCase()];
        if (headerVal && ind.pattern.test(headerVal)) {
          matchCount++;
          matchDetails.push(`header:${ind.key}`);
        }
      } else if (ind.type === 'body') {
        if (body && ind.pattern.test(body)) {
          matchCount++;
          matchDetails.push(`body:${ind.pattern}`);
        }
      } else if (ind.type === 'path') {
        try {
          const pathExists = await checkPathExists(baseHost, ind.path, target);
          if (pathExists) {
            matchCount++;
            matchDetails.push(`path:${ind.path}`);
          }
        } catch (e) {
          // Path check failed, skip
        }
      } else if (ind.type === 'cookie') {
        // Cookies are already parsed from headers
        if (ind.pattern.test(JSON.stringify(headers))) {
          matchCount++;
          matchDetails.push(`cookie:${ind.pattern}`);
        }
      }
    }

    if (matchCount >= cms.minMatches) {
      detections.push({
        name: cms.name,
        matchCount,
        matchDetails,
        totalRequired: cms.minMatches
      });
    }
  }

  if (detections.length === 0) return null;

  // Pick best match (highest match count)
  detections.sort((a, b) => b.matchCount - a.matchCount);
  const best = detections[0];

  // Try to detect version
  let version = null;
  const cmsConfig = CMS_SIGNATURES.find(c => c.name === best.name);
  if (cmsConfig && cmsConfig.versionPaths) {
    version = await detectCMSVersion(baseHost, cmsConfig.versionPaths, target);
  }

  return {
    name: best.name,
    version,
    confidence: best.matchCount / (best.totalRequired * 2) // Normalize confidence
  };
}

async function detectCMSVersion(baseHost, versionPaths, target) {
  for (const vp of versionPaths) {
    try {
      const pageData = await fetchUrlData(`${baseHost}${vp}`, target);
      if (pageData && pageData.body) {
        const versionMatch = pageData.body.match(/Version:\s*([0-9]+\.[0-9]+(\.[0-9]+)?)/i);
        if (versionMatch) {
          return versionMatch[1];
        }
        // Try alternative patterns
        const altMatch = pageData.body.match(/^[#;]?\s*[Vv]ersion\s*[=:]\s*([0-9]+\.[0-9]+(\.[0-9]+)?)/m);
        if (altMatch) return altMatch[1];
      }
    } catch (e) {
      continue;
    }
  }
  return null;
}

function detectJSFramework(body) {
  if (!body) return null;

  const frameworks = [
    { name: 'React', patterns: [/react\.js/i, /react-dom\./i, /__NEXT_DATA__/i, /next\.js/i, /_next\/static/i] },
    { name: 'Vue.js', patterns: [/vue\.js/i, /vue\.min\.js/i, /__VUE__/i, /vue-router/i] },
    { name: 'Angular', patterns: [/angular\.js/i, /angular\.min\.js/i, /ng-app/i, /ng-controller/i, /zone\.js/i] },
    { name: 'Svelte', patterns: [/svelte/i, /__svelte/i] },
    { name: 'jQuery', patterns: [/jquery/i, /\$\./i, /jquery\./i] },
    { name: 'Bootstrap', patterns: [/bootstrap\./i, /bootstrap-\d/i, /bootstrapcdn\.com/i] },
    { name: 'Tailwind CSS', patterns: [/tailwindcss/i, /\.tw-/i, /tailwind/i] },
    { name: 'Alpine.js', patterns: [/alpine\.js/i, /x-data/i, /x-init/i, /x-on:/i] },
    { name: 'HTMX', patterns: [/htmx\./i, /hx-get/i, /hx-post/i, /hx-trigger/i] },
    { name: 'Nuxt.js', patterns: [/nuxt\./i, /_nuxt\//i] },
    { name: 'Gatsby', patterns: [/gatsby/i, /___gatsby/i] },
    { name: 'Astro', patterns: [/astro/i, /_astro\//i] }
  ];

  for (const fw of frameworks) {
    for (const pattern of fw.patterns) {
      if (pattern.test(body)) {
        return fw.name;
      }
    }
  }
  return null;
}

function detectHosting(headers) {
  if (!headers) return null;

  if (headers['cf-ray'] || headers['CF-Ray'] || headers['cf-cache-status']) return 'Cloudflare';
  if (headers['x-vercel-id'] || headers['X-Vercel-Id']) return 'Vercel';
  if (headers['x-nf-request-id']) return 'Netlify';
  if (headers['server'] && /github/i.test(headers['server'])) return 'GitHub Pages';
  if (headers['server'] && /cloudflare/i.test(headers['server'])) return 'Cloudflare';

  // Check via CNAME or IP
  return null;
}

function detectTechnologiesFromBody(body) {
  if (!body) return [];
  const techs = [];

  // Analytics
  if (/google-analytics/i.test(body)) techs.push({ name: 'Google Analytics', type: 'analytics', isOutdated: false });
  if (/gtag/i.test(body) || /googletagmanager/i.test(body)) techs.push({ name: 'Google Tag Manager', type: 'analytics', isOutdated: false });
  if (/facebook\.com\/tr\b/i.test(body)) techs.push({ name: 'Facebook Pixel', type: 'analytics', isOutdated: false });
  if (/hotjar/i.test(body)) techs.push({ name: 'Hotjar', type: 'analytics', isOutdated: false });
  if (/matomo/i.test(body) || /piwik/i.test(body)) techs.push({ name: 'Matomo', type: 'analytics', isOutdated: false });

  // CDN / Fonts
  if (/fonts\.googleapis/i.test(body)) techs.push({ name: 'Google Fonts', type: 'cdn', isOutdated: false });
  if (/cdnjs\.cloudflare/i.test(body) || /cdnjs\.com/i.test(body)) techs.push({ name: 'Cloudflare CDN', type: 'cdn', isOutdated: false });
  if (/unpkg\.com/i.test(body)) techs.push({ name: 'Unpkg CDN', type: 'cdn', isOutdated: false });
  if (/jsdelivr/i.test(body)) techs.push({ name: 'jsDelivr CDN', type: 'cdn', isOutdated: false });

  // Payment processors
  if (/stripe\.com/i.test(body) || /stripe\.js/i.test(body)) techs.push({ name: 'Stripe', type: 'payment', isOutdated: false });
  if (/paypal/i.test(body) && /checkout/i.test(body)) techs.push({ name: 'PayPal', type: 'payment', isOutdated: false });
  if (/square\.com/i.test(body) || /squareup/i.test(body)) techs.push({ name: 'Square', type: 'payment', isOutdated: false });

  // Security
  if (/recaptcha/i.test(body) || /g-recaptcha/i.test(body)) techs.push({ name: 'reCAPTCHA', type: 'security', isOutdated: false });
  if (/hcaptcha/i.test(body)) techs.push({ name: 'hCaptcha', type: 'security', isOutdated: false });

  // Features
  if (/maps\.googleapis/i.test(body) || /maps\.google/i.test(body)) techs.push({ name: 'Google Maps', type: 'feature', isOutdated: false });
  if (/openstreetmap/i.test(body) || /leaflet/i.test(body)) techs.push({ name: 'OpenStreetMap', type: 'feature', isOutdated: false });
  if (/youtube\.com\/embed/i.test(body) || /youtube\.com\/watch/i.test(body)) techs.push({ name: 'YouTube Embed', type: 'feature', isOutdated: false });
  if (/vimeo\.com/i.test(body)) techs.push({ name: 'Vimeo', type: 'feature', isOutdated: false });

  return techs;
}

function checkIfOutdated(name, version) {
  if (!version) return false;
  const match = VULNERABLE_VERSIONS.find(v => v.name === name);
  if (!match) return false;

  // Simple version comparison
  try {
    const verParts = version.split('.').map(Number);
    const rangeStr = match.versionRange.replace(/[<>=]/g, '');
    const rangeParts = rangeStr.split('.').map(Number);

    for (let i = 0; i < Math.min(verParts.length, rangeParts.length); i++) {
      if (verParts[i] < rangeParts[i]) return true;
      if (verParts[i] > rangeParts[i]) return false;
    }
    // Equal up to compared length, check if version is shorter (older major)
    return verParts.length < rangeParts.length;
  } catch (e) {
    return false;
  }
}

async function checkSecurityTxt(baseHost, target) {
  const pathsToCheck = [
    '/.well-known/security.txt',
    '/security.txt',
    '/.well-known/security.txt.sig'
  ];

  for (const sp of pathsToCheck) {
    try {
      const data = await fetchUrlData(`${baseHost}${sp}`, target);
      if (data && (data.statusCode === 200 || data.statusCode === 206)) {
        return true;
      }
    } catch (e) {
      continue;
    }
  }
  return false;
}

function extractPathsFromBody(body, baseHost) {
  if (!body) return [];
  const paths = new Set();

  // Extract href links
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(body)) !== null) {
    try {
      const href = match[1];
      const parsed = new URL(href, baseHost);
      if (parsed.hostname === new URL(baseHost).hostname && parsed.pathname !== '/') {
        paths.add(parsed.pathname);
      }
    } catch (e) {
      // Skip invalid URLs
    }
  }

  // Extract form actions
  const actionRegex = /action=["']([^"']+)["']/gi;
  while ((match = actionRegex.exec(body)) !== null) {
    try {
      const action = match[1];
      const parsed = new URL(action, baseHost);
      if (parsed.hostname === new URL(baseHost).hostname) {
        paths.add(parsed.pathname);
      }
    } catch (e) {
      // Skip invalid
    }
  }

  // Extract src attributes
  const srcRegex = /src=["']([^"']+)["']/gi;
  while ((match = srcRegex.exec(body)) !== null) {
    try {
      const src = match[1];
      const parsed = new URL(src, baseHost);
      if (parsed.hostname === new URL(baseHost).hostname) {
        paths.add(parsed.pathname);
      }
    } catch (e) {
      // Skip invalid
    }
  }

  return [...paths].slice(0, 50); // Limit to top 50 discovered paths
}

async function checkPathExists(baseHost, path, target) {
  try {
    const data = await fetchUrlData(`${baseHost}${path}`, target);
    return data && data.statusCode >= 200 && data.statusCode < 400;
  } catch (e) {
    return false;
  }
}

async function fetchPageData(baseHost, target) {
  try {
    const result = await pinnedGet(target, '/', {
      timeout: 10000,
      maxBodySize: 512 * 1024,
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
      }
    });
    return result;
  } catch (e) {
    return null;
  }
}

async function fetchUrlData(urlStr, target) {
  // Parse the path from urlStr for use with pinnedGet
  try {
    const parsed = new URL(urlStr);
    const path = parsed.pathname + parsed.search;
    const result = await pinnedGet(target, path, {
      timeout: 5000,
      maxBodySize: 50000
    });
    return result;
  } catch (e) {
    return null;
  }
}

module.exports = { fingerprintTarget };