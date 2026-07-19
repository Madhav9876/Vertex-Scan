// Vertex Scan - Directory Scanner
// Discovers exposed directories, files, and sensitive endpoints

const https = require('https');
const http = require('http');
const url = require('url');
const { buildPinnedUrl, applyPinnedTarget } = require('../utils/validation');

const COMMON_PATHS = [
  // Admin panels
  { path: '/admin', severity: 'high', category: 'admin' },
  { path: '/administrator', severity: 'high', category: 'admin' },
  { path: '/admin/login', severity: 'high', category: 'admin' },
  { path: '/wp-admin', severity: 'high', category: 'admin' },
  { path: '/dashboard', severity: 'medium', category: 'admin' },
  { path: '/cpanel', severity: 'high', category: 'admin' },
  { path: '/phpmyadmin', severity: 'critical', category: 'admin' },
  { path: '/pma', severity: 'critical', category: 'admin' },
  { path: '/adminer', severity: 'critical', category: 'admin' },
  
  // Configuration files
  { path: '/.env', severity: 'critical', category: 'config' },
  { path: '/.git/config', severity: 'critical', category: 'config' },
  { path: '/.git/HEAD', severity: 'critical', category: 'config' },
  { path: '/config.php', severity: 'high', category: 'config' },
  { path: '/config.json', severity: 'high', category: 'config' },
  { path: '/configuration.php', severity: 'high', category: 'config' },
  { path: '/wp-config.php', severity: 'critical', category: 'config' },
  { path: '/.htaccess', severity: 'high', category: 'config' },
  { path: '/web.config', severity: 'medium', category: 'config' },
  { path: '/robots.txt', severity: 'low', category: 'info' },
  { path: '/sitemap.xml', severity: 'low', category: 'info' },
  { path: '/crossdomain.xml', severity: 'medium', category: 'config' },
  { path: '/clientaccesspolicy.xml', severity: 'medium', category: 'config' },
  
  // Sensitive files
  { path: '/backup', severity: 'high', category: 'sensitive' },
  { path: '/backup.zip', severity: 'critical', category: 'sensitive' },
  { path: '/backup.sql', severity: 'critical', category: 'sensitive' },
  { path: '/dump.sql', severity: 'critical', category: 'sensitive' },
  { path: '/db.sql', severity: 'critical', category: 'sensitive' },
  { path: '/database.sql', severity: 'critical', category: 'sensitive' },
  { path: '/.sql', severity: 'critical', category: 'sensitive' },
  { path: '/log', severity: 'medium', category: 'sensitive' },
  { path: '/logs', severity: 'medium', category: 'sensitive' },
  { path: '/error.log', severity: 'medium', category: 'sensitive' },
  { path: '/debug.log', severity: 'medium', category: 'sensitive' },
  { path: '/.npmrc', severity: 'medium', category: 'sensitive' },
  { path: '/.dockerenv', severity: 'medium', category: 'sensitive' },
  { path: '/Dockerfile', severity: 'low', category: 'info' },
  { path: '/docker-compose.yml', severity: 'medium', category: 'sensitive' },
  
  // API endpoints
  { path: '/api', severity: 'medium', category: 'api' },
  { path: '/api/v1', severity: 'medium', category: 'api' },
  { path: '/api/docs', severity: 'medium', category: 'api' },
  { path: '/swagger', severity: 'medium', category: 'api' },
  { path: '/swagger.json', severity: 'medium', category: 'api' },
  { path: '/api-docs', severity: 'medium', category: 'api' },
  { path: '/graphql', severity: 'medium', category: 'api' },
  { path: '/graphiql', severity: 'high', category: 'api' },
  
  // Development files
  { path: '/.git', severity: 'high', category: 'dev' },
  { path: '/.svn', severity: 'high', category: 'dev' },
  { path: '/.DS_Store', severity: 'low', category: 'dev' },
  { path: '/Thumbs.db', severity: 'low', category: 'dev' },
  { path: '/composer.json', severity: 'low', category: 'dev' },
  { path: '/composer.lock', severity: 'low', category: 'dev' },
  { path: '/package.json', severity: 'low', category: 'dev' },
  { path: '/package-lock.json', severity: 'low', category: 'dev' },
  { path: '/yarn.lock', severity: 'low', category: 'dev' },
  { path: '/webpack.config.js', severity: 'low', category: 'dev' },
  { path: '/.babelrc', severity: 'low', category: 'dev' },
  { path: '/tsconfig.json', severity: 'low', category: 'dev' },
  { path: '/Makefile', severity: 'low', category: 'dev' },
  
  // Common CMS paths
  { path: '/wp-content', severity: 'medium', category: 'cms' },
  { path: '/wp-includes', severity: 'medium', category: 'cms' },
  { path: '/wp-json', severity: 'medium', category: 'cms' },
  { path: '/wp-content/uploads', severity: 'medium', category: 'cms' },
  { path: '/wp-content/plugins', severity: 'high', category: 'cms' },
  { path: '/wp-content/themes', severity: 'medium', category: 'cms' },
  { path: '/joomla', severity: 'medium', category: 'cms' },
  { path: '/drupal', severity: 'medium', category: 'cms' },
  { path: '/magento', severity: 'medium', category: 'cms' },
  
  // File uploads and user content
  { path: '/uploads', severity: 'medium', category: 'content' },
  { path: '/files', severity: 'medium', category: 'content' },
  { path: '/images', severity: 'low', category: 'content' },
  { path: '/assets', severity: 'low', category: 'content' },
  { path: '/static', severity: 'low', category: 'content' },
  { path: '/public', severity: 'low', category: 'content' },
  { path: '/download', severity: 'medium', category: 'content' },
  { path: '/downloads', severity: 'medium', category: 'content' },
  
  // Authentication
  { path: '/login', severity: 'low', category: 'auth' },
  { path: '/signin', severity: 'low', category: 'auth' },
  { path: '/register', severity: 'low', category: 'auth' },
  { path: '/signup', severity: 'low', category: 'auth' },
  { path: '/forgot-password', severity: 'low', category: 'auth' },
  { path: '/reset-password', severity: 'low', category: 'auth' },
  { path: '/logout', severity: 'low', category: 'auth' },
  { path: '/oauth', severity: 'medium', category: 'auth' },
  { path: '/oauth2', severity: 'medium', category: 'auth' },
  
  // Common web paths
  { path: '/.well-known', severity: 'low', category: 'info' },
  { path: '/.well-known/security.txt', severity: 'info', category: 'info' },
  { path: '/favicon.ico', severity: 'info', category: 'info' },
  { path: '/server-status', severity: 'high', category: 'info' },
  { path: '/server-info', severity: 'high', category: 'info' },
  { path: '/info.php', severity: 'high', category: 'info' },
  { path: '/phpinfo.php', severity: 'high', category: 'info' },
  { path: '/test.php', severity: 'medium', category: 'info' },
  { path: '/shell.php', severity: 'critical', category: 'malware' },
  { path: '/cmd.php', severity: 'critical', category: 'malware' },
  { path: '/eval.php', severity: 'critical', category: 'malware' },
  { path: '/c99.php', severity: 'critical', category: 'malware' },
  { path: '/r57.php', severity: 'critical', category: 'malware' },
  
  // Proxies and services
  { path: '/proxy', severity: 'high', category: 'service' },
  { path: '/actuator', severity: 'high', category: 'service' },
  { path: '/actuator/health', severity: 'medium', category: 'service' },
  { path: '/actuator/env', severity: 'critical', category: 'service' },
  { path: '/actuator/beans', severity: 'high', category: 'service' },
  { path: '/h2-console', severity: 'critical', category: 'service' },
  { path: '/console', severity: 'high', category: 'service' },
  { path: '/jmx', severity: 'critical', category: 'service' },
];

const SEVERITY_DESCRIPTIONS = {
  critical: {
    impact: 'Immediate security risk. This path exposes sensitive data or allows unauthorized access.',
    remediation: 'Restrict access immediately. Remove or password-protect this path. Review server configuration.'
  },
  high: {
    impact: 'Significant security concern. This path may expose sensitive information or functionality.',
    remediation: 'Restrict access to authorized users only. Consider removing or obfuscating this path.'
  },
  medium: {
    impact: 'Moderate security concern. This path may provide useful information to attackers.',
    remediation: 'Review if this path needs to be publicly accessible. Implement access controls if necessary.'
  },
  low: {
    impact: 'Minor information disclosure. This path reveals limited information about the application.',
    remediation: 'Review if this path should be publicly accessible.'
  },
  info: {
    impact: 'Informational finding. No direct security impact.',
    remediation: 'No action required, but review for any unintended information disclosure.'
  }
};

async function scanDirectories(target) {
  const findings = [];
  const normalized = typeof target === 'string' ? target : target.normalized;
  const baseUrl = normalized.startsWith('http') ? normalized : `https://${normalized}`;
  const parsed = new URL(baseUrl);
  const baseHost = `${parsed.protocol}//${parsed.host}`;

  // Scan in batches to avoid overwhelming the target
  const batchSize = 10;
  const paths = [...COMMON_PATHS];
  
  for (let i = 0; i < paths.length; i += batchSize) {
    const batch = paths.slice(i, i + batchSize);
    const promises = batch.map(pathConfig =>
      checkPath(baseHost, pathConfig, target)
        .then(result => {
          if (result) {
            findings.push(result);
          }
        })
        .catch(() => {})
    );
    
    await Promise.all(promises);
    
    // Small delay between batches to be respectful
    if (i + batchSize < paths.length) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  // If no findings, add an informational one
  if (findings.length === 0) {
    findings.push({
      category: 'directories',
      severity: 'info',
      title: 'No Exposed Directories Found',
      description: `No common sensitive directories or files were found exposed on ${baseHost}.`,
      impact: 'Good security posture - no obvious information disclosure via common paths.',
      remediation: 'Continue monitoring and periodically scan for new exposed paths.',
      current_value: 'No exposed paths detected',
      recommended_value: 'Maintain current access controls',
      confidence: 'medium'
    });
  }

  return findings;
}

async function checkPath(baseUrl, pathConfig, target) {
  const url = `${baseUrl}${pathConfig.path}`;

  try {
    const { statusCode, headers } = await fetchUrl(url, target);
    
    if (statusCode && statusCode >= 200 && statusCode < 400) {
      const severityInfo = SEVERITY_DESCRIPTIONS[pathConfig.severity] || SEVERITY_DESCRIPTIONS.medium;
      const contentLength = headers['content-length'] || 'unknown';
      
      return {
        category: 'directories',
        severity: pathConfig.severity,
        title: `Exposed ${pathConfig.category.toUpperCase()}: ${pathConfig.path}`,
        description: `Found accessible path: ${pathConfig.path} (HTTP ${statusCode}). This is a ${pathConfig.category} endpoint.`,
        impact: severityInfo.impact,
        remediation: severityInfo.remediation,
        current_value: `HTTP ${statusCode} - ${pathConfig.path} is publicly accessible`,
        recommended_value: `HTTP 403/404 - ${pathConfig.path} should not be publicly accessible`,
        cwe_id: pathConfig.severity === 'critical' ? 'CWE-538' : 'CWE-200',
        confidence: statusCode < 300 ? 'high' : 'medium',
        metadata: {
          url: url,
          status_code: statusCode,
          content_length: contentLength,
          category: pathConfig.category
        }
      };
    }
  } catch (err) {
    // Path not accessible, skip
  }
  
  return null;
}

function fetchUrl(urlStr, target) {
  return new Promise((resolve, reject) => {
    const isHttps = urlStr.startsWith('https');
    const client = isHttps ? https : http;

    const options = {
      timeout: 5000,
      headers: {
        'User-Agent': 'Vertex-Scan/1.0 (Security Scanner)',
        'Accept': '*/*'
      }
    };
    if (target && target.resolvedAddress) {
      applyPinnedTarget(options, target);
      urlStr = buildPinnedUrl(target, isHttps ? 'https:' : 'http:');
    }

    const req = client.get(urlStr, options, (res) => {
      res.resume();
      resolve({
        statusCode: res.statusCode,
        headers: res.headers
      });
    });
    
    req.on('error', (err) => {
      reject(err);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
  });
}

module.exports = { scanDirectories };