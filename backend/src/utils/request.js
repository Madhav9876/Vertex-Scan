// Vertex Scan - Pinned HTTP Request Utility
// Properly handles SSRF-pinned connections while preserving the original Host header.
// Solves multi-tenant hosting issue where sites sharing an IP returned identical results.

const https = require('https');
const http = require('http');

/**
 * Create connection options for a pinned target.
 * Instead of embedding the IP in the URL (which causes Node.js to override the Host header),
 * we pass the path separately and set the host+headers explicitly.
 *
 * @param {Object} target - Pinned target from assertPublicTarget
 * @param {string} path - Request path (e.g. '/api/data')
 * @param {Object} extraOptions - Additional request options to merge
 * @returns {Object} Request options suitable for http.get() or https.get()
 */
function createPinnedOptions(target, path, extraOptions) {
  const isHttps = target.protocol === 'https:' || !target.normalized.startsWith('http:');
  const parsedNormalized = new URL(target.normalized);
  const defaultPort = isHttps ? 443 : 80;
  const port = target.port || parsedNormalized.port || defaultPort;
  const isDefaultPort = Number(port) === defaultPort;

  const options = {
    hostname: target.resolvedAddress,
    host: target.resolvedAddress,
    port: Number(port),
    path: path || parsedNormalized.pathname || '/',
    method: 'GET',
    rejectUnauthorized: false,
    servername: target.hostname,
    headers: {
      'Host': target.hostname + (isDefaultPort ? '' : `:${port}`),
      'User-Agent': 'Vertex-Scan/2.0 (Security Scanner)',
      'Accept': '*/*',
    }
  };

  // IPv6 requires special handling
  if (target.family === 6 || target.resolvedAddress.includes(':')) {
    options.family = 6;
  }

  // Merge any extra options (headers take precedence from extra)
  if (extraOptions) {
    if (extraOptions.headers) {
      Object.assign(options.headers, extraOptions.headers);
      delete extraOptions.headers;
    }
    Object.assign(options, extraOptions);
  }

  return options;
}

/**
 * Create a URL string that preserves the original hostname for logging/reporting
 * but uses the pinned IP for actual connection via http.get(options).
 * This function is for display/logging purposes only.
 */
function buildDisplayUrl(target, path) {
  const parsed = new URL(target.normalized);
  if (path) parsed.pathname = path;
  return parsed.toString();
}

/**
 * Perform a GET request against a pinned target, returning headers and body.
 * Properly sends the original Host header so multi-tenant IPs return correct content.
 */
function pinnedGet(target, path, extraOptions) {
  return new Promise((resolve, reject) => {
    const options = createPinnedOptions(target, path, extraOptions);
    const isHttps = options.port === 443 || target.protocol === 'https:' || 
                    (!target.normalized.startsWith('http:'));
    const client = isHttps ? https : http;

    const req = client.get(options, (res) => {
      let body = '';
      const maxSize = extraOptions && extraOptions.maxBodySize ? extraOptions.maxBodySize : 100000;
      let size = 0;

      res.on('data', (chunk) => {
        size += chunk.length;
        if (size <= maxSize) {
          body += chunk.toString('utf8');
        }
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          cookies: res.headers['set-cookie'] || []
        });
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    if (extraOptions && extraOptions.timeout) {
      req.setTimeout(extraOptions.timeout);
    }
  });
}

/**
 * Perform a HEAD-like request to check if a path exists (just status code + headers).
 */
function pinnedHead(target, path, extraOptions) {
  return new Promise((resolve, reject) => {
    const options = createPinnedOptions(target, path, extraOptions);
    options.method = 'GET'; // Some servers don't respond properly to HEAD

    const isHttps = options.port === 443 || (target.protocol !== 'http:');
    const client = isHttps ? https : http;

    const req = client.get(options, (res) => {
      // Consume response data to free memory
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
      reject(new Error('Request timed out'));
    });

    if (extraOptions && extraOptions.timeout) {
      req.setTimeout(extraOptions.timeout);
    }
  });
}

module.exports = { createPinnedOptions, buildDisplayUrl, pinnedGet, pinnedHead };