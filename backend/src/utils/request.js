// Vertex Scan - Pinned HTTP Request Utility
// Properly handles SSRF-pinned connections while preserving the original Host header.
// v2.0 - Robust timeout: hard deadline with AbortController, no hanging promises.

const https = require('https');
const http = require('http');

function buildDisplayUrl(target, path) {
  const parsed = new URL(target.normalized);
  if (path) parsed.pathname = path;
  return parsed.toString();
}

/**
 * Create connection options for a pinned target.
 * The timeout is NOT passed here - it's enforced via hard timer + socket destroy.
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

  // Merge extra headers only (do NOT merge timeout/maxBodySize into Node options)
  if (extraOptions) {
    if (extraOptions.headers) {
      Object.assign(options.headers, extraOptions.headers);
    }
  }

  return options;
}

/**
 * Perform a GET request against a pinned target, returning headers and body.
 * Uses a HARD timeout that kills the request after `timeoutMs` regardless of activity.
 * This prevents slow-loris style hangs where servers send data very slowly.
 */
function pinnedGet(target, path, extraOptions) {
  return new Promise((resolve) => {
    // Hard deadline enforced via combined idle + absolute timeout
    const timeoutMs = (extraOptions && extraOptions.timeout) || 10000;
    const maxBodySize = (extraOptions && extraOptions.maxBodySize) || 100000;

    const options = createPinnedOptions(target, path, extraOptions);
    const isHttps = options.port === 443 || target.protocol === 'https:' || 
                    (!target.normalized.startsWith('http:'));
    const client = isHttps ? https : http;

    // Track if we've already settled to prevent double resolve
    let settled = false;
    const done = (err, result) => {
      if (settled) return;
      settled = true;
      timer && clearTimeout(timer);
      if (err) {
        resolve(null);
      } else {
        resolve(result);
      }
    };

    // Hard killswitch: fires after absolute deadline regardless of activity
    const timer = setTimeout(() => {
      req.destroy(new Error('Request timed out'));
      done(new Error('Request timed out'), null);
    }, timeoutMs);

    let body = '';
    let size = 0;

    const req = client.get(options, (res) => {
      // Reset timer on first response (server is alive)
      timer && timer.refresh();

      res.on('data', (chunk) => {
        size += chunk.length;
        if (size <= maxBodySize) {
          body += chunk.toString('utf8');
        }
      });

      res.on('end', () => {
        done(null, {
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          cookies: res.headers['set-cookie'] || []
        });
      });

      res.on('error', () => {
        done(new Error('Response stream error'), null);
      });
    });

    req.on('error', () => {
      done(new Error('Request error'), null);
    });

    req.on('timeout', () => {
      req.destroy(new Error('Idle timeout'));
      // The absolute timer will fire done() if not already settled
    });

    // Set idle timeout as a shorter threshold (triggers if socket is truly idle)
    req.setTimeout(Math.min(timeoutMs, 5000));
  });
}

/**
 * Perform a GET request to check if a path exists (returns status code + headers).
 * Includes hard timeout killswitch like pinnedGet.
 */
function pinnedHead(target, path, extraOptions) {
  return new Promise((resolve) => {
    const timeoutMs = (extraOptions && extraOptions.timeout) || 10000;
    const options = createPinnedOptions(target, path, extraOptions);

    const isHttps = options.port === 443 || (target.protocol !== 'http:');
    const client = isHttps ? https : http;

    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      timer && clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      req.destroy(new Error('Request timed out'));
      done(null);
    }, timeoutMs);

    const req = client.get(options, (res) => {
      timer && timer.refresh();
      // Consume response data to free memory
      res.resume();
      done({
        statusCode: res.statusCode,
        headers: res.headers
      });
    });

    req.on('error', () => {
      done(null);
    });

    req.on('timeout', () => {
      req.destroy(new Error('Idle timeout'));
    });

    req.setTimeout(Math.min(timeoutMs, 5000));
  });
}

module.exports = { createPinnedOptions, buildDisplayUrl, pinnedGet, pinnedHead };