// Vertex Scan - Security Test Suite (dependency-free, run with: node --test)
// Exercises the live backend over HTTP and asserts key security controls.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const BASE = process.env.BASE_URL || 'http://localhost:3001';
const ADMIN_EMAIL = `sec_test_${Date.now()}@example.com`;
const ADMIN_PASS = 'Password123';

function request(method, path, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE + path);
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json;
        try { json = data ? JSON.parse(data) : null; } catch { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, body: json, raw: data });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function registerLogin() {
  await request('POST', '/api/v1/auth/register', { body: { email: ADMIN_EMAIL, password: ADMIN_PASS } });
  const res = await request('POST', '/api/v1/auth/login', { body: { email: ADMIN_EMAIL, password: ADMIN_PASS } });
  return res.body.token;
}

test('SSRF: private/loopback targets are rejected', async () => {
  const token = await registerLogin();
  const h = { Authorization: `Bearer ${token}` };
  for (const target of ['http://localhost:3001/api/health', 'http://169.254.169.254/latest/meta-data', 'http://192.168.1.1']) {
    const res = await request('POST', '/api/v1/scans', { body: { target_url: target }, headers: h });
    assert.strictEqual(res.status, 400, `expected 400 for ${target}, got ${res.status}`);
    assert.ok(res.body.error, 'should return an error message');
  }
});

test('SSRF: valid public target is accepted', async () => {
  const token = await registerLogin();
  const res = await request('POST', '/api/v1/scans', {
    body: { target_url: 'https://example.com' },
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.strictEqual(res.status, 201, `expected 201, got ${res.status}: ${JSON.stringify(res.body)}`);
});

test('Auth: protected route requires token', async () => {
  const res = await request('GET', '/api/v1/scans');
  assert.strictEqual(res.status, 401);
});

test('Auth: invalid token is rejected', async () => {
  const res = await request('GET', '/api/v1/scans', { headers: { Authorization: 'Bearer not.a.real.jwt' } });
  assert.strictEqual(res.status, 403);
});

test('Input validation: malformed email rejected', async () => {
  const res = await request('POST', '/api/v1/auth/register', { body: { email: 'not-an-email', password: 'Password123' } });
  assert.strictEqual(res.status, 400);
});

test('CORS: disallowed origin is blocked', async () => {
  const res = await request('GET', '/api/health', { headers: { Origin: 'http://evil.example.com' } });
  assert.strictEqual(res.status, 403);
});

test('CORS: allowed origin is permitted', async () => {
  const res = await request('GET', '/api/health', { headers: { Origin: 'http://localhost:5173' } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers['access-control-allow-origin'], 'http://localhost:5173');
});

test('Security headers are present', async () => {
  const res = await request('GET', '/api/health');
  assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
  assert.strictEqual(res.headers['x-frame-options'], 'DENY');
});

test('Content-Type enforcement: non-JSON POST rejected', async () => {
  const token = await registerLogin();
  const res = await request('POST', '/api/v1/scans', {
    body: 'target_url=http://example.com',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  assert.strictEqual(res.status, 415);
});

test('Unknown API route returns generic 404', async () => {
  const res = await request('GET', '/api/v1/does-not-exist');
  assert.strictEqual(res.status, 404);
  assert.ok(res.body.error);
});
