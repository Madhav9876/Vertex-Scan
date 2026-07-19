// Vertex Scan - Database Connection
const { Pool } = require('pg');
const { parse: parseConnectionString } = require('pg-connection-string');

const isProduction = process.env.NODE_ENV === 'production';

// Resolve the connection string. Prefer DATABASE_URL (e.g. Supabase),
// falling back to the SUPABASE_* variables commonly copied from the dashboard.
const connectionString =
  process.env.DATABASE_URL ||
  process.env.SUPABASE_DB_URL ||
  null;

// Managed Postgres providers such as Supabase require TLS. When a
// connection string is used we default SSL on (relaxed cert validation,
// which is what Supabase's poolers expect) unless explicitly disabled.
function resolveSsl() {
  if (process.env.DB_SSL === 'false') return false;

  if (connectionString) {
    // Supabase / hosted providers: TLS required. Allow a custom CA if provided,
    // otherwise skip strict validation (the connection is still encrypted).
    return process.env.DB_SSL_CA
      ? { rejectUnauthorized: true, ca: process.env.DB_SSL_CA }
      : { rejectUnauthorized: false };
  }

  // Legacy per-field config: enforce strict TLS in production only.
  return isProduction && process.env.DB_SSL !== 'false'
    ? { rejectUnauthorized: true, ca: process.env.DB_SSL_CA || undefined }
    : (process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false);
}

let poolConfig;
if (connectionString) {
  // Parse explicitly so the (URL-encoded) password is always passed to pg as a
  // decoded string — avoids SASL "client password must be a string" errors.
  const parsed = parseConnectionString(connectionString);
  poolConfig = {
    host: parsed.host,
    port: parsed.port ? Number(parsed.port) : 5432,
    database: parsed.database,
    user: parsed.user,
    password: parsed.password,
    max: Number(process.env.DB_POOL_MAX) || 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    ssl: resolveSsl(),
  };
} else {
  poolConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'vertex_scan',
    user: process.env.DB_USER || 'vertex_app',
    password: process.env.DB_PASSWORD,
    max: Number(process.env.DB_POOL_MAX) || 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    ssl: resolveSsl(),
  };
}

const pool = new Pool(poolConfig);

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  getClient: () => pool.connect(),
  pool,
};
