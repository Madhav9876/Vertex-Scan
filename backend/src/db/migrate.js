// Vertex Scan - Database Migration Script
require('dotenv').config();
const { query, pool } = require('./connection');
const { SCHEMA_SQL } = require('./schema');

// Create a dedicated least-privilege application role (no superuser).
// The app connects as this role; it can only DML/DDL on its own objects.
async function ensureAppRole() {
  const role = process.env.DB_APP_ROLE || 'vertex_app';
  await query(`DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${role}') THEN
      EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', '${role}', current_setting('app.db_password', true));
    END IF;
  END $$;`, []);
  await query(`GRANT USAGE ON SCHEMA public TO ${role};`);
  await query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${role};`);
  await query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${role};`);
  console.log(`Ensured least-privilege role: ${role}`);
}

// Idempotently bring the existing `public.users` table in line with SCHEMA_SQL.
// `CREATE TABLE IF NOT EXISTS` only creates when the table is absent, so a table
// that was created before new columns were added would otherwise drift and cause
// runtime errors like `column "auth_provider" does not exist`. We reconcile every
// column declared in the schema, adding only the ones that are missing.
const EXPECTED_USERS_COLUMNS = [
  `email VARCHAR(255) NOT NULL UNIQUE`,
  `password_hash VARCHAR(255)`,
  `full_name VARCHAR(100)`,
  `role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'api'))`,
  `api_key VARCHAR(64) UNIQUE`,
  `is_active BOOLEAN DEFAULT true`,
  `email_verified BOOLEAN DEFAULT false`,
  `token_version INTEGER DEFAULT 0`,
  `auth_provider VARCHAR(20) DEFAULT 'local' CHECK (auth_provider IN ('local', 'google'))`,
  `provider_id VARCHAR(255)`,
  `password_reset_token VARCHAR(255)`,
  `password_reset_expires_at TIMESTAMP`,
  `created_at TIMESTAMP DEFAULT NOW()`,
  `updated_at TIMESTAMP DEFAULT NOW()`,
  `last_login_at TIMESTAMP`,
];

async function syncUsersColumns() {
  const existing = await query(
    `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users'`
  );
  const have = new Set(existing.rows.map((r) => r.column_name));
  let added = 0;
  for (const def of EXPECTED_USERS_COLUMNS) {
    const name = def.split(' ')[0];
    if (have.has(name)) continue;
    await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${def};`);
    added++;
    console.log(`Added missing column users.${name}`);
  }
  console.log(added ? `Synced users table (${added} column(s) added).` : 'Users table already in sync.');
}

async function migrate() {
  console.log('Running Vertex Scan database migration...');
  try {
    if (process.env.DB_CREATE_ROLE === 'true') {
      await ensureAppRole();
    }
    await query(SCHEMA_SQL);
    await syncUsersColumns();
    console.log('Migration completed successfully.');
  } catch (err) {
    console.error('Migration failed:', err.message);
  } finally {
    await pool.end();
  }
}

migrate();