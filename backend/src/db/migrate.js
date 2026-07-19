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

async function migrate() {
  console.log('Running Vertex Scan database migration...');
  try {
    if (process.env.DB_CREATE_ROLE === 'true') {
      await ensureAppRole();
    }
    await query(SCHEMA_SQL);
    console.log('Migration completed successfully.');
  } catch (err) {
    console.error('Migration failed:', err.message);
  } finally {
    await pool.end();
  }
}

migrate();