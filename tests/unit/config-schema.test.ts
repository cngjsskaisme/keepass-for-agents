// config.toml schema_version — migration skeleton + save/load round-trip.
// Import order: tmp-home first.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONFIG_DIR, CONFIG_PATH, CONFIG_SCHEMA_VERSION, SCHEMA_MIGRATIONS,
  defaultConfig, loadConfig, migrateSchema, parseToml, readSchemaVersion,
  saveConfig, schemaVersionOf,
} from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');

test('schemaVersionOf — absent key is v0 (pre-versioned); integers pass through', () => {
  assert.equal(schemaVersionOf({}), 0);
  assert.equal(schemaVersionOf({ schema_version: 1 }), 1);
  assert.equal(schemaVersionOf({ schema_version: 'nope' }), 0);
  assert.equal(schemaVersionOf({ schema_version: -1 }), 0);
});

test('migrateSchema — v0 runs the v1 baseline step; registry has no gaps to current', () => {
  const r = migrateSchema(parseToml('[keepass]\nexecutable = "x"\n'));
  assert.equal(r.from, 0);
  assert.equal(r.to, CONFIG_SCHEMA_VERSION);
  assert.equal(r.applied.length, 1);
  assert.match(r.applied[0], /v0→v1/);
  assert.equal(r.raw.keepass.executable, 'x');
  // every step 1..CONFIG_SCHEMA_VERSION must be registered (no holes)
  for (let v = 1; v <= CONFIG_SCHEMA_VERSION; v++)
    assert.ok(SCHEMA_MIGRATIONS[v], `missing migration step v${v - 1}→v${v}`);
});

test('migrateSchema — newer version passes through untouched with fromNewer', () => {
  const r = migrateSchema({ schema_version: CONFIG_SCHEMA_VERSION + 5, keepass: {} });
  assert.equal(r.fromNewer, true);
  assert.equal(r.applied.length, 0);
  assert.equal(r.to, CONFIG_SCHEMA_VERSION + 5);
});

test('saveConfig stamps schema_version; loadConfig round-trips it', () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  saveConfig(defaultConfig());
  const text = readFileSync(CONFIG_PATH, 'utf8');
  assert.match(text, /^schema_version = 1$/m);
  const c = loadConfig();
  assert.equal(c.schema_version, CONFIG_SCHEMA_VERSION);
  assert.equal(c.migrations_applied, undefined); // already current — nothing applied
  assert.equal(readSchemaVersion(), 1);
});

test('loadConfig — pre-versioned file upgrades in memory; disk untouched until save', () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, '[keepass]\nexecutable = "C:/KeePass.exe"\nkpscript = ""\ndefault_database = ""\n\n[agents.default]\nallowed = ["*"]\n');
  assert.equal(readSchemaVersion(), 0);
  const c = loadConfig();
  assert.equal(c.schema_version, CONFIG_SCHEMA_VERSION);
  assert.deepEqual(c.migrations_applied?.length, 1);
  assert.equal(readSchemaVersion(), 0, 'load must not persist the migration');
  // an explicit migrate/save stamps it
  saveConfig(c);
  assert.equal(readSchemaVersion(), 1);
  const c2 = loadConfig();
  assert.equal(c2.migrations_applied, undefined);
});

test('kp config migrate — persists a pending upgrade, then is a no-op', () => {
  const home = join(TEST_HOME, 'mig-home');
  const dir = join(home, '.config', 'keepass-agent');
  mkdirSync(dir, { recursive: true });
  const cfgPath = join(dir, 'config.toml');
  writeFileSync(cfgPath, '[keepass]\nexecutable = ""\nkpscript = ""\ndefault_database = ""\n\n[agents.default]\nallowed = ["*"]\n');
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  const r1 = spawnSync(process.execPath, [KP, 'config', 'migrate'], { encoding: 'utf8', env });
  assert.equal(r1.status, 0, r1.stderr);
  const j1 = JSON.parse(r1.stdout.trim());
  assert.equal(j1.migrated, true);
  assert.equal(j1.schema_version, 1);
  assert.equal(j1.applied.length, 1);
  assert.match(readFileSync(cfgPath, 'utf8'), /^schema_version = 1$/m);
  const r2 = spawnSync(process.execPath, [KP, 'config', 'migrate'], { encoding: 'utf8', env });
  const j2 = JSON.parse(r2.stdout.trim());
  assert.equal(j2.migrated, false);
});

test('kp config migrate — invalid config fails with INVALID_CONFIG, no save', () => {
  const home = join(TEST_HOME, 'mig-bad');
  const dir = join(home, '.config', 'keepass-agent');
  mkdirSync(dir, { recursive: true });
  const cfgPath = join(dir, 'config.toml');
  // invalid: non-absolute kdbx path → validateConfig must reject before save
  writeFileSync(cfgPath, '[keepass]\nexecutable = ""\nkpscript = ""\ndefault_database = ""\n\n[databases.x]\npath = "rel/x.kdbx"\n\n[agents.default]\nallowed = ["*"]\n');
  const before = readFileSync(cfgPath, 'utf8');
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  const r = spawnSync(process.execPath, [KP, 'config', 'migrate'], { encoding: 'utf8', env });
  assert.equal(r.status, 1);
  const j = JSON.parse(r.stdout.trim());
  assert.equal(j.code, 'INVALID_CONFIG');
  assert.ok(Array.isArray(j.errors) && j.errors.length > 0);
  assert.equal(readFileSync(cfgPath, 'utf8'), before, 'invalid config must not be saved');
});

test('kp config migrate — missing config fails with CONFIG_NOT_FOUND (not INTERNAL_ERROR)', () => {
  const home = join(TEST_HOME, 'mig-none');
  mkdirSync(join(home, '.config', 'keepass-agent'), { recursive: true });
  const env = { ...process.env, HOME: home, USERPROFILE: home, KEEPASS_AGENT_CONFIG: join(home, 'absent.toml') };
  const r = spawnSync(process.execPath, [KP, 'config', 'migrate'], { encoding: 'utf8', env });
  assert.equal(r.status, 1);
  const j = JSON.parse(r.stdout.trim());
  assert.equal(j.code, 'CONFIG_NOT_FOUND');
});
