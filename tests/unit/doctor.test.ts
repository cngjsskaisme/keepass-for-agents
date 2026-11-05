// kp doctor diagnostics — output schema + per-check scenarios.
// Import order: tmp-home first (config.ts binds homedir()).
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDoctor, nodeVersionOk, type DoctorCheck, type SpawnProbe } from '../../src/cli/doctor.ts';
import { CONFIG_DIR, CONFIG_PATH, defaultConfig, normalize, saveConfig } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');

const byName = (checks: DoctorCheck[], n: string) => checks.find((c) => c.name === n)!;

/** spawn fake — routes the version/import probes runDoctor issues. */
function fakeSpawn(table: { version?: string | null; pykeepass?: boolean }): SpawnProbe {
  return (_cmd, args) => {
    const src = args.join(' ');
    if (src.includes('version_info')) {
      if (table.version == null) return { status: 1, stdout: '' };
      return { status: 0, stdout: table.version + '\n' };
    }
    if (src.includes('pykeepass')) {
      return table.pykeepass ? { status: 0, stdout: '4.2.0\n' } : { status: 1, stdout: '' };
    }
    return { status: 1, stdout: '' };
  };
}

test('nodeVersionOk — engines contract >=22.18 || >=23.6', () => {
  assert.equal(nodeVersionOk('v22.18.0'), true);
  assert.equal(nodeVersionOk('v22.17.9'), false);
  assert.equal(nodeVersionOk('v23.6.0'), true);
  assert.equal(nodeVersionOk('v23.5.0'), false);
  assert.equal(nodeVersionOk('v24.0.0'), true);
  assert.equal(nodeVersionOk('v25.1.0'), true);
  assert.equal(nodeVersionOk('garbage'), false);
});

test('doctor — report schema: success/checks/summary, fail drives success=false', async () => {
  // fresh TEST_HOME: no config.toml → config check must fail
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: null }) });
  assert.equal(typeof r.success, 'boolean');
  assert.equal(r.success, false); // missing config is a fail
  assert.ok(Array.isArray(r.checks) && r.checks.length >= 5);
  assert.equal(r.summary.total, r.checks.length);
  assert.equal(r.summary.ok + r.summary.warn + r.summary.fail, r.summary.total);
  assert.ok(r.checks.every((c) => ['ok', 'warn', 'fail'].includes(c.status)));
  // every fail/warn carries a remediation hint
  for (const c of r.checks.filter((c) => c.status !== 'ok'))
    assert.ok(c.hint || c.detail, `check ${c.name} has no hint/detail`);
});

test('doctor — missing config → config fail with init hint; node.version ok', async () => {
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: null }) });
  assert.equal(byName(r.checks, 'config').status, 'fail');
  assert.match(byName(r.checks, 'config').hint ?? '', /config init/);
  assert.equal(byName(r.checks, 'node.version').status, 'ok');
  assert.equal(byName(r.checks, 'hardened.mode').status, 'ok'); // not enabled → informational
});

test('doctor — valid config: config ok; empty agents → deny-by-default warn', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  const c = normalize({});              // no [agents.*] sections at all
  saveConfig(c);
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.12', pykeepass: true }) });
  assert.equal(byName(r.checks, 'config').status, 'ok');
  assert.equal(byName(r.checks, 'config.schema').status, 'ok');
  const ag = byName(r.checks, 'policy.agents');
  assert.equal(ag.status, 'warn');
  assert.match(ag.detail ?? '', /deny-by-default/);
  assert.equal(byName(r.checks, 'python.pykeepass').status, 'ok');
  assert.equal(byName(r.checks, 'kdbx.paths').status, 'ok');
});

test('doctor — default-seeded agents → policy.agents ok', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  saveConfig(defaultConfig());          // seeds agents.default allow-all
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.12', pykeepass: true }) });
  assert.equal(byName(r.checks, 'policy.agents').status, 'ok');
});

test('doctor — python probe outcomes map to platform severity', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  saveConfig(defaultConfig());
  const missing = await runDoctor({ spawnImpl: fakeSpawn({ version: null }) });
  const sev = process.platform === 'win32' ? 'warn' : 'fail';
  assert.equal(byName(missing.checks, 'python.pykeepass').status, sev);
  const oldPy = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.8' }) });
  assert.equal(byName(oldPy.checks, 'python.pykeepass').status, sev);
  const noPk = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.12', pykeepass: false }) });
  assert.equal(byName(noPk.checks, 'python.pykeepass').status, sev);
});

test('doctor — pre-versioned config (v0) → config.schema warn with migrate hint', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, '[keepass]\nexecutable = ""\nkpscript = ""\ndefault_database = ""\n\n[agents.default]\nallowed = ["*"]\n');
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.12', pykeepass: true }) });
  const s = byName(r.checks, 'config.schema');
  assert.equal(s.status, 'warn');
  assert.match(s.hint ?? '', /config migrate/);
});

test('doctor — config from a NEWER schema → warn (load continues best-effort)', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, 'schema_version = 99\n\n[keepass]\nexecutable = ""\nkpscript = ""\ndefault_database = ""\n\n[agents.default]\nallowed = ["*"]\n');
  const r = await runDoctor({ spawnImpl: fakeSpawn({ version: '3.12', pykeepass: true }) });
  const s = byName(r.checks, 'config.schema');
  assert.equal(s.status, 'warn');
  assert.match(s.detail ?? '', /v99/);
});

test('doctor — hardened enabled: isolation + service checks appear, stub probe down → fail', async () => {
  mkdirSync(CONFIG_DIR, { recursive: true });
  const c = defaultConfig();
  c.hardened.enabled = true;
  c.hardened.endpoint = process.platform === 'win32' ? 'kp-doctor-test' : join(TEST_HOME, 'svc.sock');
  c.hardened.token_file = join(TEST_HOME, 'ipc-token'); // absent → token_file_perms unmet
  saveConfig(c);
  const r = await runDoctor({
    spawnImpl: fakeSpawn({ version: '3.12', pykeepass: true }),
    probeServiceImpl: async () => ({ down: true, code: 'HARDENED_SERVICE_UNAVAILABLE' }),
  });
  assert.equal(byName(r.checks, 'hardened.isolation').status, 'fail');
  assert.match(byName(r.checks, 'hardened.isolation').detail ?? '', /token_file_perms/);
  const svc = byName(r.checks, 'hardened.service');
  assert.equal(svc.status, 'fail');
  assert.match(svc.detail ?? '', /HARDENED_SERVICE_UNAVAILABLE/);
  assert.equal(r.success, false);
});

test('kp doctor CLI — JSON on stdout, exit 1 when checks fail, works with no config', () => {
  const home = join(TEST_HOME, 'cli-home');
  mkdirSync(home, { recursive: true });
  const r = spawnSync(process.execPath, [KP, 'doctor'], {
    encoding: 'utf8',
    env: { ...process.env, HOME: home, USERPROFILE: home, KEEPASS_AGENT_CONFIG: join(home, 'nope.toml') },
  });
  assert.equal(r.status, 1);
  const j = JSON.parse(r.stdout.trim());
  assert.equal(j.success, false);
  assert.equal(j.code, 'DOCTOR_FAILED');
  assert.ok(Array.isArray(j.checks));
  assert.equal(byName(j.checks, 'config').status, 'fail');
});
