// Policy enforcement integration tests — run the real CLI as a subprocess
// against TEST_HOME config. Covers deny-by-default, allow matching, named
// agents via --agent / KEEPASS_AGENT_ID, require_approval routing, the
// POLICY_DENIED / POLICY_APPROVAL_REQUIRED paths, config.set policy keys, and
// audit-log emission (schema + secret absence).
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalize, saveConfig, SESSION_DIR, CONFIG_DIR, type AppConfig } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');
const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');
const DB_PATH = join(TEST_HOME, 'pol.kdbx');

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);
writeFileSync(DB_PATH, Buffer.alloc(64, 7)); // getDb only needs the file to exist

interface KpRun { status: number | null; stdout: string; stderr: string; json: any; }

function kp(args: string[], env: Record<string, string | undefined> = {}): KpRun {
  const e: Record<string, string> = { ...process.env, USERPROFILE: TEST_HOME, HOME: TEST_HOME } as any;
  delete e.KEEPASS_AGENT_ID;
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete e[k]; else e[k] = v; }
  const r = spawnSync(process.execPath, [KP, ...args], { env: e, encoding: 'utf8', timeout: 30_000 });
  let json: any = null;
  try { json = JSON.parse(r.stdout.trim().split('\n').pop() || ''); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

function setCfg(mutate: (c: AppConfig) => void): void {
  const c = normalize({});
  c.databases = { testdb: { path: DB_PATH } };
  c.keepass.default_database = 'testdb';
  mutate(c);
  saveConfig(c);
}

function auditEvents(): any[] {
  if (!existsSync(AUDIT_LOG)) return [];
  return readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}
const clearAudit = () => { try { unlinkSync(AUDIT_LOG); } catch {} };

test('deny-by-default — no [agents.*] sections deny every gated command', () => {
  setCfg(() => {});
  for (const args of [['db', 'list'], ['search', '--db', 'testdb'], ['login', '--db', 'testdb'], ['unlock', '--db', 'testdb'], ['audit']]) {
    const r = kp(args);
    assert.equal(r.json?.code, 'POLICY_DENIED', args.join(' '));
    assert.match(String(r.json?.detail), /deny-by-default|not allowed/);
  }
  // Bootstrap hint: a policy-less (legacy) install must be told how to grant.
  const r = kp(['db', 'list']);
  assert.match(String(r.json?.detail), /config set agents\.default\.allowed/);
});

test('allow matching — listed action runs through to the normal flow', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['search', 'db.list', 'audit.read'] } }; });
  const l = kp(['db', 'list']);
  assert.equal(l.json?.success, true, l.stdout + l.stderr);
  // 'search' is allowed → passes the gate, then hits the locked session.
  const s = kp(['search', '--db', 'testdb', '--site', 'x']);
  assert.equal(s.json?.code, 'UNLOCK_REQUIRED', s.stdout);
  // 'login' still not listed → denied.
  assert.equal(kp(['login', '--db', 'testdb', '--title', 'x']).json?.code, 'POLICY_DENIED');
});

test('named agents — --agent and KEEPASS_AGENT_ID select distinct policies', () => {
  setCfg((c) => {
    c.agents = {
      reader: { allowed: ['db.list'] },
      nobody: { allowed: ['audit.read'] },
    };
  });
  // No agents.default → unidentified callers get nothing.
  assert.equal(kp(['db', 'list']).json?.code, 'POLICY_DENIED');
  // --agent flag selects the named policy.
  assert.equal(kp(['db', 'list', '--agent', 'reader']).json?.success, true);
  assert.equal(kp(['db', 'list', '--agent', 'nobody']).json?.code, 'POLICY_DENIED');
  // Env identity works too; flag beats env.
  assert.equal(kp(['db', 'list'], { KEEPASS_AGENT_ID: 'reader' }).json?.success, true);
  assert.equal(kp(['db', 'list', '--agent', 'nobody'], { KEEPASS_AGENT_ID: 'reader' }).json?.code, 'POLICY_DENIED');
});

test('invalid agent identity fails closed (INVALID_AGENT_ID)', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['*'] } }; });
  const r = kp(['db', 'list'], { KEEPASS_AGENT_ID: 'bad agent!' });
  assert.equal(r.json?.code, 'INVALID_AGENT_ID');
});

test('require_approval — non-approvable action fails POLICY_APPROVAL_REQUIRED', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['db.list'], require_approval: ['login'] } }; });
  const r = kp(['login', '--db', 'testdb', '--title', 'x']);
  assert.equal(r.json?.code, 'POLICY_APPROVAL_REQUIRED');
});

test('config set — agents.* and policy.* keys write policy and emit audit', () => {
  setCfg(() => {});
  const r = kp(['config', 'set', 'agents.default.allowed', 'db.list,audit.read']);
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(kp(['db', 'list']).json?.success, true);
  // config.set must be audit-logged even though it is not policy-gated.
  const evs = auditEvents();
  assert.ok(evs.some((e) => e.action === 'config.set' && e.target === 'agents.default.allowed'), JSON.stringify(evs));
});

test('config set — failed policy writes are audited; reserved names rejected', () => {
  setCfg(() => {});
  clearAudit();
  // Invalid int for policy.audit_max_bytes → INVALID_CONFIG, but still audited.
  const r1 = kp(['config', 'set', 'policy.audit_max_bytes', 'notanint']);
  assert.equal(r1.json?.code, 'INVALID_CONFIG');
  // Reserved prototype-polluting agent names must be rejected outright.
  const r2 = kp(['config', 'set', 'agents.__proto__.allowed', '*']);
  assert.equal(r2.json?.code, 'INVALID_CONFIG');
  const r3 = kp(['config', 'set', 'agents.constructor.allowed', '*']);
  assert.equal(r3.json?.code, 'INVALID_CONFIG');
  // Unknown field on agents.* → INVALID_CONFIG, also audited.
  const r4 = kp(['config', 'set', 'agents.default.bogus', 'x']);
  assert.equal(r4.json?.code, 'INVALID_CONFIG');
  const evs = auditEvents();
  const sets = evs.filter((e) => e.action === 'config.set');
  assert.ok(sets.length >= 4, JSON.stringify(sets));
  assert.ok(sets.every((e) => e.result_code === 'INVALID_CONFIG'), JSON.stringify(sets));
  assert.ok(sets.some((e) => e.target === 'agents.__proto__.allowed'));
  assert.ok(sets.some((e) => e.target === 'policy.audit_max_bytes'));
  // And nothing leaked into Object.prototype or the saved config.
  assert.equal(({} as any).allowed, undefined);
});

test('audit log — schema fields + decision/result codes; no secret material', () => {
  clearAudit();
  setCfg((c) => { c.agents = { default: { allowed: ['db.list'] } }; });
  kp(['db', 'list']);                                   // allow → OK
  kp(['login', '--db', 'testdb', '--title', 'x']);      // deny
  kp(['search', '--db', 'testdb', '--title', 's3cr3t-hunter'], { KEEPASS_AGENT_ID: 'reader' }); // deny — carries a secret-ish query
  const evs = auditEvents();
  assert.equal(evs.length, 3, JSON.stringify(evs));
  for (const e of evs) {
    assert.ok(e.ts && e.agent && e.action && e.result_code, JSON.stringify(e));
    assert.ok(typeof e.decision === 'string');
  }
  assert.deepEqual(evs.map((e) => e.result_code), ['OK', 'POLICY_DENIED', 'POLICY_DENIED']);
  assert.equal(evs[2].agent, 'reader');
  const raw = readFileSync(AUDIT_LOG, 'utf8');
  // The denied query never becomes an audit field — no search target was set.
  assert.ok(!raw.includes('s3cr3t-hunter'), 'query/secret material must not reach audit.log');
});

test('policy-gated audit.read — allowed agents can read the log', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['db.list'] }, watcher: { allowed: ['audit.read'] } }; });
  kp(['db', 'list']);
  assert.equal(kp(['audit']).json?.code, 'POLICY_DENIED');
  const r = kp(['audit', '--agent', 'watcher']);
  assert.equal(r.json?.success, true, r.stdout);
  assert.ok(Array.isArray(r.json.events));
  assert.ok(r.json.events.some((e: any) => e.action === 'db.list'));
});
