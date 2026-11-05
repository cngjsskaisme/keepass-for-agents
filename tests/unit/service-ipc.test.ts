// Credential Service IPC integration (in-process) — real socket/named-pipe
// server + real client handshake. Proves: authenticated requests are served,
// wrong tokens are rejected at the boundary, a down service is an explicit
// error, service-side policy re-gates, and the login op's response carries
// no secret material. Import order: tmp-home first.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { startServiceServer, type ServiceServer } from '../../src/service/server.ts';
import { callService } from '../../src/service/client.ts';
import { newToken, writeTokenFile, hmacToken } from '../../src/service/auth.ts';
import { makeSubmissionGate } from '../../src/service/handlers.ts';
import { normalize, saveConfig, SESSION_DIR, type AppConfig } from '../../src/config/config.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { AUDIT_MAX_BYTES_DEFAULT } from '../../src/policy/audit.ts';
import { MAX_MSG_BYTES } from '../../src/service/protocol.ts';
import type { UnlockRequest } from '../../src/unlock-server/server.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

// KPScript mock (Windows provider path) — same stdin-key protocol as
// pipeline.test.ts. POSIX uses the mock PyKeePass helper instead.
const MOCK_KPS = join(TEST_HOME, 'mock-kpscript-svc.mjs');
writeFileSync(MOCK_KPS, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
if(args.includes('-c:ListEntries')){process.stdout.write('UUID-1\\tGitHub Work\\tu@x.com\\thttps://github.com/login\\n')}
else if(args.includes('-c:GetEntryString')){process.stdout.write(args.includes('-Field:Password')?'s3cr3t\\n':'')}
process.exit(0)})`);

if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

const ENDPOINT = process.platform === 'win32'
  ? `\\\\.\\pipe\\kp-svc-test-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
  : join(TEST_HOME, 'svc-test.sock');
const TOKEN_FILE = join(TEST_HOME, 'ipc-token');
const TOKEN = newToken();

const ALIAS = 'svcdb';
const DB_PATH = join(TEST_HOME, 'svc.kdbx');

function testCfg(agents: AppConfig['agents']): AppConfig {
  const c = normalize({});
  c.databases = { [ALIAS]: { path: DB_PATH } };
  c.keepass.default_database = ALIAS;
  c.agents = agents;
  c.hardened.enabled = true;
  c.hardened.token_file = TOKEN_FILE;
  if (process.platform === 'win32') c.hardened.endpoint = ENDPOINT.replace('\\\\.\\pipe\\', '');
  else c.hardened.endpoint = ENDPOINT;
  return c;
}

let svc: ServiceServer;
let cfg: AppConfig;

before(async () => {
  writeFileSync(DB_PATH, Buffer.alloc(64, 3));
  cfg = testCfg({ default: { allowed: ['*'] } });
  saveConfig(cfg); // handleRequest reloads config per request
  writeTokenFile(TOKEN_FILE, TOKEN);
  svc = await startServiceServer({
    endpoint: ENDPOINT,
    token: TOKEN,
    cfg,
    ctx: {
      kpscript: process.platform === 'win32' ? [process.execPath, MOCK_KPS] : '',
      auditMaxBytes: AUDIT_MAX_BYTES_DEFAULT,
    },
  });
});

after(async () => {
  clearSession(ALIAS);
  await svc?.close();
});

test('ipc — hello over authenticated handshake returns minimised identity', async () => {
  const r = await callService(cfg, 'hello', { agent: 'tester' });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.service, 'kp-credential-service');
  // pid/uptime are deliberately not disclosed to token-holding callers.
  assert.equal(r.pid, undefined);
  assert.equal(r.uptime_s, undefined);
});

test('ipc — wrong capability token is denied (HARDENED_AUTH_FAILED)', async () => {
  const badTokenFile = join(TEST_HOME, 'bad-token');
  writeTokenFile(badTokenFile, newToken());
  const bad = { ...cfg, hardened: { ...cfg.hardened, token_file: badTokenFile } };
  const r = await callService(bad, 'hello', { agent: 'tester' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'HARDENED_AUTH_FAILED');
});

test('ipc — unreadable/missing token file fails before connecting', async () => {
  const bad = { ...cfg, hardened: { ...cfg.hardened, token_file: join(TEST_HOME, 'nope') } };
  const r = await callService(bad, 'hello', {});
  assert.equal(r.ok, false);
  assert.equal(r.code, 'HARDENED_TOKEN_UNAVAILABLE');
});

test('ipc — dead endpoint is an explicit SERVICE_UNAVAILABLE, never a hang', async () => {
  const dead = {
    ...cfg,
    hardened: {
      ...cfg.hardened,
      endpoint: process.platform === 'win32' ? `kp-svc-dead-${process.pid}` : join(TEST_HOME, 'dead.sock'),
    },
  };
  const r = await callService(dead, 'hello', {});
  assert.equal(r.ok, false);
  assert.equal(r.code, 'HARDENED_SERVICE_UNAVAILABLE');
});

test('ipc — service-side policy denies an agent with no grants', async () => {
  // The service reloads config per request — temporarily scope the policy so
  // 'status' is unlisted, then restore.
  const denied = testCfg({ reader: { allowed: ['db.list'] } });
  saveConfig(denied);
  try {
    const r = await callService(cfg, 'status', { agent: 'intruder' });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'POLICY_DENIED');
  } finally {
    saveConfig(cfg);
  }
});

test('ipc — malformed/unknown ops are rejected, not dispatched', async () => {
  const r = await callService(cfg, 'getSecret', { db: ALIAS });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'HARDENED_IPC_ERROR');
});

test('ipc — list returns policy-filtered entry metadata, never secrets', async () => {
  await saveSession(ALIAS, 'rightkey', 300);
  const r = await callService(cfg, 'list', { db: ALIAS, agent: 'tester' });
  assert.equal(r.ok, true, JSON.stringify(r));
  const e = (r.entries ?? [])[0];
  assert.equal(e.id, 'UUID-1');
  assert.equal(e.title, 'GitHub Work');
  assert.ok(!JSON.stringify(r).includes('s3cr3t'));
});

test('ipc — login pipes the secret to a service-spawned worker; response has no secret', async () => {
  // Register the mock worker for this test by monkey-patching the registry?
  // No — the registry is an allowlist. Use 'local-test' semantics instead:
  // point the entry URL at a local login endpoint is heavier; instead we
  // assert the response shape and secret absence via the allowlisted worker.
  // The worker-level secret delivery is covered end-to-end in
  // tests/integration/hardened.test.ts.
  const r = await callService(cfg, 'login', { db: ALIAS, entry: 'UUID-1', worker: 'local-test', agent: 'tester' });
  // local-test worker will try to fetch github.com — outcome varies by
  // network; the assertion that matters is response hygiene.
  assert.ok(!JSON.stringify(r).includes('s3cr3t'), 'secret must never cross IPC');
  assert.ok(r.ok === true || typeof r.code === 'string');
});

test('ipc — lock clears the service-held session', async () => {
  await saveSession(ALIAS, 'rightkey', 300);
  const r = await callService(cfg, 'lock', { db: ALIAS, agent: 'tester' });
  assert.equal(r.ok, true);
  const st = await callService(cfg, 'status', { db: ALIAS, agent: 'tester' });
  assert.equal(st.states?.[ALIAS], 'LOCKED');
});

test('ipc — audit op returns the service-side gated-op records', async () => {
  const r = await callService(cfg, 'audit', { agent: 'tester', limit: 50 });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.ok(Array.isArray(r.events));
  assert.ok(r.events.length >= 1, JSON.stringify(r.events));
  assert.ok(r.events.some((e: any) => e.agent === 'tester'));
});

test('ipc — oversized message kills the connection pre-auth (F4)', async () => {
  // Raw socket: read the challenge, then blast >1MiB without newline — the
  // server must close the connection rather than buffer it.
  const socket = connect(ENDPOINT);
  const closed = await new Promise<boolean>((resolve) => {
    socket.setTimeout(10_000, () => { socket.destroy(); resolve(false); });
    let gotChallenge = false;
    socket.on('data', (d) => {
      if (gotChallenge) return;
      gotChallenge = true;
      try { socket.write('x'.repeat(MAX_MSG_BYTES + 16)); } catch { resolve(false); }
    });
    socket.on('close', () => resolve(true));
    socket.on('error', () => resolve(true)); // ECONNRESET is a valid kill too
  });
  assert.equal(closed, true, 'oversized unterminated message must close the connection');
});

test('ipc — approval entry-add denied service-side by host policy (F1)', async () => {
  // Service reloads config per request — scope allowed_hosts so the prefill
  // URL is outside the agent's remit, then restore.
  const restricted = testCfg({ default: { allowed: ['entry.add'], allowed_hosts: ['good.com'] } });
  saveConfig(restricted);
  try {
    const r = await callService(cfg, 'approval', {
      mode: 'entry', db: ALIAS, agent: 'tester',
      prefill: { title: 'T', url: 'https://evil.com/login' },
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'POLICY_DENIED', JSON.stringify(r));
  } finally {
    saveConfig(cfg);
  }
});

test('ipc — approval openUrl scheme is validated (F6)', async () => {
  const r = await callService(cfg, 'approval', {
    mode: 'cookies', db: ALIAS, agent: 'tester',
    entryUuid: 'UUID-1', domain: 'github.com', cdpEndpoint: 'http://127.0.0.1:9222',
    openUrl: 'file:///etc/passwd', capture: true,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_CONFIG', JSON.stringify(r));
});

test('submission gate — evaluate() runs on submitted values, drift denied (F1)', () => {
  const ctx = {
    cfg: testCfg({ default: { allowed: ['entry.add', 'entry.sync-cookies', 'unlock'], allowed_hosts: ['good.com'] } }),
    kpscript: '',
    auditMaxBytes: AUDIT_MAX_BYTES_DEFAULT,
  };
  const req = { mode: 'entry', db: ALIAS, prefill: { title: 'T', url: 'https://good.com/' } } as UnlockRequest;
  const gate = makeSubmissionGate(ctx, 'tester', 'entry.add', req);
  // Submitted url outside allowed_hosts → denied even though action is allowed.
  const bad = gate({ mode: 'entry', db: ALIAS, entry: { title: 'T', url: 'https://evil.com/' }, fields: { title: 'T', url: 'https://evil.com/' } });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'POLICY_DENIED');
  // Submitted url differing from the approved prefill → drift denied.
  const drift = gate({ mode: 'entry', db: ALIAS, entry: { title: 'T', url: 'https://good.com/x' }, fields: { title: 'T', url: 'https://good.com/x' } });
  assert.equal(drift.ok, true, 'same host as prefill should pass');
  const titleDrift = gate({ mode: 'entry', db: ALIAS, entry: { title: 'T2' }, fields: { title: 'T2', url: 'https://good.com/' } });
  assert.equal(titleDrift.ok, false, 'title drift from prefill must deny');
  // Entry db drift (submitted a different alias than approved).
  const dbDrift = gate({ mode: 'entry', db: 'other', entry: { title: 'T', url: 'https://good.com/' }, fields: { title: 'T', url: 'https://good.com/' } });
  assert.equal(dbDrift.ok, false, 'entry db drift must deny');
  // Cookies: uuid/domain drift from the approved request denied.
  const creq = { mode: 'cookies', db: ALIAS, entryUuid: 'UUID-1', domain: 'good.com' } as UnlockRequest;
  const cgate = makeSubmissionGate(ctx, 'tester', 'entry.sync-cookies', creq);
  assert.equal(cgate({ mode: 'cookies', db: ALIAS, entry: { id: 'UUID-1' }, host: 'good.com' }).ok, true);
  assert.equal(cgate({ mode: 'cookies', db: ALIAS, entry: { id: 'UUID-9' }, host: 'good.com' }).ok, false);
  // Unlock: db drift denied.
  const ureq = { mode: 'unlock', db: ALIAS } as UnlockRequest;
  const ugate = makeSubmissionGate(ctx, 'tester', 'unlock', ureq);
  assert.equal(ugate({ mode: 'unlock', db: 'other' }).ok, false);
  // Create: declared alias/path pinned for create-mode requests.
  const mkreq = { mode: 'create', db: 'newdb', targetPath: 'C:/vaults/a.kdbx' } as UnlockRequest;
  const mkg = makeSubmissionGate(
    { ...ctx, cfg: testCfg({ default: { allowed: ['db.create'] } }) },
    'tester', 'entry.sync-cookies', mkreq);
  assert.equal(mkg({ mode: 'create', db: 'newdb', path: 'C:/vaults/a.kdbx' }).ok, true);
  assert.equal(mkg({ mode: 'create', db: 'newdb', path: 'C:/other/b.kdbx' }).ok, false, 'create path drift must deny');
  assert.equal(mkg({ mode: 'create', db: 'otherdb', path: 'C:/vaults/a.kdbx' }).ok, false, 'create alias drift must deny');
});

test('submission gate — cross-action create requires a strict allow (G3)', () => {
  // unlock-mode request submitting action=create is a DIFFERENT action than
  // what was approved — require_approval on db.create must NOT be satisfied
  // by the unlock approval channel.
  const ctx = {
    cfg: testCfg({ default: { allowed: ['unlock'], require_approval: ['db.create'] } }),
    kpscript: '',
    auditMaxBytes: AUDIT_MAX_BYTES_DEFAULT,
  };
  const ureq = { mode: 'unlock', db: ALIAS } as UnlockRequest;
  const g = makeSubmissionGate(ctx, 'tester', 'unlock', ureq);
  const r = g({ mode: 'create', db: 'x', path: 'C:/x.kdbx' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'POLICY_DENIED');
  // But with an outright allow, a cross-action create is legitimate
  // (pageCreate is a first-class section of the unlock page).
  const ctx2 = {
    cfg: testCfg({ default: { allowed: ['unlock', 'db.create'] } }),
    kpscript: '',
    auditMaxBytes: AUDIT_MAX_BYTES_DEFAULT,
  };
  assert.equal(makeSubmissionGate(ctx2, 'tester', 'unlock', ureq)({ mode: 'create', db: 'x', path: 'C:/x.kdbx' }).ok, true);
});
