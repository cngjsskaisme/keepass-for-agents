// MCP Adapter tool tests — callTool handlers end-to-end (Standard mode via
// mock backend; Hardened mode via an in-process Credential Service). Asserts:
// per-tool response schemas are secret-free (no password/secret/cookie
// fields), policy deny + require_approval paths, one audit record per call
// (action `mcp.<tool>`), and hardened IPC routing. Import order: tmp-home
// first.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { normalize, saveConfig, SESSION_DIR, CONFIG_DIR, type AppConfig } from '../../src/config/config.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { callTool, type McpSession } from '../../src/mcp/tools.ts';
import { startServiceServer, type ServiceServer } from '../../src/service/server.ts';
import { newToken, writeTokenFile } from '../../src/service/auth.ts';
import { AUDIT_MAX_BYTES_DEFAULT } from '../../src/policy/audit.ts';

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const DB_PATH = join(TEST_HOME, 'mcp-tools.kdbx');
writeFileSync(DB_PATH, Buffer.alloc(64, 11));
const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');

// Mock backend (win32 → KPScript argv hook; POSIX → helper env hook). The
// entry URL is env-parameterized so request_login can hit a real loopback
// login endpoint — same convention as tests/integration/hardened.test.ts.
const MOCK_KPS = join(TEST_HOME, 'mock-kpscript-mcp.mjs');
writeFileSync(MOCK_KPS, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
if(args.includes('-c:ListEntries')){process.stdout.write('UUID-1\\tGitHub Work\\tu@x.com\\t'+(process.env.MOCK_ENTRY_URL||'https://github.com/login')+'\\n')}
else if(args.includes('-c:GetEntryString')){process.stdout.write(args.includes('-Field:Password')?'s3cr3t\\n':'')}
process.exit(0)})`);

if (process.platform !== 'win32') {
  const MOCK_HELPER = join(TEST_HOME, 'mock-helper-mcp.mjs');
  writeFileSync(MOCK_HELPER, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
let j={};try{j=JSON.parse(d)}catch{}
if(j.master!=='rightkey'){process.stdout.write(JSON.stringify({ok:false,code:'INVALID_MASTER_KEY'}));process.exit(1)}
if(j.cmd==='verify')process.stdout.write(JSON.stringify({ok:true}));
else if(j.cmd==='list')process.stdout.write(JSON.stringify({ok:true,entries:[{id:'UUID-1',title:'GitHub Work',username:'u@x.com',url:process.env.MOCK_ENTRY_URL||'https://github.com/login'}]}));
else if(j.cmd==='get')process.stdout.write(JSON.stringify({ok:true,secret:'s3cr3t'}));
else process.stdout.write(JSON.stringify({ok:false,code:'UNKNOWN_CMD'}))})`);
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([process.execPath, MOCK_HELPER]);
}

const KPS: string | string[] = process.platform === 'win32' ? [process.execPath, MOCK_KPS] : '';

function setCfg(mutate: (c: AppConfig) => void = () => {}): void {
  const c = normalize({});
  c.databases = { testdb: { path: DB_PATH } };
  c.keepass.default_database = 'testdb';
  c.agents = { default: { allowed: ['*'] } };
  c.unlock.auto_open_browser = false;
  c.unlock.port = 0; // always bind ephemeral — no cross-test collisions
  mutate(c);
  saveConfig(c);
}

const session = (agent = 'default'): McpSession => ({
  agent, agentOk: true, cfg: undefined, kpscript: KPS, log: () => {},
});

/** Structural secret-absence: no password/secret/cookie/master keys or
 *  's3cr3t' values may appear anywhere in a tool response. */
const FORBIDDEN_KEY = /password|secret|cookie|master|credential/i;
function assertNoSecrets(v: any, path = '$'): void {
  assert.ok(!JSON.stringify(v).includes('s3cr3t'), `${path}: secret value leaked`);
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      assert.ok(!FORBIDDEN_KEY.test(k), `${path}: forbidden key '${k}'`);
      assertNoSecrets(x, `${path}.${k}`);
    }
  }
}

const auditEvents = (): any[] =>
  existsSync(AUDIT_LOG) ? readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
const clearAudit = () => { try { unlinkSync(AUDIT_LOG); } catch {} };

let loginServer: Server;
let loginPort = 0;

before(async () => {
  setCfg();
  loginServer = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      const p = new URLSearchParams(b);
      const ok = p.get('password') === 's3cr3t' && p.get('username') === 'u@x.com';
      res.writeHead(ok ? 200 : 403, { 'content-type': 'text/plain' });
      res.end(ok ? 'welcome' : 'invalid credentials');
    });
  });
  await new Promise<void>((r) => loginServer!.listen(0, '127.0.0.1', () => r()));
  loginPort = (loginServer.address() as any).port;
  process.env.MOCK_ENTRY_URL = `http://127.0.0.1:${loginPort}/login`;
});

after(async () => {
  clearSession('testdb');
  loginServer?.close();
});

test('mcp tool — session_status reports LOCKED/UNLOCKED; omit db for all', async () => {
  clearSession('testdb');
  let r = await callTool(session(), 'session_status', { db: 'testdb' });
  assert.equal(r.success, true);
  assert.equal(r.mode, 'standard');
  assert.equal(r.status, 'LOCKED');
  await saveSession('testdb', 'rightkey', 300);
  r = await callTool(session(), 'session_status', { db: 'testdb' });
  assert.equal(r.status, 'UNLOCKED');
  r = await callTool(session(), 'session_status', {});
  assert.equal(r.databases?.testdb, 'UNLOCKED');
  assertNoSecrets(r);
});

test('mcp tool — search_entries returns metadata only (id/title/username/url)', async () => {
  await saveSession('testdb', 'rightkey', 300);
  const r = await callTool(session(), 'search_entries', { query: 'git' });
  assert.equal(r.success, true, JSON.stringify(r));
  assert.equal(r.database, 'testdb');
  assert.equal(r.matches.length, 1);
  assert.deepEqual(Object.keys(r.matches[0]).sort(), ['id', 'title', 'url', 'username']);
  assertNoSecrets(r);
  // field filters work like the CLI; a non-match returns an empty list.
  // (the mock entry URL is the loopback login server — see MOCK_ENTRY_URL)
  const m = await callTool(session(), 'search_entries', { site: '127.0.0.1' });
  assert.equal(m.matches.length, 1);
  const z = await callTool(session(), 'search_entries', { query: 'zzz-none' });
  assert.deepEqual(z.matches, []);
});

test('mcp tool — search_entries on a locked db is UNLOCK_REQUIRED, no criteria is INVALID_CONFIG', async () => {
  clearSession('testdb');
  const r = await callTool(session(), 'search_entries', { query: 'x' });
  assert.equal(r.success, false);
  assert.equal(r.code, 'UNLOCK_REQUIRED');
  await saveSession('testdb', 'rightkey', 300);
  const bad = await callTool(session(), 'search_entries', {});
  assert.equal(bad.code, 'INVALID_CONFIG');
});

test('mcp tool — search results honor the agent entry remit (denied_entries)', async () => {
  setCfg((c) => { c.agents = { default: { allowed: ['*'], denied_entries: ['GitHub*'] } }; });
  try {
    await saveSession('testdb', 'rightkey', 300);
    const r = await callTool(session(), 'search_entries', { query: 'git' });
    assert.equal(r.success, true);
    assert.deepEqual(r.matches, [], 'denied_entries must filter search results');
  } finally { setCfg(); }
});

test('mcp tool — request_login returns the worker result shape only', async () => {
  await saveSession('testdb', 'rightkey', 300);
  const r = await callTool(session(), 'request_login', { entry: 'UUID-1' });
  assert.equal(r.success, true, JSON.stringify(r));
  assert.equal(r.status, 'authenticated');
  assert.equal(r.entry_id, 'UUID-1');
  assert.deepEqual(Object.keys(r).sort(), ['database', 'entry_id', 'status', 'success'].sort());
  assertNoSecrets(r);
});

test('mcp tool — request_login resolves entry by site; ambiguous/unknown fail', async () => {
  await saveSession('testdb', 'rightkey', 300);
  const r = await callTool(session(), 'request_login', { site: '127.0.0.1' });
  assert.equal(r.success, true, JSON.stringify(r));
  assert.equal(r.entry_id, 'UUID-1');
  const nf = await callTool(session(), 'request_login', { title: 'no-such' });
  assert.equal(nf.code, 'ENTRY_NOT_FOUND');
  const nfe = await callTool(session(), 'request_login', { entry: 'NOPE-9' });
  assert.equal(nfe.code, 'ENTRY_NOT_FOUND');
  const uw = await callTool(session(), 'request_login', { entry: 'UUID-1', worker: 'evil-worker' });
  assert.equal(uw.code, 'UNSUPPORTED_WORKER');
});

test('mcp tool — logout/revoke_session drop the session', async () => {
  await saveSession('testdb', 'rightkey', 300);
  let r = await callTool(session(), 'logout', { db: 'testdb' });
  assert.equal(r.success, true);
  assert.equal(r.status, 'locked');
  assert.equal((await callTool(session(), 'session_status', { db: 'testdb' })).status, 'LOCKED');
  await saveSession('testdb', 'rightkey', 300);
  r = await callTool(session(), 'revoke_session', {});
  assert.equal(r.status, 'locked');
  assert.equal(r.alias, 'testdb');
});

test('mcp tool — audit_tail returns events (gated by audit.read)', async () => {
  clearAudit();
  await callTool(session(), 'session_status', {});
  const r = await callTool(session(), 'audit_tail', { limit: 10 });
  assert.equal(r.success, true);
  assert.ok(Array.isArray(r.events));
  const e = r.events.find((x: any) => x.action === 'mcp.session_status');
  assert.ok(e, JSON.stringify(r.events));
  assert.equal(e.result_code, 'OK');
  assertNoSecrets(r);
});

test('mcp tool — every call writes exactly one mcp.<tool> audit record', async () => {
  clearAudit();
  await saveSession('testdb', 'rightkey', 300);
  await callTool(session(), 'session_status', { db: 'testdb' });
  await callTool(session(), 'search_entries', { query: 'x' });
  const evs = auditEvents();
  assert.equal(evs.length, 2, JSON.stringify(evs));
  assert.equal(evs[0].action, 'mcp.session_status');
  assert.equal(evs[0].db, 'testdb');
  assert.equal(evs[1].action, 'mcp.search_entries');
  assert.match(evs[1].target, /^query:/);
  for (const e of evs) {
    assert.ok(e.ts && e.agent && e.decision && e.result_code, JSON.stringify(e));
  }
});

test('mcp tool — deny-by-default: unlisted action → POLICY_DENIED + deny audit', async () => {
  setCfg((c) => { c.agents = { default: { allowed: ['status'] } }; });
  try {
    clearAudit();
    const r = await callTool(session(), 'search_entries', { query: 'x' });
    assert.equal(r.success, false);
    assert.equal(r.code, 'POLICY_DENIED');
    const evs = auditEvents().filter((e) => e.action === 'mcp.search_entries');
    assert.equal(evs.length, 1);
    assert.equal(evs[0].decision, 'deny');
    assert.equal(evs[0].result_code, 'POLICY_DENIED');
  } finally { setCfg(); }
});

test('mcp tool — require_approval on a non-approval action → POLICY_APPROVAL_REQUIRED', async () => {
  setCfg((c) => { c.agents = { default: { allowed: ['status'], require_approval: ['login'] } }; });
  try {
    await saveSession('testdb', 'rightkey', 300);
    const r = await callTool(session(), 'request_login', { entry: 'UUID-1' });
    assert.equal(r.code, 'POLICY_APPROVAL_REQUIRED');
  } finally { setCfg(); }
});

test('mcp tool — request_unlock returns an approval URL (web channel, no master key via MCP)', async () => {
  const r = await callTool(session(), 'request_unlock', { db: 'testdb' });
  assert.equal(r.success, true, JSON.stringify(r));
  assert.equal(r.status, 'awaiting_user_input');
  assert.equal(typeof r.expires_in_seconds, 'number');
  assert.match(r.url, /^http:\/\/127\.0\.0\.1:\d+\/unlock\?t=[A-Za-z0-9_-]+$/);
  assertNoSecrets(r);
  // Cleanup: cancel the pending approval so its HTTP server closes.
  const t = new URL(r.url).searchParams.get('t')!;
  const cancel = await fetch(`http://127.0.0.1:${new URL(r.url).port}/cancel?t=${t}`, { method: 'POST' });
  assert.equal(cancel.status, 200);
});

test('mcp tool — request_unlock under require_approval still routes the web channel', async () => {
  setCfg((c) => { c.agents = { default: { allowed: ['status'], require_approval: ['unlock'] } }; });
  try {
    const r = await callTool(session(), 'request_unlock', { db: 'testdb' });
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(r.status, 'awaiting_user_input', 'unlock IS the approval channel — it must proceed');
    const t = new URL(r.url).searchParams.get('t')!;
    await fetch(`http://127.0.0.1:${new URL(r.url).port}/cancel?t=${t}`, { method: 'POST' });
  } finally { setCfg(); }
});

test('mcp tool — hardened enabled but unprovisioned fails closed (no silent standard path)', async () => {
  setCfg((c) => { c.hardened.enabled = true; });
  try {
    // Token file missing → the pre-flight ACL gate denies before any IPC.
    const s = await callTool(session(), 'search_entries', { query: 'x' });
    assert.equal(s.code, 'HARDENED_ACL_UNMET', JSON.stringify(s));
    const lo = await callTool(session(), 'logout', {});
    assert.equal(lo.code, 'HARDENED_ACL_UNMET');
    // status/audit reach the IPC client first — transport failures are
    // explicit HARDENED_* codes, never a standard-mode fallback.
    const st = await callTool(session(), 'session_status', { db: 'testdb' });
    assert.equal(st.success, true, JSON.stringify(st));
    assert.equal(st.mode, 'unavailable');
    assert.equal(st.status, 'UNAVAILABLE');
    const at = await callTool(session(), 'audit_tail', {});
    assert.equal(at.success, false);
    assert.ok(String(at.code).startsWith('HARDENED_'), at.code);
  } finally { setCfg(); }
});

// --- Hardened Mode live routing: agent → MCP → in-process service ---------

const SVC_STATE = join(TEST_HOME, 'svc-state-mcp');
const TOKEN_FILE = join(SVC_STATE, 'ipc-token');
const ENDPOINT = process.platform === 'win32'
  ? `\\\\.\\pipe\\kp-mcp-test-${process.pid}-${Math.random().toString(36).slice(2, 8)}`
  : join(SVC_STATE, 'svc.sock');
const ME = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
const ALLOWED_SIDS = [ME, 'NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators'];

let svc: ServiceServer | null = null;

async function startHardenedFixture(): Promise<void> {
  mkdirSync(SVC_STATE, { recursive: true });
  if (process.platform !== 'win32') {
    chmodSync(DB_PATH, 0o600);
    chmodSync(SVC_STATE, 0o750);
  } else {
    for (const [p, pmod] of [[DB_PATH, 'F'], [SVC_STATE, '(OI)(CI)F']] as const) {
      const r = spawnSync('icacls', [p, '/inheritance:r', '/grant:r', `${ME}:${pmod}`, `*S-1-5-18:${pmod}`, `BUILTIN\\Administrators:${pmod}`], { encoding: 'utf8' });
      assert.equal(r.status, 0, `icacls ${p}: ${r.stderr || r.stdout}`);
    }
  }
  const token = newToken();
  writeTokenFile(TOKEN_FILE, token);
  const cfg = normalize({});
  cfg.databases = { testdb: { path: DB_PATH } };
  cfg.keepass.default_database = 'testdb';
  cfg.agents = { default: { allowed: ['*'] } };
  cfg.hardened.enabled = true;
  cfg.hardened.token_file = TOKEN_FILE;
  cfg.hardened.state_dir = SVC_STATE;
  cfg.hardened.endpoint = process.platform === 'win32' ? ENDPOINT.replace('\\\\.\\pipe\\', '') : ENDPOINT;
  if (process.platform === 'win32') cfg.hardened.allowed_sids = ALLOWED_SIDS;
  cfg.unlock.auto_open_browser = false;
  cfg.unlock.port = 0;
  saveConfig(cfg);
  svc = await startServiceServer({
    endpoint: ENDPOINT, token, cfg,
    ctx: { kpscript: KPS, auditMaxBytes: AUDIT_MAX_BYTES_DEFAULT },
  });
}

test('mcp tool — hardened: search/status/login/lock/audit route over IPC', async () => {
  await startHardenedFixture();
  try {
    await saveSession('testdb', 'rightkey', 300); // shared home in tests
    let r = await callTool(session(), 'session_status', { db: 'testdb' });
    assert.equal(r.mode, 'hardened');
    assert.equal(r.status, 'UNLOCKED', JSON.stringify(r));

    r = await callTool(session(), 'search_entries', { query: 'git' });
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(r.matches?.[0]?.id, 'UUID-1');
    assertNoSecrets(r);

    r = await callTool(session(), 'request_login', { entry: 'UUID-1' });
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(r.status, 'authenticated');
    assertNoSecrets(r);

    r = await callTool(session(), 'logout', {});
    assert.equal(r.status, 'locked');
    r = await callTool(session(), 'session_status', { db: 'testdb' });
    assert.equal(r.status, 'LOCKED');

    // request_unlock: the approval round-trip runs inside the service; the
    // URL arrives as an IPC interim frame — cancel it for cleanup.
    r = await callTool(session(), 'request_unlock', { db: 'testdb' });
    assert.equal(r.success, true, JSON.stringify(r));
    assert.equal(r.status, 'awaiting_user_input');
    assert.match(r.url, /^http:\/\/127\.0\.0\.1:\d+\/unlock\?t=[A-Za-z0-9_-]+$/);
    assertNoSecrets(r);
    const u = new URL(r.url);
    const cancel = await fetch(`http://127.0.0.1:${u.port}/cancel?t=${u.searchParams.get('t')}`, { method: 'POST' });
    assert.equal(cancel.status, 200);

    r = await callTool(session(), 'audit_tail', { limit: 50 });
    assert.equal(r.success, true, JSON.stringify(r));
    // The service-side audit trail (authoritative in hardened mode) carries
    // the canonical op records the service wrote while fulfilling the calls.
    assert.ok(r.events.some((e: any) => e.action === 'login'), 'service-side audit must carry the login op');
    assertNoSecrets(r);
  } finally {
    await svc?.close();
    svc = null;
    setCfg();
    clearSession('testdb');
  }
});
