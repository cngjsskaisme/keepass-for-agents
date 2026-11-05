// Hardened Mode end-to-end — a real Credential Service process (separate
// HOME = separate session store / DPAPI scope) serving the real kp CLI over
// authenticated IPC. SELFTEST env keeps the service's own ACL self-check off
// (same-uid runs can't satisfy cross-account checks); the client-side gate
// still runs fully.
//
// Import order: tmp-home first.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { chmodSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { normalize, saveConfig, CONFIG_PATH, SESSION_DIR, type AppConfig } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');
const SVC_TS = join(__dir, '..', '..', 'src', 'service', 'service.ts');
const DPAPI_URL = pathToFileURL(join(__dir, '..', '..', 'src', 'security', 'dpapi.ts')).href;
const SESSION_HELPER = join(__dir, '..', 'fixtures', 'svc-session.mjs');

const SVC_HOME = join(TEST_HOME, 'svc-home');
const SVC_STATE = join(TEST_HOME, 'svc-state');
mkdirSync(SVC_HOME, { recursive: true });
const ALIAS = 'hdb';
const DB_PATH = join(TEST_HOME, 'hdb.kdbx');
const TOKEN_FILE = join(SVC_STATE, 'ipc-token');
const PIPE = `kp-it-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
const ENDPOINT = process.platform === 'win32' ? PIPE : join(SVC_STATE, 'svc.sock');

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

// POSIX: env-parameterized mock helper so the entry URL can point at the
// local login server (the fixture returns this test's loopback endpoint).
const MOCK_HELPER = join(TEST_HOME, 'mock-helper-hardened.mjs');
writeFileSync(MOCK_HELPER, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
let j={};try{j=JSON.parse(d)}catch{}
if(j.master!=='rightkey'){process.stdout.write(JSON.stringify({ok:false,code:'INVALID_MASTER_KEY'}));process.exit(1)}
if(j.cmd==='verify')process.stdout.write(JSON.stringify({ok:true}));
else if(j.cmd==='list')process.stdout.write(JSON.stringify({ok:true,entries:[{id:'UUID-1',title:'Local Site',username:'agent1',url:process.env.MOCK_ENTRY_URL||''}]}));
else if(j.cmd==='get')process.stdout.write(JSON.stringify({ok:true,secret:'s3cr3t'}));
else process.stdout.write(JSON.stringify({ok:false,code:'UNKNOWN_CMD'}))})`);

// Windows allow-list: the exact principal set provisioning would grant —
// current user (agent+operator stand-in) + SYSTEM + Administrators.
// `whoami` may return a bare name in some environments; USERDOMAIN\USERNAME
// is the form icacls displays and winAclCheck compares.
const ME = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
const ALLOWED_SIDS = [ME, 'NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators'];

function baseCfg(over: (c: AppConfig) => void = () => {}): AppConfig {
  const c = normalize({});
  c.databases = { [ALIAS]: { path: DB_PATH } };
  c.keepass.default_database = ALIAS;
  c.agents = { default: { allowed: ['*'] } };
  c.hardened.enabled = true;
  c.hardened.token_file = TOKEN_FILE;
  c.hardened.state_dir = SVC_STATE;
  c.hardened.endpoint = ENDPOINT; // posix path; win32 pipe name
  if (process.platform === 'win32') c.hardened.allowed_sids = ALLOWED_SIDS;
  c.unlock.auto_open_browser = false;
  over(c);
  return c;
}

interface KpRun { status: number | null; stdout: string; stderr: string; json: any }
function kp(args: string[], env: Record<string, string | undefined> = {}): KpRun {
  const e: Record<string, string> = { ...process.env, USERPROFILE: TEST_HOME, HOME: TEST_HOME, KEEPASS_AGENT_ID: 'e2e' } as any;
  delete e.KEEPASS_AGENT_CONFIG;            // CLI must use its own (agent-side) home
  delete e.KEEPASS_AGENT_SERVICE_SELFTEST;  // service-only hook
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete e[k]; else e[k] = v; }
  const r = spawnSync(process.execPath, [KP, ...args], { env: e, encoding: 'utf8', timeout: 45_000 });
  let json: any = null;
  try { json = JSON.parse(r.stdout.trim().split('\n').pop() || ''); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

let loginServer: Server;
let loginPort = 0;
let svc: ChildProcess | null = null;

function startSvc(): Promise<void> {
  return new Promise((resolve, reject) => {
    const env: Record<string, string> = {
      ...process.env,
      HOME: SVC_HOME, USERPROFILE: SVC_HOME,
      KEEPASS_AGENT_CONFIG: CONFIG_PATH,
      KEEPASS_AGENT_SERVICE_SELFTEST: '1',
      MOCK_ENTRY_URL: `http://127.0.0.1:${loginPort}/login`,
    } as any;
    if (process.platform !== 'win32')
      env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([process.execPath, MOCK_HELPER]);
    svc = spawn(process.execPath, [SVC_TS], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    const to = setTimeout(() => reject(new Error(`service did not report ready: ${buf}`)), 20_000);
    svc.stdout!.on('data', (d) => {
      buf += d;
      const line = buf.split('\n').find((l) => l.includes('"ready"'));
      if (line) { clearTimeout(to); resolve(); }
    });
    svc.on('exit', (c) => { if (c) reject(new Error(`service exited ${c}: ${buf}`)); });
  });
}

function stopSvc(): Promise<void> {
  return new Promise((resolve) => {
    if (!svc) return resolve();
    svc.once('exit', () => { svc = null; resolve(); });
    svc.kill('SIGTERM');
    setTimeout(() => { try { svc?.kill('SIGKILL'); } catch {}; svc = null; resolve(); }, 3_000);
  });
}

/** Inject a valid session into the SERVICE home (service-side session store). */
function makeSvcSession(alias = ALIAS, key = 'rightkey', ttl = 300): void {
  const r = spawnSync(process.execPath, [SESSION_HELPER, DPAPI_URL, alias, key, String(ttl)], {
    env: { ...process.env, HOME: SVC_HOME, USERPROFILE: SVC_HOME },
    encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(r.stdout.trim(), 'ok', `session inject failed: ${r.stderr}`);
}

before(async () => {
  writeFileSync(DB_PATH, Buffer.alloc(64, 5));
  if (process.platform !== 'win32') chmodSync(DB_PATH, 0o600);
  else {
    // Explicit tight ACL (same shape provisioning applies) — temp dirs
    // inherit environment-specific ACEs (sandbox groups, stray SIDs) that
    // would legitimately trip the allow-list, so normalize to the 3 listed
    // principals. The service state dir gets the same treatment so the
    // token file it writes inherits only the allowed set.
    mkdirSync(SVC_STATE, { recursive: true });
    for (const [p, pmod] of [[DB_PATH, 'F'], [SVC_STATE, '(OI)(CI)F']] as const) {
      const r = spawnSync('icacls', [p, '/inheritance:r', '/grant:r', `${ME}:${pmod}`, `*S-1-5-18:${pmod}`, `BUILTIN\\Administrators:${pmod}`], { encoding: 'utf8' });
      assert.equal(r.status, 0, `icacls ${p}: ${r.stderr || r.stdout}`);
    }
  }
  loginServer = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => b += c);
    req.on('end', () => {
      const p = new URLSearchParams(b);
      const ok = p.get('password') === 's3cr3t' && p.get('username') === 'agent1';
      res.writeHead(ok ? 200 : 403, { 'content-type': 'text/plain' });
      res.end(ok ? 'welcome' : 'invalid credentials');
    });
  });
  await new Promise<void>((r) => loginServer.listen(0, '127.0.0.1', () => r()));
  loginPort = (loginServer.address() as any).port;
  saveConfig(baseCfg());
  await startSvc();
});

after(async () => {
  await stopSvc();
  loginServer?.close();
});

test('hardened — kp status reports mode/service/isolation while service is up', () => {
  const r = kp(['status']);
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(r.json?.mode, 'hardened');
  assert.equal(r.json?.service?.state, 'up');
  assert.equal(r.json?.service?.endpoint, process.platform === 'win32' ? `\\\\.\\pipe\\${PIPE}` : ENDPOINT);
  assert.equal(r.json?.isolation?.ok, true, JSON.stringify(r.json?.isolation));
  assert.equal(r.json?.databases?.[ALIAS], 'LOCKED');
});

test('hardened — locked service reports UNLOCK_REQUIRED (fail-closed code)', () => {
  const r = kp(['search', '--db', ALIAS, '--title', 'x']);
  assert.equal(r.json?.code, 'UNLOCK_REQUIRED', r.stdout);
  assert.equal(r.status, 3);
});

test('hardened — db list/current surface service-held session state', () => {
  makeSvcSession();
  const l = kp(['db', 'list']);
  const dbRow = l.json?.databases?.find((d: any) => d.alias === ALIAS);
  assert.equal(dbRow?.state, 'UNLOCKED', l.stdout);
  const c = kp(['db', 'current']);
  assert.equal(c.json?.state, 'UNLOCKED', c.stdout);
});

test('hardened — search returns entries via the service (POSIX full flow)', () => {
  const r = kp(['search', '--db', ALIAS, '--title', 'Local']);
  if (process.platform === 'win32') {
    // No KPScript on CI — routing proof: the service answered with a
    // provider code (session was valid, provider was invoked), not a
    // HARDENED_* transport failure.
    assert.ok(r.json?.code, r.stdout);
    assert.ok(!String(r.json.code).startsWith('HARDENED_'), r.stdout);
    return;
  }
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(r.json?.matches?.[0]?.id, 'UUID-1');
  assert.ok(!r.stdout.includes('s3cr3t'));
});

test('hardened — login pipes secret service-side; agent sees status only', { skip: process.platform === 'win32' }, async () => {
  const r = kp(['login', '--db', ALIAS, '--entry', 'UUID-1', '--worker', 'local-test']);
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(r.json?.status, 'authenticated');
  assert.ok(!r.stdout.includes('s3cr3t'), 'stdout must not carry the secret');
});

test('hardened — login reaches the provider inside the service (Windows routing proof)', { skip: process.platform !== 'win32' }, () => {
  const r = kp(['login', '--db', ALIAS, '--entry', 'UUID-1', '--worker', 'local-test']);
  assert.ok(r.json?.code, r.stdout);
  assert.ok(!String(r.json.code).startsWith('HARDENED_'), r.stdout);
});

test('hardened — service-side audit log is readable via kp audit', () => {
  const r = kp(['audit', '--limit', '50']);
  assert.equal(r.json?.success, true, r.stdout);
  assert.ok(r.json?.events?.length >= 1, JSON.stringify(r.json?.events));
  assert.ok(r.json?.events?.some((e: any) => e.agent === 'e2e'));
});

test('hardened — wrong capability token fails the handshake explicitly', () => {
  const badToken = join(SVC_STATE, 'wrong-token');
  writeFileSync(badToken, 'z'.repeat(48));
  if (process.platform !== 'win32') chmodSync(badToken, 0o640);
  // Point the CLIENT config at the wrong token (service's is unchanged).
  saveConfig(baseCfg((c) => { c.hardened.token_file = badToken; }));
  try {
    const r = kp(['lock', '--db', ALIAS]);
    assert.equal(r.json?.code, 'HARDENED_AUTH_FAILED', r.stdout);
  } finally {
    saveConfig(baseCfg());
  }
});

test('hardened — KDBX readable by non-service principals → ACL_UNMET', () => {
  if (process.platform === 'win32') {
    const r0 = spawnSync('icacls', [DB_PATH, '/grant', 'Everyone:R'], { encoding: 'utf8' });
    assert.equal(r0.status, 0, r0.stderr);
    try {
      const r = kp(['search', '--db', ALIAS, '--title', 'x']);
      assert.equal(r.json?.code, 'HARDENED_ACL_UNMET', r.stdout);
    } finally {
      const me = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
      spawnSync('icacls', [DB_PATH, '/inheritance:r', '/grant:r', `${me}:F`, '*S-1-5-18:F', 'BUILTIN\\Administrators:F'], { encoding: 'utf8' });
    }
  } else {
    chmodSync(DB_PATH, 0o644);
    try {
      const r = kp(['search', '--db', ALIAS, '--title', 'x']);
      assert.equal(r.json?.code, 'HARDENED_ACL_UNMET', r.stdout);
    } finally {
      chmodSync(DB_PATH, 0o600);
    }
  }
});

test('hardened — service down is UNAVAILABLE, never a silent standard fallback', async () => {
  await stopSvc();
  const r = kp(['lock', '--db', ALIAS]);
  assert.equal(r.json?.code, 'HARDENED_SERVICE_UNAVAILABLE', r.stdout);
  assert.notEqual(r.status, 0);
  // kp status reports the down state instead of failing.
  const s = kp(['status']);
  assert.equal(s.json?.mode, 'unavailable', s.stdout);
  assert.equal(s.json?.service?.state, 'down');
  assert.equal(s.json?.databases?.[ALIAS], 'UNAVAILABLE');
});

test('hardened — ACL allow-list: a granted principal missing from allowed_sids is UNMET (F2)', { skip: process.platform !== 'win32' }, () => {
  // The KDBX carries an Administrators ACE — drop it from the allow-list and
  // the check must fail closed even though Administrators look "safe".
  saveConfig(baseCfg((c) => { c.hardened.allowed_sids = [ME, 'NT AUTHORITY\\SYSTEM']; }));
  try {
    const r = kp(['search', '--db', ALIAS, '--title', 'x']);
    assert.equal(r.json?.code, 'HARDENED_ACL_UNMET', r.stdout);
  } finally {
    saveConfig(baseCfg());
  }
});

test('hardened — config set cannot toggle the mode (F3); direct edit works', () => {
  // F3: hardened.* via `config set` is rejected — same-UID callers must not
  // be able to downgrade isolation. The attempt is still a clean failure.
  const set = kp(['config', 'set', 'hardened.enabled', 'false']);
  assert.equal(set.json?.code, 'CONFIG_KEY_READONLY', set.stdout);
  // Config untouched — still hardened (mode is 'unavailable' rather than
  // 'hardened' here because the service-down test already stopped it; what
  // matters is it never silently became 'standard').
  const still = kp(['status']);
  assert.notEqual(still.json?.mode, 'standard', still.stdout);
  // Operator path: editing config.toml directly flips the mode.
  saveConfig(baseCfg((c) => { c.hardened.enabled = false; }));
  try {
    const s = kp(['status']);
    assert.equal(s.json?.mode, 'standard', s.stdout);
  } finally {
    saveConfig(baseCfg());
  }
});

test('hardened — peer_verify=strict with empty allowed_uids refuses to start (F9)', () => {
  saveConfig(baseCfg((c) => { c.hardened.peer_verify = 'strict'; }));
  try {
    const env: Record<string, string> = {
      ...process.env,
      HOME: SVC_HOME, USERPROFILE: SVC_HOME,
      KEEPASS_AGENT_CONFIG: CONFIG_PATH,
      KEEPASS_AGENT_SERVICE_SELFTEST: '1',
    } as any;
    const r = spawnSync(process.execPath, [SVC_TS], { env, encoding: 'utf8', timeout: 15_000 });
    assert.notEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr, /allowed_uids/);
  } finally {
    saveConfig(baseCfg());
  }
});
