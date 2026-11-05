// Unlock-server security tests — boots waitForUnlock on an ephemeral loopback
// port and exercises it over real HTTP: token TTL/invalidation, Host/Origin
// checks, mandatory encrypted `p` payload, attempt-cap enforcement, and
// replay resistance.
//
// Import order matters: tmp-home must evaluate before any src module so that
// config.ts binds SESSION_DIR/CONFIG_PATH under the throwaway home.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { mkdirSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCipheriv, createPublicKey, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { requestUnlock, requestCookieSync, requestAddEntry, waitForUnlock, TOKEN_TTL_MS, type UnlockRequest, type UnlockResult } from '../../src/unlock-server/server.ts';
import { normalize, saveConfig, SESSION_DIR, type DbConfig } from '../../src/config/config.ts';
import { saveSession, readSession, sessionStatus, sessionFile, clearSession } from '../../src/security/dpapi.ts';

const __dir = dirname(fileURLToPath(import.meta.url));

// Tripwire — if tmp-home ever loses the import-order race, SESSION_DIR points
// at the real profile and this fails loudly instead of polluting it.
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

// win32 verify path: same [exe, ...prefix] convention as broker.ts /
// pipeline.test.ts — node runs a mock that reads the -keyprompt stdin and
// accepts only 'rightkey'.
const MOCK = join(TEST_HOME, 'mock-kpscript-unlock.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
process.exit(0)})`);
const KS: string[] = [process.execPath, MOCK];

// POSIX verify path goes through the PyKeePass helper protocol instead —
// inject the shared mock helper (master must be 'rightkey').
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

const DB: DbConfig = { path: 'C:/fake/test.kdbx', session_timeout: 900 };
const DBS: Record<string, DbConfig> = { testdb: DB };

// Register a config so the server-side loadConfig()/session_timeout paths
// resolve inside TEST_HOME rather than throwing.
{
  const c = normalize({});
  c.databases = { ...DBS };
  c.keepass.default_database = 'testdb';
  saveConfig(c);
}

let nextPort = 24100 + Math.floor(Math.random() * 3000);

interface Running { port: number; url: string; result: Promise<UnlockResult>; }

/** Boot waitForUnlock for `req` on a fresh port; resolves once it listens. */
function serve(req: UnlockRequest, dbs = DBS): Promise<Running> {
  const cfg = normalize({});
  cfg.unlock.port = nextPort++;
  cfg.unlock.auto_open_browser = false; // never spawn a browser in tests
  return new Promise((resolve) => {
    const result = waitForUnlock(cfg, KS, req, dbs, (url) => {
      resolve({ port: cfg.unlock.port, url, result });
    });
  });
}

interface Resp { status: number; body: string; json: any; }

function req(opts: { method?: string; path: string; port: number; headers?: Record<string, string>; body?: string }): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({
      hostname: '127.0.0.1', port: opts.port, path: opts.path,
      method: opts.method || 'GET', headers: opts.headers,
    }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => {
        let j: any = null;
        try { j = JSON.parse(b); } catch {}
        resolve({ status: res.statusCode!, body: b, json: j });
      });
    });
    r.on('error', reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}

const get = (port: number, path: string, headers?: Record<string, string>) => req({ port, path, headers });
const post = (port: number, path: string, body: string, headers: Record<string, string> = {}) =>
  req({ port, path, body, method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers } });

/** Pull the per-request RSA public JWK out of the served page. */
function pubkeyOf(htmlBody: string): any {
  const m = htmlBody.match(/const PUB = (\{[^;]+\});/);
  assert.ok(m, 'page did not contain a rendered PUBKEY');
  return JSON.parse(m![1]);
}

/** Test-side equivalent of the page's WebCrypto wrap: RSA-OAEP(kek) + AES-256-GCM. */
function encPayload(jwk: any, obj: Record<string, string>): string {
  const aes = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', aes, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  const ek = publicEncrypt(
    { key: createPublicKey({ key: jwk, format: 'jwk' }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aes);
  return `${ek.toString('base64url')}.${iv.toString('base64url')}.${ct.toString('base64url')}`;
}

const MAX_ATTEMPTS = 5;

test('unlock page — 200 for live token, 410 for bogus/expired tokens', async () => {
  const live = requestUnlock('testdb');
  const dead = requestUnlock('testdb');
  dead.expiresAt = Date.now() - 1; // force-expire before serving
  assert.equal(live.expiresAt - live.createdAt, TOKEN_TTL_MS, 'token TTL must be TOKEN_TTL_MS');
  const s = await serve(live);
  try {
  const page = await get(s.port, `/unlock?t=${live.token}`);
  assert.equal(page.status, 200);
  assert.match(page.body, /const PUB = \{/);
  // i18n wiring: English is the rendered default, Korean applies client-side
  // from data-i18n keys + the shared kp-lang preference.
  assert.match(page.body, /<html lang="en">/);
  assert.match(page.body, /data-i18n="title_unlock"/);
  assert.match(page.body, /kp-lang/);
  assert.match(page.body, /Unlock database/);

  assert.equal((await get(s.port, '/unlock?t=no-such-token')).status, 410);
  assert.equal((await get(s.port, `/unlock?t=${dead.token}`)).status, 410);
  } finally {
    // Cancel shuts the server down cleanly (also works on an expired token —
    // /cancel only checks pending membership).
    await post(s.port, `/cancel?t=${live.token}`, '').catch(() => {});
    const r = await s.result;
    assert.equal(r.ok, false);
    assert.equal(r.code, 'USER_INTERACTION_REQUIRED');
  }
});

test('onboarding — GET / and /onboarding need no token and carry the i18n loader', async () => {
  const req = requestUnlock('testdb');
  const s = await serve(req);
  try {
  for (const p of ['/', '/onboarding']) {
    const page = await get(s.port, p);
    assert.equal(page.status, 200, p);
    assert.match(page.body, /KeePass for agents/);
    assert.match(page.body, /data-i18n=/);
    assert.match(page.body, /kp-lang/);
  }
  // Still behind the same Host check — no tokenless hole off-loopback.
  assert.equal((await get(s.port, '/', { host: '10.0.0.9' })).status, 403);
  // And POSTing there is not a thing.
  assert.equal((await post(s.port, '/onboarding', '')).status, 404);
  } finally {
    await post(s.port, `/cancel?t=${req.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});

test('Host/Origin — non-loopback values are rejected with 403', async () => {
  const req = requestUnlock('testdb');
  const s = await serve(req);
  try {
  assert.equal((await get(s.port, `/unlock?t=${req.token}`, { host: '10.0.0.9' })).status, 403);
  assert.equal((await get(s.port, `/unlock?t=${req.token}`, { host: '127.0.0.1.evil.example' })).status, 403);
  assert.equal((await get(s.port, `/unlock?t=${req.token}`, { origin: 'http://evil.example' })).status, 403);
  assert.equal((await post(s.port, '/unlock', `t=${req.token}`, { origin: 'https://10.1.2.3:444' })).status, 403);
  } finally {
    await post(s.port, `/cancel?t=${req.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});

test('POST /unlock — plaintext credential fields are rejected (p required)', async () => {
  const req = requestUnlock('testdb');
  const s = await serve(req);
  try {
  // The page must be fetched first — it is what issues the per-token RSA key.
  assert.equal((await get(s.port, `/unlock?t=${req.token}`)).status, 200);

  // urlencoded plaintext — the old pre-PR-02 submit path
  const plain = await post(s.port, '/unlock', `t=${req.token}&password=rightkey`);
  assert.equal(plain.status, 400);
  assert.equal(plain.json?.code, 'PAYLOAD_REQUIRED');

  // JSON plaintext — same rule
  const plainJson = await post(s.port, '/unlock', JSON.stringify({ t: req.token, password: 'rightkey' }),
    { 'content-type': 'application/json' });
  assert.equal(plainJson.status, 400);
  assert.equal(plainJson.json?.code, 'PAYLOAD_REQUIRED');

  // p present but undecryptable — rejected, counts toward the attempt cap
  const bad = await post(s.port, '/unlock', `t=${req.token}&p=not-a-payload`);
  assert.equal(bad.status, 400);
  assert.equal(bad.json?.code, 'DECRYPT_FAILED');
  assert.ok(!('attempts' in (bad.json || {})), 'attempt count must not leak into responses');

  // p for an unknown token → 410 (checked before decrypt)
  assert.equal((await post(s.port, '/unlock', 't=bogus&p=zzz')).status, 410);
  } finally {
    await post(s.port, `/cancel?t=${req.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});

test('attempt cap — MAX_ATTEMPTS-1 failures keep the token, the MAXth invalidates it', async () => {
  // reqB is exercised over reqA's server: exhausting reqB must not close the
  // serving waitForUnlock, which lets us verify post-invalidation responses.
  const reqA = requestUnlock('testdb');
  const reqB = requestUnlock('testdb');
  const s = await serve(reqA);
  try {
  const pageB = await get(s.port, `/unlock?t=${reqB.token}`);
  assert.equal(pageB.status, 200);
  const jwkB = pubkeyOf(pageB.body);

  // Failure 1: undecryptable payload counts too.
  assert.equal((await post(s.port, '/unlock', `t=${reqB.token}&p=garbage`)).status, 400);

  // Failures 2..MAX-1: well-formed payload, wrong master key → 401.
  for (let i = 2; i < MAX_ATTEMPTS; i++) {
    const r = await post(s.port, '/unlock', `t=${reqB.token}&p=${encPayload(jwkB, { password: 'wrongkey' })}`);
    assert.equal(r.status, 401, `attempt ${i} should be a plain auth failure`);
    assert.ok(!('attempts' in (r.json || {})), 'remaining-attempts oracle must not leak');
  }

  // Still valid after MAX-1 failures.
  assert.equal((await get(s.port, `/unlock?t=${reqB.token}`)).status, 200);

  // MAXth failure invalidates the token; every later touch is 410.
  const last = await post(s.port, '/unlock', `t=${reqB.token}&p=${encPayload(jwkB, { password: 'wrongkey' })}`);
  assert.equal(last.status, 401);
  assert.equal((await get(s.port, `/unlock?t=${reqB.token}`)).status, 410);
  assert.equal((await post(s.port, '/unlock', `t=${reqB.token}&p=${encPayload(jwkB, { password: 'rightkey' })}`)).status, 410);
  } finally {
    // reqA is untouched — cancel it to close the server.
    await post(s.port, `/cancel?t=${reqA.token}`, '').catch(() => {});
    const r = await s.result;
    assert.equal(r.code, 'USER_INTERACTION_REQUIRED');
  }
});

test('attempt cap — exhausting the serving token finishes waitForUnlock', async () => {
  const req = requestUnlock('testdb');
  const s = await serve(req);
  try {
  const jwk = pubkeyOf((await get(s.port, `/unlock?t=${req.token}`)).body);
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    await post(s.port, '/unlock', `t=${req.token}&p=${encPayload(jwk, { password: 'wrongkey' })}`);
  }
  const r = await s.result;
  assert.equal(r.ok, false);
  assert.equal(r.code, 'MAX_ATTEMPTS_EXCEEDED');
  } finally {
    await post(s.port, `/cancel?t=${req.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});

test('success path — right key unlocks, session persists, token cannot replay', async () => {
  // Track every live server so a mid-test failure can't leak a listener.
  const running: Array<{ port: number; token: string; result: Promise<UnlockResult> }> = [];
  const open = async (req: UnlockRequest) => {
    const s = await serve(req);
    running.push({ port: s.port, token: req.token, result: s.result });
    return s;
  };
  try {
  const req = requestUnlock('testdb');
  const s = await open(req);
  const jwk = pubkeyOf((await get(s.port, `/unlock?t=${req.token}`)).body);

  const ok = await post(s.port, '/unlock', `t=${req.token}&p=${encPayload(jwk, { password: 'rightkey' })}`);
  assert.equal(ok.status, 200);
  assert.equal(ok.json?.ok, true);

  const r = await s.result;
  assert.equal(r.ok, true);
  assert.equal(r.status, 'unlocked');
  assert.equal(sessionStatus('testdb'), 'UNLOCKED');
  clearSession('testdb');

  // Replay defence: the consumed token is gone from pending — prove it via a
  // second live server (the first closed itself after success).
  const req2 = requestUnlock('testdb');
  const s2 = await open(req2);
  assert.equal((await get(s2.port, `/unlock?t=${req.token}`)).status, 410);
  // ...and a cancelled token dies the same way.
  await post(s2.port, `/cancel?t=${req2.token}`, '');
  const r2 = await s2.result;
  assert.equal(r2.code, 'USER_INTERACTION_REQUIRED');
  const req3 = requestUnlock('testdb');
  const s3 = await open(req3);
  assert.equal((await get(s3.port, `/unlock?t=${req2.token}`)).status, 410);
  } finally {
    for (const s of running) {
      await post(s.port, `/cancel?t=${s.token}`, '').catch(() => {});
      await s.result.catch(() => {});
    }
  }
});

test('sessions — expired file is cleaned by readSession/sessionStatus; POSIX mode 0600', async () => {
  const alias = 'sesstest';
  const f = sessionFile(alias);
  mkdirSync(SESSION_DIR, { recursive: true });
  const stale = JSON.stringify({ db: alias, expiresAt: Date.now() - 1000, payload: 'xx' });

  writeFileSync(f, stale);
  assert.equal(await readSession(alias), null);
  assert.ok(!existsSync(f), 'readSession must delete expired session files');

  writeFileSync(f, stale);
  assert.equal(sessionStatus(alias), 'EXPIRED');
  assert.ok(!existsSync(f), 'sessionStatus must delete expired session files');
  assert.equal(sessionStatus(alias), 'LOCKED');

  await saveSession(alias, 'rightkey', 60);
  assert.equal(sessionStatus(alias), 'UNLOCKED');
  assert.equal(await readSession(alias), 'rightkey');
  if (process.platform !== 'win32') {
    assert.equal(statSync(f).mode & 0o777, 0o600, 'session file must be user-only');
  }
  clearSession(alias);
});

test('submissionGate — deny runs before unlock/session side effects (G2)', async () => {
  // A denied submission must never mint a session: the gate is evaluated
  // right after parsing, BEFORE master-field unlock or session read. The
  // mock helper accepts 'rightkey', so if the gate ran late a session would
  // exist — asserting both the 403 and the absent session proves ordering.
  for (const [mode, mk] of [
    ['cookies', () => requestCookieSync('testdb', 'UUID-1', 'github.com', 'http://127.0.0.1:9222', 'agent-x')],
    ['entry', () => requestAddEntry('testdb', { title: 'T', url: 'https://good.com/' }, 'agent-x')],
  ] as const) {
    const req = mk();
    req.submissionGate = () => ({ ok: false, code: 'POLICY_DENIED', detail: 'drift-denied' });
    const s = await serve(req);
    try {
      const jwk = pubkeyOf((await get(s.port, `/unlock?t=${req.token}`)).body);
      const fields: Record<string, string> = mode === 'cookies'
        ? { master_password: 'rightkey' }
        : { password: 'entrypw', master_password: 'rightkey', title: 'T', url: 'https://good.com/' };
      const r = await post(s.port, '/unlock', `t=${req.token}&p=${encPayload(jwk, fields)}`);
      assert.equal(r.status, 403, `${mode}: ${r.body}`);
      assert.equal(r.json?.code, 'POLICY_DENIED', `${mode}: ${r.body}`);
      assert.equal(await readSession('testdb'), null, `${mode}: deny must not mint a session`);
    } finally {
      // The token survives a policy deny (it is not an auth failure) —
      // cancel to release the server even on assertion failure.
      await post(s.port, `/cancel?t=${req.token}`, '').catch(() => {});
      await s.result;
    }
  }
});
