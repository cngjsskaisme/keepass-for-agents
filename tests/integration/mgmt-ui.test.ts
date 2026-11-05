// Management UI (kp ui) tests — boots startMgmtServer on an ephemeral
// loopback port and exercises the JSON API over real HTTP: session-token
// enforcement, Host/Origin checks, method rules, session list/revoke,
// audit reads (with filters), agents read/write (config.toml + audit
// record), the declared-agent policy gate (deny-by-default), the operator
// bypass, hardened IPC fail-closed paths, and the standard-mode unlock
// delegation to the existing approval flow.
//
// Import order matters: tmp-home must evaluate before any src module so
// config.ts binds SESSION_DIR/CONFIG_PATH under the throwaway home.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCipheriv, createPublicKey, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { startMgmtServer, type MgmtServer } from '../../src/mgmt/server.ts';
import { normalize, saveConfig, SESSION_DIR, CONFIG_DIR, type AppConfig } from '../../src/config/config.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');
const DB_PATH = join(TEST_HOME, 'mgmt.kdbx');

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);
writeFileSync(DB_PATH, Buffer.alloc(64, 9)); // getDb only needs the file to exist

// win32 verify path: [exe, ...prefix] hook (same convention as the unlock
// server tests) — a mock that accepts only 'rightkey' on the -keyprompt stdin.
const MOCK = join(TEST_HOME, 'mock-kpscript-mgmt.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
process.exit(0)})`);
const KS: string[] = [process.execPath, MOCK];

// POSIX verify path goes through the PyKeePass helper protocol (mock-helper
// accepts master 'rightkey').
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

function setCfg(mutate: (c: AppConfig) => void = () => {}): void {
  const c = normalize({});
  c.databases = { testdb: { path: DB_PATH } };
  c.keepass.default_database = 'testdb';
  c.agents = { default: { allowed: ['*'] } };
  mutate(c);
  saveConfig(c);
}
setCfg();

const servers: MgmtServer[] = [];
async function boot(kpscript: string | string[] = '', launchAgent = 'default', ttlMs = 60_000): Promise<MgmtServer> {
  const s = await startMgmtServer({ kpscript, launchAgent, ttlMs });
  servers.push(s);
  return s;
}

interface Resp { status: number; body: string; json: any; headers: Record<string, any>; }
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
        resolve({ status: res.statusCode!, body: b, json: j, headers: res.headers });
      });
    });
    r.on('error', reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}

const get = (s: MgmtServer, path: string, headers: Record<string, string> = {}) => req({ port: s.port, path, headers });
const getT = (s: MgmtServer, path: string, headers: Record<string, string> = {}) =>
  get(s, path, { 'x-kp-ui-token': s.token, ...headers });
const postT = (s: MgmtServer, path: string, body: any, headers: Record<string, string> = {}) =>
  req({
    port: s.port, path, method: 'POST', body: JSON.stringify(body),
    headers: { 'x-kp-ui-token': s.token, 'content-type': 'application/json', ...headers },
  });

const auditEvents = (): any[] => {
  if (!existsSync(AUDIT_LOG)) return [];
  return readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
};
const clearAudit = () => { try { unlinkSync(AUDIT_LOG); } catch {} };

function pubkeyOf(htmlBody: string): any {
  const m = htmlBody.match(/const PUB = (\{[^;]+\});/);
  assert.ok(m, 'unlock page did not contain a rendered PUBKEY');
  return JSON.parse(m![1]);
}
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

test('page + tokens — one-time pageToken in URL, apiToken header-only; cookie reload', async () => {
  const s = await boot();
  try {
    const pageT = new URL(s.url).searchParams.get('t')!;
    assert.ok(pageT, 'launch URL must carry the page token');
    assert.notEqual(pageT, s.token, 'URL token and API session token must differ (F-2)');

    // The page is served only via the one-time URL token.
    assert.equal((await get(s, '/')).status, 403);
    assert.equal((await get(s, '/?t=bogus')).status, 403);
    // The API token is never a valid page token.
    assert.equal((await get(s, `/?t=${s.token}`)).status, 403);

    const page = await get(s, `/?t=${pageT}`);
    assert.equal(page.status, 200);
    assert.match(page.body, /const UI_TOKEN = "/);
    assert.ok(page.body.includes(s.token), 'apiToken must be embedded for API calls');
    // First serve sets the SameSite=Strict HttpOnly reload cookie.
    const sc = page.headers['set-cookie'];
    const cookieLine = Array.isArray(sc) ? sc[0] : sc;
    assert.match(String(cookieLine), new RegExp(`kpui=${s.token}`));
    assert.match(String(cookieLine), /HttpOnly/i);
    assert.match(String(cookieLine), /SameSite=Strict/i);

    // F-2: the page token is consumed — replay (e.g. argv-recovered URL) dies.
    assert.equal((await get(s, `/?t=${pageT}`)).status, 403);
    // A same-browser reload re-serves via the cookie instead.
    const re = await get(s, '/', { cookie: `kpui=${s.token}` });
    assert.equal(re.status, 200);
    // A forged cookie does not.
    assert.equal((await get(s, '/', { cookie: 'kpui=bogus' })).status, 403);

    // API without/with a wrong token → 401 before any handler.
    assert.equal((await get(s, '/api/dbs')).status, 401);
    assert.equal((await get(s, '/api/dbs', { 'x-kp-ui-token': 'wrong' })).status, 401);
    assert.equal((await get(s, '/api/audit')).status, 401);
    assert.equal((await postT(s, '/api/session/lock', { db: 'testdb' }, { 'x-kp-ui-token': 'nope' })).status, 401);
    // The consumed pageToken is no better — API needs the apiToken.
    assert.equal((await get(s, '/api/dbs', { 'x-kp-ui-token': pageT })).status, 401);
    // Correct token → the API answers.
    assert.equal((await getT(s, '/api/dbs')).status, 200);
  } finally { s.close(); await s.done; }
});

test('Host/Origin — non-loopback values rejected; mutation method rules', async () => {
  const s = await boot();
  try {
    assert.equal((await get(s, `/?t=${s.token}`, { host: '10.0.0.9' })).status, 403);
    assert.equal((await getT(s, '/api/dbs', { host: '127.0.0.1.evil.example' })).status, 403);
    assert.equal((await postT(s, '/api/session/lock', { db: 'testdb' }, { origin: 'http://evil.example' })).status, 403);
    // Loopback origin is fine.
    assert.equal((await getT(s, '/api/dbs', { origin: `http://127.0.0.1:${s.port}` })).status, 200);
    // Mutations are POST-only; reads are GET-only.
    assert.equal((await getT(s, '/api/session/lock')).status, 405);
    assert.equal((await postT(s, '/api/dbs', {})).status, 405);
    assert.equal((await getT(s, '/api/agents')).status, 200);
    // Unknown paths.
    assert.equal((await getT(s, '/api/nope')).status, 404);
    // Mutation bodies must be JSON.
    assert.equal((await req({ port: s.port, path: '/api/session/lock', method: 'POST', body: 'db=testdb', headers: { 'x-kp-ui-token': s.token, 'content-type': 'application/x-www-form-urlencoded' } })).json?.code, 'BAD_CONTENT_TYPE');
    assert.equal((await postT(s, '/api/session/lock', 'not json')).json?.code, 'INVALID_JSON');
  } finally { s.close(); await s.done; }
});

test('sessions — list shows state; POST /api/session/lock revokes and audits as operator', async () => {
  setCfg();
  clearAudit();
  await saveSession('testdb', 'rightkey', 600);
  const s = await boot();
  try {
    const d1 = await getT(s, '/api/dbs');
    assert.equal(d1.status, 200);
    const row = d1.json.databases.find((d: any) => d.alias === 'testdb');
    assert.equal(row.state, 'UNLOCKED');
    assert.equal(row.default, true);
    assert.equal(d1.json.mode, 'standard');

    const r = await postT(s, '/api/session/lock', { db: 'testdb' });
    assert.equal(r.status, 200, r.body);
    assert.equal(r.json.status, 'locked');

    const d2 = await getT(s, '/api/dbs');
    assert.equal(d2.json.databases.find((d: any) => d.alias === 'testdb').state, 'LOCKED');

    const evs = auditEvents();
    const lockEv = evs.find((e) => e.action === 'ui.lock');
    assert.ok(lockEv, JSON.stringify(evs));
    assert.equal(lockEv.agent, 'operator');
    assert.equal(lockEv.db, 'testdb');
    assert.equal(lockEv.result_code, 'OK');
    assert.ok(evs.some((e) => e.action === 'ui.dbs' && e.agent === 'operator'), 'reads are audited too');
    // Invalid alias shape is rejected and audited.
    assert.equal((await postT(s, '/api/session/lock', { db: 'bad alias!' })).json?.code, 'INVALID_CONFIG');
  } finally { clearSession('testdb'); s.close(); await s.done; }
});

test('audit endpoint — recent events, agent/action filters, ui.* marker records', async () => {
  setCfg();
  clearAudit();
  const s = await boot();
  try {
    await getT(s, '/api/dbs');               // writes ui.dbs
    await postT(s, '/api/session/lock', { db: 'testdb' }); // writes ui.lock
    const r = await getT(s, '/api/audit?limit=50');
    assert.equal(r.status, 200);
    assert.ok(Array.isArray(r.json.events));
    assert.ok(r.json.events.some((e: any) => e.action === 'ui.dbs'));
    assert.ok(r.json.events.some((e: any) => e.action === 'ui.lock'));
    // Filters are exact-match.
    const fa = await getT(s, '/api/audit?action=ui.lock');
    assert.ok(fa.json.events.length >= 1);
    assert.ok(fa.json.events.every((e: any) => e.action === 'ui.lock'));
    const fag = await getT(s, '/api/audit?agent=operator');
    assert.ok(fag.json.events.every((e: any) => e.agent === 'operator'));
    const fnone = await getT(s, '/api/audit?agent=no-such-agent');
    assert.equal(fnone.json.events.length, 0);
    // The audit read itself is audited as ui.audit.
    assert.ok(auditEvents().some((e) => e.action === 'ui.audit' && e.result_code === 'OK'));
  } finally { s.close(); await s.done; }
});

test('agents read/write — config.toml updated, audit recorded, validation enforced', async () => {
  setCfg((c) => { c.agents = { default: { allowed: ['*'] }, worker1: { allowed: ['search'] } }; });
  clearAudit();
  const s = await boot();
  try {
    const g = await getT(s, '/api/agents');
    assert.equal(g.status, 200);
    assert.deepEqual(g.json.agents.worker1.allowed, ['search']);

    // Write a policy.
    const w = await postT(s, '/api/agents', {
      name: 'worker1',
      policy: { allowed: ['search', 'db.list'], require_approval: ['login'], allowed_hosts: ['example.com'] },
    });
    assert.equal(w.status, 200, w.body);
    const after = await getT(s, '/api/agents');
    assert.deepEqual(after.json.agents.worker1.allowed, ['search', 'db.list']);
    assert.deepEqual(after.json.agents.worker1.require_approval, ['login']);
    assert.deepEqual(after.json.agents.worker1.allowed_hosts, ['example.com']);
    // The change really landed in config.toml (fresh CLI-equivalent read).
    const toml = readFileSync(join(CONFIG_DIR, 'config.toml'), 'utf8');
    assert.match(toml, /\[agents\.worker1\]/);
    assert.match(toml, /require_approval = \["login"\]/);
    assert.match(toml, /allowed_hosts = \["example\.com"\]/);

    // New agent creation.
    assert.equal((await postT(s, '/api/agents', { name: 'newbot', policy: { allowed: ['ui.audit'] } })).status, 200);
    // Bad inputs are rejected.
    assert.equal((await postT(s, '/api/agents', { name: 'bad.name', policy: {} })).json?.code, 'INVALID_CONFIG');
    assert.equal((await postT(s, '/api/agents', { name: '__proto__', policy: {} })).json?.code, 'INVALID_CONFIG');
    assert.equal((await postT(s, '/api/agents', { name: 'x', policy: { allowed: 'notalist' } })).json?.code, 'INVALID_CONFIG');
    // Delete.
    assert.equal((await postT(s, '/api/agents', { name: 'newbot', delete: true })).status, 200);
    assert.ok(!Object.hasOwn((await getT(s, '/api/agents')).json.agents, 'newbot'));
    assert.equal((await postT(s, '/api/agents', { name: 'newbot', delete: true })).json?.code, 'AGENT_NOT_FOUND');

    const evs = auditEvents().filter((e) => e.action === 'ui.agents.write');
    assert.ok(evs.length >= 5, JSON.stringify(evs));
    assert.ok(evs.some((e) => e.agent === 'operator' && e.result_code === 'OK' && e.target === 'agents.worker1'));
    assert.ok(evs.some((e) => e.result_code === 'INVALID_CONFIG'));
  } finally { s.close(); await s.done; }
});

test('declared-agent gate — x-kp-agent is policy-evaluated deny-by-default; operator bypasses', async () => {
  setCfg((c) => {
    c.agents = {
      default: { allowed: ['ui'] },          // launcher only needs 'ui'
      reader: { allowed: ['ui.audit'] },     // API-scoped agent
    };
  });
  clearAudit();
  const s = await boot();
  try {
    // Operator (no header) bypasses even though [agents.default] lacks ui.dbs —
    // [agents.operator] is unconfigured so the console keeps operator rights.
    assert.equal((await getT(s, '/api/dbs')).status, 200);

    // Declared agent is evaluated against ui.* actions.
    const denied = await getT(s, '/api/dbs', { 'x-kp-agent': 'reader' });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.code, 'POLICY_DENIED');
    const allowed = await getT(s, '/api/audit', { 'x-kp-agent': 'reader' });
    assert.equal(allowed.status, 200);
    // Unknown agent → deny-by-default.
    assert.equal((await getT(s, '/api/dbs', { 'x-kp-agent': 'ghost' })).json?.code, 'POLICY_DENIED');
    // Mutations gated the same way — and ui.agents.write fires the stricter
    // OPERATOR_ONLY check before policy evaluation (MED-3).
    assert.equal((await postT(s, '/api/agents', { name: 'z', policy: {} }, { 'x-kp-agent': 'reader' })).json?.code, 'OPERATOR_ONLY');
    assert.equal((await postT(s, '/api/session/lock', { db: 'testdb' }, { 'x-kp-agent': 'reader' })).json?.code, 'POLICY_DENIED');
    // Malformed identity fails closed — including an EMPTY header, which
    // must never silently degrade to operator (F-3).
    assert.equal((await getT(s, '/api/dbs', { 'x-kp-agent': 'bad agent!' })).json?.code, 'INVALID_AGENT_ID');
    assert.equal((await getT(s, '/api/dbs', { 'x-kp-agent': '' })).json?.code, 'INVALID_AGENT_ID');

    // Denials are attributed to the declared agent, grants too.
    const evs = auditEvents();
    assert.ok(evs.some((e) => e.agent === 'reader' && e.action === 'ui.dbs' && e.result_code === 'POLICY_DENIED'), JSON.stringify(evs));
    assert.ok(evs.some((e) => e.agent === 'reader' && e.action === 'ui.audit' && e.result_code === 'OK'));

    // MED-3: ui.agents.write is OPERATOR_ONLY — a declared agent can never
    // write policy through the API, even when [agents.<id>] grants it.
    setCfg((c) => { c.agents = { default: { allowed: ['ui'] }, writer: { allowed: ['ui.agents.write'] } }; });
    const w = await postT(s, '/api/agents', { name: 'x', policy: {} }, { 'x-kp-agent': 'writer' });
    assert.equal(w.status, 403);
    assert.equal(w.json.code, 'OPERATOR_ONLY');
    assert.ok(auditEvents().some((e) => e.agent === 'writer' && e.action === 'ui.agents.write' && e.result_code === 'OPERATOR_ONLY'));
    // An explicit [agents.operator] section turns the bypass into evaluation.
    setCfg((c) => { c.agents = { default: { allowed: ['ui'] }, operator: { allowed: ['ui.dbs'] } }; });
    assert.equal((await getT(s, '/api/dbs')).status, 200);        // operator allowed
    assert.equal((await getT(s, '/api/audit')).status, 403);      // operator scoped to ui.dbs only
  } finally { s.close(); await s.done; setCfg(); }
});

test('unlock — POST /api/unlock returns the approval URL; completing it unlocks the DB', async () => {
  setCfg();
  clearSession('testdb');
  const s = await boot(KS);
  let unlockUrl: URL | null = null;
  try {
    const r = await postT(s, '/api/unlock', { db: 'testdb' });
    assert.equal(r.status, 200, r.body);
    assert.ok(r.json.url.startsWith('http://127.0.0.1:'), r.body);
    assert.ok(r.json.expires_in_seconds > 0);
    unlockUrl = new URL(r.json.url);

    // The approval page is the standard unlock-server flow — token + RSA key
    // — served on ITS OWN port (the unlock server is a per-request listener).
    const page = await req({ port: Number(unlockUrl.port), path: unlockUrl.pathname + unlockUrl.search });
    assert.equal(page.status, 200);
    const jwk = pubkeyOf(page.body);
    const t = unlockUrl.searchParams.get('t')!;
    const submit = await req({
      port: Number(unlockUrl.port), path: '/unlock', method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `t=${t}&p=${encPayload(jwk, { password: 'rightkey' })}`,
    });
    assert.equal(submit.json?.ok, true, submit.body);

    const d = await getT(s, '/api/dbs');
    assert.equal(d.json.databases.find((x: any) => x.alias === 'testdb').state, 'UNLOCKED');
    assert.ok(auditEvents().some((e) => e.action === 'ui.unlock' && e.result_code === 'OK'));

    // Missing DB → explicit code.
    assert.equal((await postT(s, '/api/unlock', { db: 'nosuch' })).json?.code, 'DATABASE_NOT_FOUND');
  } finally {
    clearSession('testdb');
    // An un-consumed approval request keeps its own listener + timer alive —
    // cancel it so the unlock server can't outlive the test.
    if (unlockUrl)
      await req({ port: Number(unlockUrl.port), path: `/cancel?t=${unlockUrl.searchParams.get('t')}`, method: 'POST' }).catch(() => {});
    s.close();
    await s.done;
  }
});

test('hardened mode — service ops route over IPC and fail closed when the service is down', async () => {
  setCfg((c) => { c.hardened.enabled = true; });
  const s = await boot();
  try {
    // dbs still answers: states degrade to UNAVAILABLE with a service marker.
    const d = await getT(s, '/api/dbs');
    assert.equal(d.status, 200, d.body);
    assert.equal(d.json.mode, 'hardened');
    assert.equal(d.json.service.state, 'down');
    assert.match(String(d.json.service.code), /^HARDENED_/);
    assert.equal(d.json.databases[0].state, 'UNAVAILABLE');
    // Mutations propagate the hardened error explicitly — never a silent
    // in-process fallback.
    const l = await postT(s, '/api/session/lock', { db: 'testdb' });
    assert.equal(l.status, 502);
    assert.match(String(l.json.code), /^HARDENED_/);
    const a = await getT(s, '/api/audit');
    assert.equal(a.status, 502);
    assert.match(String(a.json.code), /^HARDENED_/);
  } finally { s.close(); await s.done; setCfg(); }
});

test('unlock cap — concurrent approvals are bounded (UNLOCK_BUSY)', async () => {
  setCfg();
  clearSession('testdb');
  const s = await boot(KS);
  const urls: URL[] = [];
  try {
    for (let i = 0; i < 3; i++) {
      const r = await postT(s, '/api/unlock', { db: 'testdb' });
      assert.equal(r.status, 200, `#${i}: ${r.body}`);
      urls.push(new URL(r.json.url));
    }
    const r4 = await postT(s, '/api/unlock', { db: 'testdb' });
    assert.equal(r4.status, 429);
    assert.equal(r4.json.code, 'UNLOCK_BUSY');
    // Completing one frees a slot.
    const u = urls.pop()!;
    const page = await req({ port: Number(u.port), path: u.pathname + u.search });
    const jwk = pubkeyOf(page.body);
    await req({
      port: Number(u.port), path: '/unlock', method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `t=${u.searchParams.get('t')}&p=${encPayload(jwk, { password: 'rightkey' })}`,
    });
    const r5 = await postT(s, '/api/unlock', { db: 'testdb' });
    assert.equal(r5.status, 200, r5.body);
    urls.push(new URL(r5.json.url));
  } finally {
    for (const u of urls)
      await req({ port: Number(u.port), path: `/cancel?t=${u.searchParams.get('t')}`, method: 'POST' }).catch(() => {});
    clearSession('testdb');
    s.close();
    await s.done;
  }
});

// --- stored-XSS regression (F-1) ---
// Two layers: (a) the served script must contain no dynamic-HTML sinks at
// all (structural), and (b) executing it under a DOM stub with hostile data
// must produce only fixed-name attributes — payloads stay data, never
// markup.

class StubEl {
  tagName: string; children: any[] = []; attributes: Record<string, string> = {};
  listeners: Record<string, Function[]> = {}; dataset: Record<string, string> = {};
  _text = ''; value = ''; type = ''; colSpan = 0;
  constructor(tag: string) { this.tagName = tag.toUpperCase(); }
  appendChild(c: any) { this.children.push(c); return c; }
  addEventListener(t: string, f: Function) { (this.listeners[t] ||= []).push(f); }
  setAttribute(n: string, v: string) { this.attributes[n] = v; }
  getAttribute(n: string) { return this.attributes[n]; }
  set className(v: string) { this.attributes['class'] = v; }
  get className() { return this.attributes['class'] || ''; }
  get textContent(): string { return this._text + this.children.map((c) => c.textContent ?? '').join(''); }
  set textContent(v: string) { this._text = String(v); this.children = []; }
  setAttributeNS(_ns: string, n: string, v: string) { this.attributes[n] = v; }
}

function walkAttrs(el: any, acc: string[]): string[] {
  for (const k of Object.keys(el.attributes || {})) acc.push(k);
  for (const c of el.children || []) if (c.attributes) walkAttrs(c, acc);
  return acc;
}
function walkTags(el: any, acc: string[]): string[] {
  acc.push(el.tagName);
  for (const c of el.children || []) if (c.tagName) walkTags(c, acc);
  return acc;
}

test('shutdown — POST /api/shutdown resolves done and closes the listener', async () => {
  const s = await boot();
  const r = await postT(s, '/api/shutdown', {});
  assert.equal(r.status, 200);
  const end = await s.done;
  assert.equal(end.code, 'UI_SHUTDOWN');
  // The listener is gone.
  await assert.rejects(get(s, '/api/dbs'));
});

test('stored-XSS — page script has no dynamic-HTML sinks; hostile data stays inert', async () => {
  const s = await boot();
  try {
    // Fetch the page with the one-time launch token.
    const body = (await req({ port: s.port, path: '/?t=' + new URL(s.url).searchParams.get('t') })).body;
    const m = body.match(/<script>([\s\S]*)<\/script>/);
    assert.ok(m, 'served page must contain the inline script');
    const script = m![1];
    // (a) structural: no HTML-parsing sinks anywhere in the script
    // (usage patterns, not comment mentions).
    for (const sink of [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML\s*\(/, /document\.write(ln)?\s*\(/, /\beval\s*\(/])
      assert.ok(!sink.test(script), `page script must not use ${sink}`);

    // (b) execute under a DOM stub with hostile payloads.
    const payload = 'x" autofocus onfocus=globalThis.PWNED=1 y="';
    const byId = new Map<string, StubEl>();
    for (const id of ['msg', 'mode-badge', 'dbs-body', 'auth-body', 'audit-body', 'agents-list',
      'f-agent', 'f-action', 'f-limit', 'new-agent-name', 'btn-agent-new',
      'btn-dbs-reload', 'btn-audit-reload', 'btn-shutdown'])
      byId.set(id, new StubEl('div'));
    byId.get('f-limit')!.value = '100';
    const doc = {
      getElementById: (id: string) => byId.get(id) ?? null,
      createElement: (t: string) => new StubEl(t),
      createTextNode: (t: string) => ({ textContent: t }),
    };
    const responses: Record<string, any> = {
      '/api/dbs': { ok: true, mode: 'standard', databases: [
        { alias: payload, path: `/p/${payload}`, exists: true, default: true, state: 'UNLOCKED', key_file: false, unlock_method: 'local-web', session_timeout: 900 }] },
      '/api/audit': { ok: true, events: [
        { ts: payload, agent: payload, action: 'login', target: payload, decision: 'allow', result_code: 'OK', db: payload }] },
      '/api/agents': { ok: true, agents: { 'a"gent': { allowed: [payload, 'search'] } } },
    };
    const fetchStub = async (path: string) => {
      const key = Object.keys(responses).find((k) => path.startsWith(k));
      return { status: 200, json: async () => key ? responses[key] : { ok: true } };
    };
    const fn = new Function('document', 'window', 'fetch', 'confirm', 'setTimeout', script);
    fn(doc, { open: () => {} }, fetchStub, () => true, setTimeout);
    // let loadDbs/loadAudit/loadAgents settle
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));

    const rendered = ['dbs-body', 'audit-body', 'auth-body', 'agents-list'].map((id) => byId.get(id)!);
    // The payload landed — but only as inert data.
    const dbsBody = byId.get('dbs-body')!;
    assert.ok(dbsBody.textContent.includes('autofocus'), 'hostile alias should render as text');
    const attrNames = rendered.flatMap((r) => walkAttrs(r, []));
    const tagNames = rendered.flatMap((r) => walkTags(r, []));
    const SAFE_ATTRS = new Set(['class', 'type', 'colspan', 'value', 'id', 'for', 'placeholder',
      'inputmode', 'style', 'href', 'target', 'rel', 'aria-live', 'data-field']);
    for (const a of attrNames) {
      assert.ok(SAFE_ATTRS.has(a), `injected attribute name escaped into DOM: ${a}`);
      assert.ok(!/^on/i.test(a), `event-handler attribute injected: ${a}`);
    }
    for (const t of tagNames)
      assert.ok(!['SCRIPT', 'IMG', 'IFRAME', 'SVG', 'OBJECT', 'EMBED', 'LINK', 'META'].includes(t), `injected element: ${t}`);
    // No injected event listeners beyond the fixed set registered by code.
    for (const r of rendered) {
      const stack: any[] = [r];
      while (stack.length) {
        const e = stack.pop();
        for (const k of Object.keys(e.listeners || {})) assert.equal(k, 'click');
        stack.push(...(e.children || []).filter((c: any) => c.listeners));
      }
    }
    // The payload survives as a literal input value (data, never markup).
    const agentInputs = (function findAll(e: any, out: any[] = []): any[] {
      if (e.tagName === 'INPUT') out.push(e);
      for (const c of e.children || []) findAll(c, out);
      return out;
    })(byId.get('agents-list'));
    assert.ok(agentInputs.some((i) => i.value.includes('autofocus')), 'policy item must land in input.value verbatim');
  } finally { s.close(); await s.done; }
});

// Safety net: if any test failed mid-way, no listeners outlive the file.
process.on('beforeExit', () => { for (const s of servers) s.close(); });
