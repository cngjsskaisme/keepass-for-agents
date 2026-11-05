// PR-09 — browser-login (playwright worker) tests.
// Part A: login-core orchestration against a fake driver (no Chrome).
// Part B: the real browser-login.mjs through pipeSecretToWorker against a
// mock CDP server (fake Chrome: /json/version + WebSocket + flat protocol).
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { runBrowserLogin, type InspectState, type LoginDriver } from '../../src/worker/playwright/login-core.ts';
import { INSPECT_SRC, SUBMIT_SRC } from '../../src/worker/playwright/cdp-driver.ts';
import { pipeSecretToWorker } from '../../src/broker/broker.ts';
import { resolveWorker } from '../../src/worker/registry.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { normalize, saveConfig, loadConfig, validateConfig, SESSION_DIR, type AppConfig } from '../../src/config/config.ts';
// @ts-expect-error — JS fixture, untyped by design
import { startMockCdp } from '../fixtures/mock-cdp.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const WORKER = join(__dir, '..', '..', 'src', 'worker', 'playwright', 'browser-login.mjs');
const ENTRY = 'https://site.example/login';
const ORIGIN = 'https://site.example';

const MOCK = join(TEST_HOME, 'mock-kpscript-blog.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: bad key');process.exit(1)}
if(args.includes('-Field:Password'))process.stdout.write('s3cr3t\\n');
process.exit(0)})`);
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

// ---------- Part A: login-core with a fake driver ----------

function mkClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => { t += ms; } };
}

interface FakeDriver extends LoginDriver {
  calls: { navigate: number; inspect: number; fill: number; submit: number };
  navFails: number;
  submitted: boolean;
  fillArgs: [string, string, string] | null;
  inspectFn: (d: FakeDriver) => InspectState;
  cookiesFn?: (d: FakeDriver) => number;
}

function fakeDriver(over: Partial<FakeDriver> = {}): FakeDriver {
  const d = {
    calls: { navigate: 0, inspect: 0, fill: 0, submit: 0 },
    navFails: 0,
    submitted: false,
    fillArgs: null as [string, string, string] | null,
    inspectFn: () => ({ url: ENTRY, hasPassword: true, hasUser: true }),
    cookiesFn: undefined as undefined | ((d: FakeDriver) => number),
    async navigate() { d.calls.navigate++; if (d.navFails > 0) { d.navFails--; throw new Error('net::ERR'); } },
    async inspect() { d.calls.inspect++; return d.inspectFn(d); },
    async fill(u: string, p: string, o: string) { d.calls.fill++; d.fillArgs = [u, p, o]; return { user: true, pass: true }; },
    async submit() { d.calls.submit++; d.submitted = true; return { how: 'clicked' }; },
    async sessionCookieCount() { return d.cookiesFn ? d.cookiesFn(d) : 0; },
    ...over,
  } as FakeDriver;
  return d;
}

const OPTS = { ...mkClock(), settleMs: 300, outcomeWaitMs: 1_000, mfaWaitMs: 500, pollMs: 50 };
const IN = { url: ENTRY, username: 'agent1', password: 's3cr3t' };

test('redirect contract — cross-origin landing rejected, fill never called', async () => {
  const d = fakeDriver({ inspectFn: () => ({ url: 'https://evil.example/phish', hasPassword: true }) });
  const r = await runBrowserLogin(IN, d, { ...mkClock(), settleMs: 300, pollMs: 50 });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'REDIRECT_REJECTED');
  assert.equal(d.calls.fill, 0, 'credentials must never reach a foreign origin');
});

test('redirect contract — cross-origin form action rejected before fill', async () => {
  const d = fakeDriver({
    inspectFn: () => ({ url: ENTRY, hasPassword: true, formActionOrigins: ['https://evil.example'] }),
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'REDIRECT_REJECTED');
  assert.equal(d.calls.fill, 0);
});

test('redirect contract — a single cross-origin formaction button is enough to reject', async () => {
  const d = fakeDriver({
    inspectFn: () => ({
      url: ENTRY, hasPassword: true,
      formActionOrigins: [ORIGIN, 'https://evil.example'],
    }),
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'REDIRECT_REJECTED');
  assert.match(r.detail!, /evil\.example/);
  assert.equal(d.calls.fill, 0);
});

test('redirect contract — same-origin formaction overrides are allowed', async () => {
  const d = fakeDriver({
    inspectFn: (s) => s.submitted
      ? { url: `${ORIGIN}/welcome`, hasPassword: false }
      : { url: ENTRY, hasPassword: true, formActionOrigins: [ORIGIN] },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
});

test('redirect contract — in-page guard catches drift at submit time', async () => {
  const d = fakeDriver({
    async submit() { d.calls.submit++; return { originMismatch: 'https://evil.example' }; },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'REDIRECT_REJECTED');
});

test('redirect contract — in-page guard catches drift at fill time', async () => {
  const d = fakeDriver({
    async fill(u, p, o) { d.calls.fill++; d.fillArgs = [u, p, o]; return { originMismatch: 'https://evil.example' }; },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'REDIRECT_REJECTED');
  assert.equal(d.calls.submit, 0);
});

test('success — url_change signal after same-origin navigation', async () => {
  const d = fakeDriver({
    inspectFn: (s) => s.submitted
      ? { url: `${ORIGIN}/welcome`, hasPassword: false }
      : { url: ENTRY, hasPassword: true, hasUser: true },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:url_change');
});

test('success — cookie signal when a new HttpOnly cookie appears', async () => {
  const d = fakeDriver({
    inspectFn: () => ({ url: ENTRY, hasPassword: true }),
    cookiesFn: (s) => (s.submitted ? 1 : 0),
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:cookie');
});

test('success — marker signal for SPA login without navigation', async () => {
  const d = fakeDriver({
    inspectFn: (s) => ({ url: ENTRY, hasPassword: !s.submitted, marker: s.submitted }),
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:marker');
});

test('session downgrade — pre-existing cookies alone are not proof (F-5)', async () => {
  // Same URL, no form, cookies present but no live signal → not success.
  const d = fakeDriver({
    inspectFn: () => ({ url: ENTRY, hasPassword: false }),
    cookiesFn: () => 2,
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'WORKER_OUTCOME_UNCERTAIN');
});

test('success — already-authenticated page (no form + live marker)', async () => {
  const d = fakeDriver({
    inspectFn: () => ({ url: `${ORIGIN}/account`, hasPassword: false, marker: true }),
    cookiesFn: () => 2,
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:marker');
});

test('rejection — credential error text is terminal, not retried', async () => {
  const d = fakeDriver({
    inspectFn: (s) => s.submitted
      ? { url: ENTRY, hasPassword: true, error: true }
      : { url: ENTRY, hasPassword: true },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'CREDENTIALS_REJECTED');
  assert.equal(d.calls.navigate, 1, 'credential rejection must not retry');
});

test('mfa — detected post-submit, budget expires → WORKER_MFA_REQUIRED', async () => {
  const d = fakeDriver({
    inspectFn: (s) => ({ url: ENTRY, hasPassword: true, mfa: s.submitted }),
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'WORKER_MFA_REQUIRED');
  assert.match(r.detail!, /left open|re-run/);
});

test('mfa — user completes inside the wait window → success', async () => {
  let polls = 0;
  const d = fakeDriver({
    inspectFn: (s) => {
      if (!s.submitted) return { url: ENTRY, hasPassword: true };
      polls++;
      return polls > 2
        ? { url: `${ORIGIN}/home`, hasPassword: false, marker: true }
        : { url: ENTRY, hasPassword: true, mfa: true };
    },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:marker+mfa');
});

test('retry — transport nav failure retried exactly once', async () => {
  const d = fakeDriver({
    navFails: 1,
    inspectFn: (s) => s.submitted
      ? { url: `${ORIGIN}/welcome`, hasPassword: false }
      : { url: ENTRY, hasPassword: true, hasUser: true },
  });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.ok, true);
  assert.equal(r.status, 'authenticated_via:url_change');
  assert.equal(d.calls.navigate, 2);
});

test('retry — persistent nav failure gives up after two attempts', async () => {
  const d = fakeDriver({ navFails: 5 });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'WORKER_NAVIGATION_FAILED');
  assert.equal(d.calls.navigate, 2);
});

test('no login form and no auth markers → WORKER_NO_LOGIN_FORM', async () => {
  const d = fakeDriver({ inspectFn: () => ({ url: `${ORIGIN}/login`, hasPassword: false }) });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'WORKER_NO_LOGIN_FORM');
});

test('uncertain outcome → WORKER_OUTCOME_UNCERTAIN', async () => {
  const d = fakeDriver({ inspectFn: () => ({ url: ENTRY, hasPassword: true }) });
  const r = await runBrowserLogin(IN, d, OPTS);
  assert.equal(r.code, 'WORKER_OUTCOME_UNCERTAIN');
});

test('input guards — NO_URL and egress policy mirrored defensively', async () => {
  const d = fakeDriver();
  assert.equal((await runBrowserLogin({ url: '', password: 'x' }, d, OPTS)).code, 'NO_URL');
  assert.equal(
    (await runBrowserLogin({ url: 'http://10.9.9.9/login', password: 'x' }, d, OPTS)).code,
    'WORKER_EGRESS_REJECTED',
  );
  assert.equal(d.calls.navigate, 0);
});

// ---------- In-page sources against a stub DOM (F-2 residual bypasses) ----------
//
// The driver ships page JS as strings — run them verbatim with a minimal
// fake document/location so the real collection/guard code is exercised,
// not a re-implementation. Supports exactly the selector shapes the
// sources use: `tag`, `tag[attr=v]`, `[attr]`, `tag[attr*="v" i]`.

class StubEvent { type: string; constructor(t: string, o?: any) { this.type = t; Object.assign(this, o); } }

function matchPart(el: any, s: string): boolean {
  const m = s.match(/^([a-z]+)?((?:\[[^\]]*\])*)$/i);
  if (!m) return false;
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  for (const am of (m[2] || '').matchAll(/\[([\w-]+)(?:(\*?)=(?:"([^"]*)"|([^\]\s]+))\s*(i)?)?\]/g)) {
    const [, name, star, qv, bv, icase] = am;
    const val = qv ?? bv;
    const actual = el.getAttribute(name);
    if (val === undefined) { if (actual == null || actual === '') return false; continue; }
    const a = String(actual ?? ''), v = String(val);
    const ok = star
      ? (icase ? a.toLowerCase().includes(v.toLowerCase()) : a.includes(v))
      : (icase ? a.toLowerCase() === v.toLowerCase() : a === v);
    if (!ok) return false;
  }
  return true;
}
const matchSel = (el: any, sel: string) => sel.split(',').some((p) => matchPart(el, p.trim()));

function mkEl(o: Record<string, any> = {}): any {
  return {
    tagName: 'INPUT', type: 'text', name: '', id: '', autocomplete: '', placeholder: '',
    offsetWidth: 1, offsetHeight: 1, value: '', textContent: '',
    _attrs: {} as Record<string, string>,
    form: null, _closest: null, clicked: false, dispatched: [] as string[],
    getClientRects() { return [1]; },
    getAttribute(n: string) { return this._attrs[n] ?? (n === 'type' ? this.type : null); },
    closest(sel: string) { return this._closest; },
    dispatchEvent(e: any) { this.dispatched.push(e.type); },
    focus() {}, click() { this.clicked = true; },
    ...o,
  };
}

function mkForm(action: string | null, elements: any[] = []): any {
  return {
    tagName: 'FORM', _attrs: action == null ? {} : { action }, elements,
    _submitted: null as string | null,
    getAttribute(n: string) { return this._attrs[n] ?? null; },
    requestSubmit() { this._submitted = 'requestSubmit'; },
    submit() { this._submitted = 'submit'; },
  };
}

function mkDom(els: any[], { baseURI, href }: { baseURI: string; href: string }) {
  const document = {
    baseURI,
    body: { innerText: '' },
    querySelectorAll: (sel: string) => els.filter((e) => matchSel(e, sel)),
    querySelector: (sel: string) => els.filter((e) => matchSel(e, sel))[0] ?? null,
  };
  const location = { href, origin: new URL(href).origin };
  return { document, location };
}

/** Evaluate an exported in-page source exactly like Runtime.evaluate does. */
function evalSrc(src: string, args: unknown[], env: { document: any; location: any }): any {
  return new Function('document', 'location', 'Event', 'KeyboardEvent',
    `return (${src})(${JSON.stringify(args)})`)(env.document, env.location, StubEvent, StubEvent);
}

test('in-page — form= attribute owner reconnection collects the owner action (F-2 bypass A)', () => {
  // <input type=password form=evil> + <button type=submit form=evil>:
  // no lexical ancestor form, but el.form resolves to the #evil form.
  const evil = mkForm('https://evil.example/collect');
  const pw = mkEl({ type: 'password', form: evil, _attrs: { form: 'evil' }, _closest: null });
  const btn = mkEl({ tagName: 'BUTTON', type: 'submit', textContent: 'Log in', form: evil, _attrs: { form: 'evil' } });
  evil.elements = [pw, btn];
  const env = mkDom([pw, btn, evil], { baseURI: ENTRY, href: ENTRY });
  const st = evalSrc(INSPECT_SRC, [], env);
  assert.ok(st.formActionOrigins.includes('https://evil.example'),
    `owner form action must be collected: ${st.formActionOrigins}`);
  // The submit-path guard must catch it too — destination via btn.form.
  const sub = evalSrc(SUBMIT_SRC, [ORIGIN], env);
  assert.equal(sub.originMismatch, 'https://evil.example');
  assert.equal(btn.clicked, false, 'a foreign-destination button must never be clicked');
});

test('in-page — <base href> mismatch: actions resolve against baseURI (F-2 bypass B)', () => {
  const f = mkForm('collect'); // relative action + evil <base> → foreign dest
  const pw = mkEl({ type: 'password', form: f, _closest: f });
  f.elements = [pw];
  const env = mkDom([pw, f], { baseURI: 'https://evil.example/', href: ENTRY });
  const st = evalSrc(INSPECT_SRC, [], env);
  assert.ok(st.formActionOrigins.includes('https://evil.example'),
    `relative action must resolve against document.baseURI: ${st.formActionOrigins}`);
  // And a same-origin base must not false-positive.
  const env2 = mkDom([pw, f], { baseURI: ORIGIN + '/dir/', href: ENTRY });
  const st2 = evalSrc(INSPECT_SRC, [], env2);
  assert.deepEqual(st2.formActionOrigins, [ORIGIN]);
});

test('in-page — submit-path destOf: formaction override wins, then owner action, all via baseURI', () => {
  const f = mkForm('/login');
  const pw = mkEl({ type: 'password', form: f, _closest: f });
  const btn = mkEl({ tagName: 'BUTTON', type: 'submit', textContent: 'Log in', form: f, _attrs: { formaction: 'https://evil.example/x' } });
  f.elements = [pw, btn];
  const env = mkDom([pw, btn, f], { baseURI: ENTRY, href: ENTRY });
  const sub = evalSrc(SUBMIT_SRC, [ORIGIN], env);
  assert.equal(sub.originMismatch, 'https://evil.example');
  assert.equal(btn.clicked, false);
});

test('in-page — requestSubmit path checks the owner action via pw.form', () => {
  const evil = mkForm('https://evil.example/collect');
  const pw = mkEl({ type: 'password', form: evil });
  evil.elements = [pw]; // no buttons at all → requestSubmit path
  const env = mkDom([pw, evil], { baseURI: ENTRY, href: ENTRY });
  const sub = evalSrc(SUBMIT_SRC, [ORIGIN], env);
  assert.equal(sub.originMismatch, 'https://evil.example');
  assert.equal(evil._submitted, null);
});

test('in-page — normal same-origin form submits (control case)', () => {
  const f = mkForm('/do-login');
  const pw = mkEl({ type: 'password', form: f, _closest: f });
  const btn = mkEl({ tagName: 'BUTTON', type: 'submit', textContent: 'Log in', form: f });
  f.elements = [pw, btn];
  const env = mkDom([pw, btn, f], { baseURI: ENTRY, href: ENTRY });
  const st = evalSrc(INSPECT_SRC, [], env);
  assert.deepEqual(st.formActionOrigins, [ORIGIN]);
  const sub = evalSrc(SUBMIT_SRC, [ORIGIN], env);
  assert.equal(sub.how, 'clicked');
  assert.equal(btn.clicked, true);
});

// ---------- Part B: full path — broker → browser-login.mjs → mock CDP ----------

const DB = { path: 'C:/fake/test.kdbx' };
const FAST = { settleMs: '150', pollMs: '30', outcomeWaitMs: '900', mfaWaitMs: '400' };

async function pipeToBrowserWorker(alias: string, meta: Record<string, string>) {
  await saveSession(alias, 'rightkey', 300);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], alias, DB, 'UUID-1',
    [process.execPath, WORKER], [], meta,
  );
  clearSession(alias);
  return r;
}

test('e2e — isolated-context login succeeds via url_change through the broker', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => s.submitted
      ? { url: `${ORIGIN}/welcome`, hasPassword: false }
      : { url: ENTRY, hasPassword: true, hasUser: true },
    cookies: (s: any) => (s.submitted ? [{ name: 'sid', httpOnly: true }] : []),
  });
  try {
    const r = await pipeToBrowserWorker('bl-ok', {
      db: 'bl-ok', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.ok, true);
    assert.equal(r.detail, 'authenticated_via:url_change');
    // Isolated context used → createBrowserContext happened; page left open
    // (session handle) → no closeTarget/dispose on success.
    const methods = mock.state.calls.map((c: any) => c.method);
    assert.ok(methods.includes('Target.createBrowserContext'));
    assert.ok(!methods.includes('Target.closeTarget'), 'success path keeps the session page alive');
    // Credentials reached the page, scoped to the entry origin — and the
    // password field was blanked before detach (F-4).
    assert.deepEqual(mock.state.fillArgs, ['agent1', 's3cr3t', ORIGIN]);
    assert.equal(mock.state.clearedPw, true, 'password field must be cleared before detach');
  } finally { await mock.close(); }
});

test('e2e — cross-origin redirect is rejected before any credential is filled', async () => {
  const mock = await startMockCdp({
    inspect: () => ({ url: 'https://evil.example/phish', hasPassword: true }),
  });
  try {
    const r = await pipeToBrowserWorker('bl-redir', {
      db: 'bl-redir', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'REDIRECT_REJECTED');
    assert.equal(mock.state.fillArgs, null, 'fill must never run on a foreign origin');
    // Failure path tears the page/context down.
    const methods = mock.state.calls.map((c: any) => c.method);
    assert.ok(methods.includes('Target.closeTarget'));
  } finally { await mock.close(); }
});

test('e2e — credential rejection surfaces CREDENTIALS_REJECTED', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => s.submitted
      ? { url: ENTRY, hasPassword: true, error: true }
      : { url: ENTRY, hasPassword: true },
  });
  try {
    const r = await pipeToBrowserWorker('bl-bad', {
      db: 'bl-bad', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.code, 'CREDENTIALS_REJECTED');
  } finally { await mock.close(); }
});

test('e2e — MFA keeps the page open and returns WORKER_MFA_REQUIRED', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => ({ url: ENTRY, hasPassword: true, mfa: s.submitted }),
  });
  try {
    const r = await pipeToBrowserWorker('bl-mfa', {
      db: 'bl-mfa', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.code, 'WORKER_MFA_REQUIRED');
    const methods = mock.state.calls.map((c: any) => c.method);
    assert.ok(!methods.includes('Target.closeTarget'), 'MFA page must stay open for user completion');
    assert.ok(!methods.includes('Target.disposeBrowserContext'));
    assert.equal(mock.state.clearedPw, true, 'typed password must be blanked before detach');
  } finally { await mock.close(); }
});

test('e2e — cookie signal authenticates when the URL never moves', async () => {
  const mock = await startMockCdp({
    inspect: () => ({ url: ENTRY, hasPassword: true }),
    cookies: (s: any) => (s.submitted ? [{ name: 'sess', httpOnly: true }] : []),
  });
  try {
    const r = await pipeToBrowserWorker('bl-cook', {
      db: 'bl-cook', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.ok, true);
    assert.equal(r.detail, 'authenticated_via:cookie');
  } finally { await mock.close(); }
});

test('e2e — non-httpOnly cookies alone do not authenticate', async () => {
  const mock = await startMockCdp({
    inspect: () => ({ url: ENTRY, hasPassword: true }),
    cookies: (s: any) => (s.submitted ? [{ name: 'csrf', httpOnly: false }] : []),
  });
  try {
    const r = await pipeToBrowserWorker('bl-weak', {
      db: 'bl-weak', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.code, 'WORKER_OUTCOME_UNCERTAIN');
  } finally { await mock.close(); }
});

test('e2e — cross-origin formaction override is rejected before fill (F-2)', async () => {
  const mock = await startMockCdp({
    inspect: () => ({
      url: ENTRY, hasPassword: true,
      formActionOrigins: [ORIGIN, 'https://evil.example'],
    }),
  });
  try {
    const r = await pipeToBrowserWorker('bl-fa', {
      db: 'bl-fa', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: mock.endpoint, ...FAST,
    });
    assert.equal(r.code, 'REDIRECT_REJECTED');
    assert.equal(mock.state.fillArgs, null, 'fill must never run with a foreign submit destination');
  } finally { await mock.close(); }
});

test('e2e — endpoint resolution falls back to KEEPASS_AGENT_CDP_ENDPOINT', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => s.submitted
      ? { url: `${ORIGIN}/home`, hasPassword: false, marker: true }
      : { url: ENTRY, hasPassword: true },
  });
  try {
    process.env.KEEPASS_AGENT_CDP_ENDPOINT = mock.endpoint;
    const r = await pipeToBrowserWorker('bl-env', {
      db: 'bl-env', entry: 'UUID-1', username: 'agent1', url: ENTRY, ...FAST,
    });
    assert.equal(r.ok, true);
    assert.equal(r.detail, 'authenticated_via:marker');
  } finally {
    delete process.env.KEEPASS_AGENT_CDP_ENDPOINT;
    await mock.close();
  }
});

test('e2e — isolated=0 skips the isolated context (dedicated profile)', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => s.submitted
      ? { url: `${ORIGIN}/home`, hasPassword: false, marker: true }
      : { url: ENTRY, hasPassword: true },
  });
  try {
    const r = await pipeToBrowserWorker('bl-dfl', {
      db: 'bl-dfl', entry: 'UUID-1', username: 'agent1', url: ENTRY,
      cdp: mock.endpoint, isolated: '0', ...FAST,
    });
    assert.equal(r.ok, true);
    const methods = mock.state.calls.map((c: any) => c.method);
    assert.ok(!methods.includes('Target.createBrowserContext'), 'default context must not create an isolated one');
    assert.ok(methods.includes('Target.createTarget'));
  } finally { await mock.close(); }
});

test('e2e — non-loopback cdp endpoint is rejected by the worker itself', async () => {
  const r = await pipeToBrowserWorker('bl-nl', {
    db: 'bl-nl', entry: 'UUID-1', username: 'agent1', url: ENTRY,
    cdp: 'http://10.9.9.9:9222', ...FAST,
  });
  assert.equal(r.code, 'WORKER_CDP_ENDPOINT_REJECTED');
});

test('e2e — unreachable endpoint → WORKER_CDP_UNAVAILABLE after one retry', async () => {
  const mock = await startMockCdp({
    inspect: () => ({ url: ENTRY, hasPassword: true }),
  });
  const endpoint = mock.endpoint;
  await mock.close(); // nothing listening now
  const r = await pipeToBrowserWorker('bl-down', {
    db: 'bl-down', entry: 'UUID-1', username: 'agent1', url: ENTRY, cdp: endpoint, ...FAST,
  });
  assert.equal(r.code, 'WORKER_CDP_UNAVAILABLE');
});

test('e2e — env endpoint hook warns on stderr (F-1 test-hook demotion)', async () => {
  const mock = await startMockCdp({
    inspect: (s: any) => s.submitted
      ? { url: `${ORIGIN}/home`, hasPassword: false, marker: true }
      : { url: ENTRY, hasPassword: true },
  });
  try {
    // spawn (not spawnSync) — the mock server lives in this process, so the
    // parent event loop must stay unblocked for it to answer.
    const r = await new Promise<{ stdout: string; stderr: string }>((res) => {
      const c = spawn(process.execPath, [WORKER], {
        env: { ...process.env, KEEPASS_AGENT_CDP_ENDPOINT: mock.endpoint },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '';
      c.stdout.on('data', (d) => (stdout += d));
      c.stderr.on('data', (d) => (stderr += d));
      c.on('close', () => res({ stdout, stderr }));
      c.stdin.end(JSON.stringify({ url: ENTRY, username: 'agent1', password: 's3cr3t', ...FAST }));
    });
    assert.match(r.stderr, /KEEPASS_AGENT_CDP_ENDPOINT/);
    assert.match(r.stderr, /vault secrets/i);
    const j = JSON.parse(r.stdout.trim());
    assert.equal(j.success, true);
  } finally { await mock.close(); }
});

// ---------- F-1/F-3: CLI + config gates ----------

const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');
const KP_DB = join(TEST_HOME, 'bl-cfg.kdbx');
writeFileSync(KP_DB, Buffer.alloc(64, 7)); // getDb only needs the file to exist

function kpRun(args: string[], env: Record<string, string> = {}) {
  const e = { ...process.env, USERPROFILE: TEST_HOME, HOME: TEST_HOME, ...env } as any;
  delete e.KEEPASS_AGENT_ID;
  const r = spawnSync(process.execPath, [KP, ...args], { env: e, encoding: 'utf8', timeout: 30_000 });
  let json: any = null;
  try { json = JSON.parse(r.stdout.trim().split('\n').pop() || ''); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

function setCfg(mutate: (c: AppConfig) => void): void {
  const c = normalize({});
  c.databases = { testdb: { path: KP_DB } };
  c.keepass.default_database = 'testdb';
  mutate(c);
  saveConfig(c);
}

test('config — [cdp] section parses, round-trips, and validates loopback (F-1)', () => {
  const c = normalize({ cdp: { endpoint: 'http://127.0.0.1:9333', allow_default_context: true } });
  assert.equal(c.cdp.endpoint, 'http://127.0.0.1:9333');
  assert.equal(c.cdp.allow_default_context, true);
  assert.equal(validateConfig(c).length, 0);
  c.databases = { testdb: { path: KP_DB } };
  saveConfig(c);
  const back = loadConfig();
  assert.equal(back.cdp.endpoint, 'http://127.0.0.1:9333');
  assert.equal(back.cdp.allow_default_context, true);
  for (const bad of ['http://10.0.0.1:9222', 'http://evil.example:1', 'ftp://127.0.0.1']) {
    const errs = validateConfig(normalize({ cdp: { endpoint: bad } }));
    assert.ok(errs.some((e) => e.startsWith('cdp.endpoint')), bad);
  }
});

test('cli — login --cdp is rejected outright (F-1)', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['login'] } }; });
  const r = kpRun(['login', '--db', 'testdb', '--title', 'x', '--cdp', 'http://127.0.0.1:9']);
  assert.equal(r.json?.code, 'INVALID_CONFIG');
  assert.match(String(r.json?.detail), /cdp\.endpoint/);
});

test('cli — login --no-isolate requires cdp.allow_default_context (F-3)', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['login'] } }; });
  const denied = kpRun(['login', '--db', 'testdb', '--title', 'x', '--no-isolate']);
  assert.equal(denied.json?.code, 'INVALID_CONFIG');
  assert.match(String(denied.json?.detail), /allow_default_context/);
  // Operator opt-in → passes the flag gate, then hits the locked session.
  setCfg((c) => { c.agents = { default: { allowed: ['login'] } }; c.cdp = { allow_default_context: true }; });
  const ok = kpRun(['login', '--db', 'testdb', '--title', 'x', '--no-isolate']);
  assert.equal(ok.json?.code, 'UNLOCK_REQUIRED', ok.stdout);
});

test('cli — env endpoint hook warns at the kp boundary too (F-1)', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['login'] } }; });
  const r = kpRun(['login', '--db', 'testdb', '--title', 'x'],
    { KEEPASS_AGENT_CDP_ENDPOINT: 'http://127.0.0.1:1' });
  assert.match(r.stderr, /KEEPASS_AGENT_CDP_ENDPOINT/);
});

test('cli — config set cdp.* is operator-managed (CONFIG_KEY_READONLY)', () => {
  setCfg((c) => { c.agents = { default: { allowed: ['login'] } }; });
  for (const [k, v] of [['cdp.endpoint', 'http://127.0.0.1:9'], ['cdp.allow_default_context', 'true']]) {
    const r = kpRun(['config', 'set', k, v]);
    assert.equal(r.json?.code, 'CONFIG_KEY_READONLY', `${k}: ${r.stdout}`);
  }
  // And it never wrote through.
  const back = loadConfig();
  assert.equal(back.cdp.endpoint, undefined);
  assert.equal(back.cdp.allow_default_context, false);
});

test('registry — playwright worker resolves with a bounded timeout', () => {
  const w = resolveWorker('playwright');
  assert.equal(w.ok, true);
  assert.ok(w.timeoutMs! >= 60_000, 'MFA budget needs a generous cap');
  assert.ok(w.cmd![1].endsWith('browser-login.mjs'));
});
