// CDP page driver for the browser-login worker — drives one attached target
// (page) inside an isolated browser context over the generic client in
// src/cdp/client.ts. Exposes the small op set login-core.ts orchestrates:
// navigate / inspect / fill / submit / sessionCookieCount. All page state
// is read through Runtime.evaluate; credentials reach the page only as
// function arguments on the wire (their intended destination), never stdout.

import { openCdpPage, closeCdpPage, type CdpConnection, type CdpPage } from '../../cdp/client.ts';
import type { InspectState, FillResult, SubmitResult, LoginDriver } from './login-core.ts';

// In-page sources carry a /*marker*/ comment so test doubles can route
// evaluations without depending on the exact JS text. They are exported so
// tests can run them verbatim against a stub DOM (tests/unit/browser-login).

// Snapshot of everything login-core needs: URL, form presence, submit
// destinations, MFA markers, credential-error markers, logged-in markers.
export const INSPECT_SRC = `() => { /*inspect*/
  const vis = (el) => !!(el && (el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length)));
  const inputs = [...document.querySelectorAll('input')].filter(vis);
  const sig = (el) => [el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute('aria-label')].filter(Boolean).join(' ').toLowerCase();
  const pw = inputs.filter((el) => (el.type || '').toLowerCase() === 'password');
  const users = inputs.filter((el) => {
    const t = (el.type || 'text').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'password', 'image', 'reset'].includes(t)) return false;
    return /user|email|login|account/.test(sig(el)) || t === 'email' || t === 'text' || t === 'tel';
  });
  // el.form is the IDL *form owner* — it honors form= attribute
  // association, so a control linked to an external form by id is covered
  // even though closest('form') would miss it. All action URLs resolve
  // against document.baseURI, matching real submission (<base href> can
  // differ from location.href — resolving against the page URL was F-2's
  // confirmed bypass B).
  const owner = pw[0] && pw[0].form;
  const resolveDest = (raw) => { try { return new URL(raw || location.href, document.baseURI).origin; } catch { return null; } };
  const actions = new Set();
  if (owner) actions.add(resolveDest(owner.getAttribute('action')));
  // Every submit-capable control in the document: a formaction override or
  // its own form owner's action — any cross-origin destination is fatal.
  for (const el of document.querySelectorAll('button, input[type=submit], input[type=image]')) {
    try {
      const fa = el.getAttribute('formaction');
      if (fa) actions.add(resolveDest(fa));
      else if (el.form) actions.add(resolveDest(el.form.getAttribute('action')));
    } catch {}
  }
  actions.delete(null);
  const mfaInput = inputs.some((el) => /otp|totp|2fa|mfa|one[-_ ]?time|verification|auth[-_ ]?code|security[-_ ]?code|인증/.test(sig(el)));
  const text = ((document.body && document.body.innerText) || '').slice(0, 4000).toLowerCase();
  const mfa = mfaInput || /(two[- ]factor|verification code|one[- ]time (code|password|passcode)|authenticator code|인증 ?코드|인증번호)/.test(text);
  const error = /(incorrect|wrong|invalid)[^\\n]{0,30}(password|credential|passcode)|(password|credential)[^\\n]{0,30}(incorrect|wrong|invalid)|(log ?in|sign ?in|authentication)[^\\n]{0,20}(failed|error)|비밀번호가 (일치하지|올바르지)|아이디 또는 비밀번호/.test(text);
  const marker = !!document.querySelector('a[href*="logout" i], a[href*="signout" i], [class*="avatar" i], [class*="account-menu" i]')
    || /(log ?out|sign ?out|my account|로그아웃|내 ?계정)/.test(text);
  return { url: location.href, hasPassword: pw.length > 0, hasUser: users.length > 0, formActionOrigins: [...actions], mfa, error, marker };
}`;

// Fill username/password via the native setter so React/Vue controlled
// inputs register the change, then real input/change events. Refuses to
// type anything when the page origin drifted from the entry origin —
// a JS redirect racing the fill cannot smuggle credentials cross-origin.
const FILL_SRC = `([u, p, expectedOrigin]) => { /*fill*/
  if (location.origin !== expectedOrigin) return { originMismatch: location.origin };
  const vis = (el) => !!(el && (el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length)));
  const inputs = [...document.querySelectorAll('input')].filter(vis);
  const sig = (el) => [el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute('aria-label')].filter(Boolean).join(' ').toLowerCase();
  const pw = inputs.filter((el) => (el.type || '').toLowerCase() === 'password')[0];
  const user = inputs.filter((el) => {
    const t = (el.type || 'text').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'password', 'image', 'reset'].includes(t)) return false;
    return /user|email|login|account/.test(sig(el)) || t === 'email' || t === 'text' || t === 'tel';
  })[0];
  const set = (el, v) => {
    const proto = Object.getPrototypeOf(el);
    const d = Object.getOwnPropertyDescriptor(proto, 'value');
    if (d && d.set) d.set.call(el, v); else el.value = v;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (user) set(user, u);
  if (pw) set(pw, p);
  if (pw) pw.focus();
  return { user: !!user, pass: !!pw };
}`;

// Submit preference order: click a real submit/login button (dispatches the
// site's click+submit handlers), then form.requestSubmit (fires validation
// + submit events), then a synthesized Enter keydown on the password field
// for JS-driven forms without a <form>. Same origin guard as fill.
export const SUBMIT_SRC = `([expectedOrigin]) => { /*submit*/
  if (location.origin !== expectedOrigin) return { originMismatch: location.origin };
  const vis = (el) => !!(el && (el.offsetWidth || el.offsetHeight || (el.getClientRects && el.getClientRects().length)));
  const pw = document.querySelector('input[type=password]');
  // IDL form owner — covers both ancestor forms and form= attribute
  // association (closest('form') misses the latter; F-2 bypass A).
  const owner = pw && pw.form;
  // Effective submit destination of a control: formaction override → its
  // own form owner's action → (none). Resolution uses document.baseURI —
  // the actual submission base — not location.href (F-2 bypass B). A
  // control with no owner submits nothing; null means "not applicable".
  const destOf = (el) => {
    try {
      const fa = el && el.getAttribute && el.getAttribute('formaction');
      if (fa) return new URL(fa, document.baseURI).origin;
      const f = el && el.form;
      if (f) return new URL(f.getAttribute('action') || location.href, document.baseURI).origin;
      return null;
    } catch { return null; }
  };
  // owner.elements includes form=-associated controls outside the form's
  // subtree — exactly the elements a form=-linked submit button lives in.
  const els = owner ? [...owner.elements] : [...document.querySelectorAll('button, input')];
  const isSubmitter = (el) => {
    if (el.tagName === 'BUTTON') return (el.type || 'submit').toLowerCase() === 'submit';
    if (el.tagName === 'INPUT') { const t = (el.type || '').toLowerCase(); return t === 'submit' || t === 'image'; }
    return false;
  };
  let btn = els.filter((el) => isSubmitter(el) && vis(el))[0];
  if (!btn) btn = els.filter(vis)
    .filter((el) => /log ?in|sign ?in|submit|continue|next|로그인/i.test((el.value || '') + ' ' + (el.textContent || '')))[0];
  if (!btn) btn = [...document.querySelectorAll('button, input[type=button], a[role=button], [role=button]')].filter(vis)
    .filter((el) => /log ?in|sign ?in|submit|continue|next|로그인/i.test((el.value || '') + ' ' + (el.textContent || '')))[0];
  if (btn) {
    const dest = destOf(btn);
    if (dest && dest !== expectedOrigin) return { originMismatch: dest };
    btn.click();
    return { how: 'clicked' };
  }
  if (owner) {
    const dest = destOf(pw); // owner's action via pw.form — no formaction on password inputs
    if (dest && dest !== expectedOrigin) return { originMismatch: dest };
    try { if (owner.requestSubmit) owner.requestSubmit(); else owner.submit(); return { how: 'submitted' }; } catch {}
  }
  if (pw) {
    for (const t of ['keydown', 'keypress', 'keyup'])
      pw.dispatchEvent(new KeyboardEvent(t, { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
    return { how: 'enter' };
  }
  return { how: 'none' };
}`;

// Best-effort secret hygiene before we detach: blank every password field
// so the secret does not linger in a page we leave open (success session,
// MFA completion page).
const CLEAR_SRC = `() => { /*clear*/
  const set = (el, v) => {
    const proto = Object.getPrototypeOf(el);
    const d = Object.getOwnPropertyDescriptor(proto, 'value');
    if (d && d.set) d.set.call(el, v); else el.value = v;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  for (const el of [...document.querySelectorAll('input[type=password]')]) set(el, '');
  return true;
}`;

export interface BrowserDriver extends LoginDriver {
  endpoint: string;
  page: CdpPage;
  conn: CdpConnection;
  sessionId: string;
  inspect(): Promise<InspectState>;
  fill(u: string, p: string, origin: string): Promise<FillResult>;
  submit(origin: string): Promise<SubmitResult>;
  sessionCookieCount(origin: string): Promise<number>;
  /** Best-effort — blank password fields before the page is left open. */
  clearPasswordField(): Promise<void>;
  /** Failure-path teardown — close tab + dispose the isolated context. */
  dispose(): Promise<void>;
  /** Success path — leave page/context alive (session + user MFA), drop our socket. */
  detach(): void;
}

function withTimeout<T>(promise: Promise<T>, ms: number, code: string): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise<T>((_, rej) => { t = setTimeout(() => rej(new Error(code)), ms); }),
  ]);
}

/**
 * Attach to an isolated page on a loopback CDP endpoint and return the
 * driver login-core orchestrates. Throws on connect/attach failure —
 * callers map that to WORKER_CDP_UNAVAILABLE.
 */
export async function createCdpDriver({
  endpoint, isolated = true, navTimeoutMs = 20_000, evalTimeoutMs = 10_000,
}: {
  endpoint: string; isolated?: boolean; navTimeoutMs?: number; evalTimeoutMs?: number;
}): Promise<BrowserDriver> {
  const page = await openCdpPage(endpoint, { timeoutMs: 10_000, isolated });
  const { conn, sessionId } = page;
  await conn.call('Page.enable', {}, sessionId);
  await conn.call('Runtime.enable', {}, sessionId);
  await conn.call('Network.enable', {}, sessionId);

  const evaluate = async (fnSrc: string, args: unknown[] = []): Promise<any> => {
    const r = await withTimeout(conn.call('Runtime.evaluate', {
      expression: `(${fnSrc})(${JSON.stringify(args)})`,
      returnByValue: true, awaitPromise: true,
    }, sessionId), evalTimeoutMs, 'CDP_EVAL_TIMEOUT');
    if (r?.exceptionDetails) throw new Error('PAGE_EVAL_FAILED');
    return r?.result?.value;
  };

  return {
    endpoint,
    page,
    conn,
    sessionId,
    /** Page.navigate + best-effort loadEvent wait; errorText → throw. */
    async navigate(url: string) {
      const loaded = conn.waitEvent('Page.loadEventFired', sessionId, navTimeoutMs).catch(() => {});
      const r = await withTimeout(conn.call('Page.navigate', { url }, sessionId), navTimeoutMs, 'CDP_NAV_TIMEOUT');
      if (r?.errorText) throw new Error(String(r.errorText).slice(0, 100));
      await loaded;
    },
    inspect() { return evaluate(INSPECT_SRC); },
    fill(username, password, origin) { return evaluate(FILL_SRC, [username, password, origin]); },
    submit(origin) { return evaluate(SUBMIT_SRC, [origin]); },
    /**
     * Count of HttpOnly cookies visible to this page's context for `origin`.
     * HttpOnly cookies can only be set by the server — a new one after
     * submit is the strongest cookie-side session signal.
     */
    async sessionCookieCount(origin) {
      const r = await conn.call('Network.getCookies', { urls: [origin] }, sessionId).catch(() => null);
      return Array.isArray(r?.cookies) ? r.cookies.filter((c: any) => c.httpOnly).length : 0;
    },
    async clearPasswordField() { await evaluate(CLEAR_SRC).catch(() => {}); },
    async dispose() { await closeCdpPage(page); },
    detach() { conn.close(); },
  };
}
