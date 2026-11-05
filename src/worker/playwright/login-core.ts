// Browser-login orchestration — pure control flow over an injected page
// driver ({navigate, inspect, fill, submit, sessionCookieCount}), so the
// policy rules are testable without Chrome. The driver performs CDP I/O;
// this module owns the security decisions:
//
//   Redirect contract — credentials are typed ONLY while the page origin
//     equals the entry URL's origin. Post-navigation origin drift, a
//     cross-origin <form action>, or an origin change caught by the
//     in-page guard at fill/submit time all fail REDIRECT_REJECTED before
//     (or instead of) the secret being entered. SSO/OAuth redirect chains
//     that leave the entry origin are therefore out of scope by policy —
//     extending them needs an explicit allowed-domain list (follow-up).
//
//   Success determination — reported as `authenticated_via:<signal>`:
//     url_change  same-origin navigation away from the login-shaped URL
//     marker      logged-in markers (logout link, account UI) appeared
//     cookie      a new HttpOnly cookie appeared for the entry origin
//   (url_change/marker are weak site-controlled heuristics — only `cookie`
//   is strong server-side evidence; a pre-existing cookie jar alone is
//   downgraded to WORKER_OUTCOME_UNCERTAIN, never success).
//   CREDENTIALS_REJECTED when the page reports invalid credentials.
//   WORKER_MFA_REQUIRED when MFA is detected and the user does not finish
//     it inside mfaWaitMs — the page is left open for manual completion.
//
//   Retry — one extra attempt for transport faults only
//     (WORKER_NAVIGATION_FAILED / WORKER_CDP_* / WORKER_ERROR);
//     CREDENTIALS_REJECTED, REDIRECT_REJECTED, WORKER_NO_LOGIN_FORM and
//     WORKER_MFA_REQUIRED are terminal answers, not retryable errors.

export interface InspectState {
  url: string;
  hasPassword: boolean;
  hasUser?: boolean;
  /** Resolved origins of every submit destination (form action + formaction overrides). */
  formActionOrigins?: string[];
  mfa?: boolean;
  error?: boolean;
  marker?: boolean;
}

export interface FillResult { user?: boolean; pass?: boolean; originMismatch?: string }
export interface SubmitResult { how?: string; originMismatch?: string }

export interface LoginDriver {
  navigate(url: string): Promise<void>;
  inspect(): Promise<InspectState>;
  fill(username: string, password: string, origin: string): Promise<FillResult>;
  submit(origin: string): Promise<SubmitResult>;
  sessionCookieCount(origin: string): Promise<number>;
}

export interface LoginInput { url: string; username?: string; password: string }
export interface LoginResult {
  ok: boolean;
  status?: string;
  code?: string;
  detail?: string;
}

export interface LoginOpts {
  settleMs?: number;
  outcomeWaitMs?: number;
  mfaWaitMs?: number;
  pollMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const LOGIN_PATH_RE = /login|signin|sign-in|log-in|auth|sso|oauth/i;

const RETRYABLE = new Set([
  'WORKER_NAVIGATION_FAILED', 'WORKER_CDP_ERROR', 'WORKER_CDP_UNAVAILABLE', 'WORKER_ERROR',
]);

const ok = (status: string): LoginResult => ({ ok: true, status });
const fail = (code: string, detail?: string): LoginResult =>
  ({ ok: false, code, ...(detail ? { detail: String(detail).slice(0, 200) } : {}) });

const sleep0 = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Mirror of the broker egress rule — defense in depth if run outside it. */
function urlPolicyOk(raw: string): boolean {
  try {
    const u = new URL(raw);
    const h = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:') return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]';
    return false;
  } catch { return false; }
}

function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return '?'; }
}

async function safeInspect(driver: LoginDriver): Promise<InspectState | null> {
  try { return await driver.inspect(); } catch { return null; }
}

/**
 * Positive-authentication signal from one inspect snapshot.
 * `sess*` counts only HttpOnly cookies for the entry origin — a bare new
 * cookie is weak evidence (CSRF/analytics set them freely), while a new
 * HttpOnly cookie is almost always a server-set session token.
 */
function successSignal(
  o: InspectState, entry: URL, submittedUrl: string, sessBefore: number, sessNow: number,
): string | null {
  if (o.marker) return 'marker';
  if (o.url && o.url !== submittedUrl) {
    try {
      const u = new URL(o.url);
      // Count a URL change as success only when the site kept us on the
      // entry origin — landing cross-origin post-submit is unverifiable.
      if (u.origin === entry.origin && !LOGIN_PATH_RE.test(u.pathname))
        return 'url_change';
    } catch { /* unparseable — not a signal */ }
  }
  if (sessNow > sessBefore) return 'cookie';
  return null;
}

interface Clock { now: () => number; sleep: (ms: number) => Promise<void> }

async function attempt(
  input: LoginInput, driver: LoginDriver,
  o: Required<Pick<LoginOpts, 'settleMs' | 'outcomeWaitMs' | 'mfaWaitMs' | 'pollMs'>> & Clock,
): Promise<LoginResult> {
  const entry = new URL(input.url);
  const now = o.now;

  // 1) Navigate to the entry URL.
  try { await driver.navigate(input.url); }
  catch (e) { return fail('WORKER_NAVIGATION_FAILED', e && (e as Error).message ? String((e as Error).message) : 'nav'); }

  // 2) Settle: JS redirects can fire after load — poll until the URL is
  //    stable across two inspects (or the settle budget runs out), then
  //    apply the redirect contract to the FINAL origin.
  let st: InspectState | null = null;
  let lastUrl = '';
  const settleEnd = now() + o.settleMs;
  for (;;) {
    st = await safeInspect(driver);
    if (!st || !st.url) return fail('WORKER_CDP_ERROR', 'inspect_failed');
    if (st.url === lastUrl || now() >= settleEnd) break;
    lastUrl = st.url;
    await o.sleep(o.pollMs);
  }
  let finalOrigin: string;
  try { finalOrigin = new URL(st.url).origin; } catch { return fail('WORKER_NAVIGATION_FAILED', 'bad_final_url'); }
  if (finalOrigin !== entry.origin)
    return fail('REDIRECT_REJECTED', `page origin ${hostOf(st.url)} != entry origin ${entry.host}`);

  const sessBefore = await driver.sessionCookieCount(entry.origin).catch(() => 0);

  // 3) No password field: markers/a same-origin landing URL are weak but
  //    acceptable proof; a pre-existing cookie jar alone is NOT (any shared
  //    context can carry stale session cookies — downgraded to uncertain).
  if (!st.hasPassword) {
    const via = st.marker ? 'marker' :
      (!LOGIN_PATH_RE.test(new URL(st.url).pathname) && st.url !== input.url ? 'url_change' : null);
    if (via) return ok(`authenticated_via:${via}`);
    if (sessBefore > 0)
      return fail('WORKER_OUTCOME_UNCERTAIN', 'existing session cookies but no live auth signal');
    return fail('WORKER_NO_LOGIN_FORM', 'no password field and no authenticated markers');
  }

  // 4) Every submit destination — form action AND any formaction override —
  //    must post back to the entry origin; a cross-origin one would
  //    exfiltrate the credentials at submit time.
  const foreignAction = (st.formActionOrigins || []).find((o) => o !== entry.origin);
  if (foreignAction)
    return fail('REDIRECT_REJECTED', `submit destination ${foreignAction} != entry origin ${entry.origin}`);

  // 5) Fill — the in-page guard re-checks the origin atomically at type
  //    time, so a racing redirect cannot smuggle the secret.
  let fillRes: FillResult | undefined;
  try { fillRes = await driver.fill(input.username || '', input.password, entry.origin); }
  catch { return fail('WORKER_CDP_ERROR', 'fill_failed'); }
  if (fillRes?.originMismatch)
    return fail('REDIRECT_REJECTED', `origin drifted to ${hostOf(fillRes.originMismatch)} before fill`);
  if (!fillRes?.pass) return fail('WORKER_NO_LOGIN_FORM', 'password field gone at fill time');

  // 6) Submit (same in-page origin guard).
  let sub: SubmitResult | undefined;
  try { sub = await driver.submit(entry.origin); }
  catch { return fail('WORKER_CDP_ERROR', 'submit_failed'); }
  if (sub?.originMismatch)
    return fail('REDIRECT_REJECTED', `origin drifted to ${hostOf(sub.originMismatch)} before submit`);
  if (!sub || sub.how === 'none') return fail('WORKER_CDP_ERROR', 'no_submit_path');

  // 7) Outcome polling: error → credentials rejected; success signals →
  //    authenticated; MFA → keep polling inside the MFA budget (the page is
  //    left open so the user can complete it manually); else uncertain.
  const submittedUrl = st.url;
  let deadline = now() + o.outcomeWaitMs;
  let mfaSeen = false;
  for (;;) {
    await o.sleep(o.pollMs);
    const cur = await safeInspect(driver);
    if (!cur) return fail('WORKER_CDP_ERROR', 'inspect_failed_post_submit');
    if (cur.error) return fail('CREDENTIALS_REJECTED', 'site reported invalid credentials');
    const sessNow = await driver.sessionCookieCount(entry.origin).catch(() => 0);
    const sig = successSignal(cur, entry, submittedUrl, sessBefore, sessNow);
    if (sig) return ok(`authenticated_via:${sig}${mfaSeen ? '+mfa' : ''}`);
    if (cur.mfa && !mfaSeen) {
      mfaSeen = true;
      deadline = now() + o.mfaWaitMs; // user-completion budget
    }
    if (now() >= deadline) break;
  }
  return mfaSeen
    ? fail('WORKER_MFA_REQUIRED', 'mfa detected — page left open for user completion; re-run after finishing')
    : fail('WORKER_OUTCOME_UNCERTAIN', 'no success/rejection signal before deadline');
}

/**
 * Run the login flow against an injected driver. One extra attempt for
 * retryable transport faults; deterministic answers are final.
 */
export async function runBrowserLogin(
  input: LoginInput, driver: LoginDriver, opts: LoginOpts = {},
): Promise<LoginResult> {
  if (!input || typeof input.url !== 'string' || !input.url)
    return fail('NO_URL');
  if (!urlPolicyOk(input.url))
    return fail('WORKER_EGRESS_REJECTED', 'entry url fails worker egress policy');
  const o = {
    settleMs: clamp(opts.settleMs, 3_000, 200, 15_000),
    outcomeWaitMs: clamp(opts.outcomeWaitMs, 20_000, 500, 60_000),
    mfaWaitMs: clamp(opts.mfaWaitMs, 60_000, 1_000, 90_000),
    pollMs: clamp(opts.pollMs, 500, 50, 5_000),
    sleep: opts.sleep || sleep0,
    now: opts.now || Date.now,
  };
  const r = await attempt(input, driver, o);
  if (r.ok || !RETRYABLE.has(r.code!)) return r;
  return attempt(input, driver, o);
}

function clamp(v: number | undefined, dflt: number, lo: number, hi: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}
