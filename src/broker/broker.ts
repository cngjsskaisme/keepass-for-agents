// Credential Broker — trusted path: session key → CredentialProvider →
// validated secret → approved worker stdin. Secrets never appear in return
// values or logs.

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { homedir } from 'node:os';
import { basename } from 'node:path';
import { createProvider } from '../provider/provider.ts';
import { readSession } from '../security/dpapi.ts';
import { CONFIG_DIR } from '../config/config.ts';
import type { DbConfig } from '../config/config.ts';
import type { Entry } from '../provider/provider.ts';

export type { Entry } from '../provider/provider.ts';

export async function listEntries(
  kpscript: string | string[], alias: string, db: DbConfig,
): Promise<{ ok: boolean; code?: string; entries?: Entry[] }> {
  const key = await readSession(alias);
  if (key == null) return { ok: false, code: 'UNLOCK_REQUIRED' };
  return createProvider(kpscript).listEntries(db, key);
}

export function normalizeHost(url: string): string | null {
  try {
    const u = new URL(url.includes('://') ? url : 'https://' + url);
    // Same normalization as the policy engine / egress check — trailing root
    // dots collapse so `evil.com.` cannot slip past host comparisons.
    return u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.+$/, '');
  } catch { return null; }
}

export function searchEntries(entries: Entry[], q: { site?: string; username?: string; title?: string }): Entry[] {
  return entries.filter((e) => {
    if (q.title && !e.title.toLowerCase().includes(q.title.toLowerCase())) return false;
    if (q.username && !e.username.toLowerCase().includes(q.username.toLowerCase())) return false;
    if (q.site) {
      const want = normalizeHost(q.site) ?? q.site.toLowerCase();
      const host = normalizeHost(e.url);
      if (!host || (host !== want && !host.endsWith('.' + want))) return false;
    }
    return true;
  });
}

// --- Worker egress + output policy (T4/T8) ---

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/**
 * Credential-egress policy for worker requests (T4). The entry URL is the only
 * destination a worker may send credentials to:
 *   https: → any host;  http: → loopback only;  everything else → rejected.
 * pipeSecretToWorker applies this before the secret is even fetched — the
 * worker allowlist gets no exemption. `entry add` may still store such URLs
 * (intranet http sites), but `login` can never fire against them.
 */
export function checkWorkerUrl(raw: string): { ok: true } | { ok: false; code: 'WORKER_URL_REJECTED'; reason: string } {
  let u: URL;
  try { u = new URL(raw); } catch {
    return { ok: false, code: 'WORKER_URL_REJECTED', reason: 'unparseable_url' };
  }
  if (u.username || u.password)
    return { ok: false, code: 'WORKER_URL_REJECTED', reason: 'embedded_credentials' };
  const host = u.hostname.toLowerCase().replace(/\.+$/, '');
  if (u.protocol === 'https:') return { ok: true };
  if (u.protocol === 'http:')
    return LOOPBACK_HOSTS.has(host)
      ? { ok: true }
      : { ok: false, code: 'WORKER_URL_REJECTED', reason: 'http_non_loopback' };
  return { ok: false, code: 'WORKER_URL_REJECTED', reason: 'scheme_not_allowed' };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Chars tolerated between secret characters when matching: whitespace, C0,
 * DEL, C1 (\x80-\x9f), soft hyphen, combining marks (incl. CGJ), Mongolian
 * FVS, zero-width/format chars (ZWSP…\u200f, bidi controls, invisible
 * operators \u2060-\u206f), variation selectors and BOM. Keeping the class
 * this wide matters: a worker inserting \x85 or \u200b between secret
 * characters must still match — otherwise post-parse field text would
 * reassemble the secret (C1 gets stripped later; ZWSP survives visibly).
 */
const SECRET_GAP = '[\\s\\x00-\\x1f\\x7f-\\x9f\\u00ad\\u0300-\\u036f\\u034f\\u180b-\\u180f\\u200b-\\u200f\\u202a-\\u202e\\u205f-\\u206f\\ufe00-\\ufe0f\\ufeff]*';

/**
 * Replace occurrences of each secret value with [redacted], best-effort.
 * Each match is case-insensitive and tolerates invisible chars inserted
 * between secret characters (see SECRET_GAP) — so a worker cannot
 * trivially evade the filter with 'S3CR3T', 's 3 c r 3 t' or
 * 's\x853\x85c…' variants. This is a backstop: encoding-level variants
 * (base64, NFC/NFD, URL-encoding) are out of scope and documented as
 * such — workers must never echo secrets at all.
 */
function redact(text: string, secrets: readonly string[]): string {
  let s = text;
  for (const v of secrets) {
    if (!v) continue;
    const flex = [...v].map((c) => escapeRe(c)).join(SECRET_GAP);
    s = s.replace(new RegExp(flex, 'gi'), '[redacted]');
  }
  return s;
}

/** Drop C0/C1 control chars and DEL (kills ANSI/OSC escapes); keeps tab. */
function stripControl(s: string): string {
  return s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '');
}

/** Same path hygiene as the CLI's detail sanitiser — no absolute paths out. */
function scrubPaths(s: string): string {
  return s.replaceAll(CONFIG_DIR, basename(CONFIG_DIR)).replaceAll(homedir(), '~');
}

/**
 * Full hygiene pipeline for any string that can reach the caller:
 * control-char strip → secret redaction → path scrub → 200-char cap.
 * Strip runs BEFORE redact on purpose: chars removed by stripControl
 * (C1, ESC, …) can otherwise act as invisible separators — stripping
 * first collapses a fragmented secret back together so redact can match
 * it; gap-class matching then also covers non-stripped invisibles (ZWSP).
 */
function sanitizeWorkerText(s: string, secrets: readonly string[]): string {
  return scrubPaths(redact(stripControl(s), secrets)).slice(0, 200);
}

const WORKER_CODE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
/** Codes workers may emit verbatim — the local-test worker vocabulary. */
const KNOWN_WORKER_CODES = new Set([
  'NO_URL', 'WORKER_ERROR', 'CREDENTIALS_REJECTED', 'REDIRECT_REJECTED', 'LOGIN_FAILED',
]);
/** Broker/policy-generated codes a worker must not spoof. */
const BROKER_CODES = new Set([
  'WORKER_TIMEOUT', 'WORKER_SPAWN_FAILED', 'WORKER_OUTPUT_INVALID', 'WORKER_URL_REJECTED',
  'POLICY_DENIED', 'POLICY_APPROVAL_REQUIRED',
]);

/**
 * Worker-emitted code policy: a known worker code, or a custom code in the
 * `WORKER_` namespace — but never a broker-owned code or a system code
 * (UNLOCK_REQUIRED, AUTHENTICATION_FAILED, ...) that could deceive the agent.
 */
function workerCodeOk(code: string): boolean {
  if (!WORKER_CODE_RE.test(code) || BROKER_CODES.has(code)) return false;
  return KNOWN_WORKER_CODES.has(code) || code.startsWith('WORKER_');
}

/**
 * Worker result whitelist (T8): success → {success,status}; failure →
 * {success:false,code,detail}. All other fields are dropped, `code` must
 * satisfy workerCodeOk (else WORKER_OUTPUT_INVALID), and every string that
 * can reach the caller — parsed fields included, not just raw output — goes
 * through sanitizeWorkerText: redaction applies pre-parse AND post-parse so
 * JSON-escaped echoes (e.g. a password containing '"') cannot smuggle the
 * secret back out through detail/status/code.
 */
function sanitizeWorkerResult(
  rawOut: string, rawErr: string, exitCode: number | null, secrets: readonly string[],
): { ok: boolean; code?: string; detail?: string } {
  const out = redact(rawOut, secrets);
  const err = redact(rawErr, secrets);
  let parsed: any = null;
  try { const j = JSON.parse(out); if (j && typeof j === 'object') parsed = j; } catch {}
  const clean = (v: unknown): string =>
    (typeof v === 'string' && v) ? sanitizeWorkerText(v, secrets) : '';
  if (exitCode === 0 && parsed?.success === true) {
    return { ok: true, detail: clean(parsed.status) || 'ok' };
  }
  let code = 'LOGIN_FAILED';
  if (parsed?.code != null) {
    const c = clean(parsed.code);
    code = workerCodeOk(c) ? c : 'WORKER_OUTPUT_INVALID';
  }
  const detail = clean(parsed?.detail)
    || sanitizeWorkerText(err.trim(), secrets)
    || `exit ${exitCode}`;
  return { ok: false, code, detail };
}

/**
 * Kill a worker and every process it spawned. Windows: taskkill /T /F with a
 * child.kill fallback so a failed taskkill can't leave a timed-out worker
 * lingering with the secret in memory. POSIX: the worker runs detached (its
 * own process group), so kill(-pid) reaches its children.
 */
function killWorkerTree(child: ChildProcess): void {
  const pid = child.pid;
  if (pid == null) return;
  if (process.platform === 'win32') {
    try {
      const r = spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      if (r.status === 0 && !r.error) return;
    } catch {}
    try { child.kill('SIGKILL'); } catch {}
  } else {
    try { process.kill(-pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} }
  }
}

/**
 * Fetch a secret and pipe it to an approved worker's stdin.
 * The secret is validated, never returned, and wiped from the buffer after send.
 */
export async function pipeSecretToWorker(
  kpscript: string | string[], alias: string, db: DbConfig, uuid: string,
  workerCmd: string[], workerArgs: string[], meta: Record<string, string>,
  opts: {
    timeoutMs?: number;
    /**
     * Policy backstop (src/policy/engine.ts `evaluate`). When provided, runs
     * before the egress/session work; any non-'allow' decision refuses the
     * pipe with POLICY_DENIED — the CLI normally evaluates earlier for a
     * better error code, but callers who skip the CLI still get denial here.
     */
    policyGate?: () => { decision: 'allow' | 'deny' | 'require_approval'; reason: string };
  } = {},
): Promise<{ ok: boolean; code?: string; detail?: string }> {
  if (opts.policyGate) {
    const g = opts.policyGate();
    if (g.decision !== 'allow')
      return { ok: false, code: 'POLICY_DENIED', detail: (g.reason || 'policy').slice(0, 200) };
  }
  // T4: the entry URL is the worker's credential destination — reject before
  // any secret leaves the vault.
  if (meta.url) {
    const v = checkWorkerUrl(meta.url);
    if (!v.ok) return { ok: false, code: v.code, detail: v.reason };
  }
  const key = await readSession(alias);
  if (key == null) return { ok: false, code: 'UNLOCK_REQUIRED' };
  const g = await createProvider(kpscript).getSecret(db, key, uuid);
  let secret: string | undefined;
  if (!g.ok) return g.detail ? { ok: false, code: g.code, detail: g.detail } : { ok: false, code: g.code };
  secret = g.secret;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  return new Promise((resolve) => {
    const payload = JSON.stringify({ ...meta, password: secret });
    // Values the worker must never be able to reflect back to the caller —
    // kept alive until close() so stdout/stderr/detail can be redacted.
    const secrets = [secret, meta.username].filter((v): v is string => !!v);
    secret = undefined; // release local reference ASAP
    const child = spawn(workerCmd[0], workerCmd.slice(1).concat(workerArgs), {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
      // POSIX: own process group so the timeout path can SIGKILL the tree.
      detached: process.platform !== 'win32',
    });
    let out = '', err = '';
    const releaseSecrets = () => { secrets.length = 0; };
    const timer = setTimeout(() => {
      killWorkerTree(child);
      releaseSecrets();
      resolve({ ok: false, code: 'WORKER_TIMEOUT' });
    }, timeoutMs);
    child.stdout.on('data', (d) => { if (out.length < 16384) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 8192) err += d; });
    child.on('error', () => {
      clearTimeout(timer);
      releaseSecrets();
      resolve({ ok: false, code: 'WORKER_SPAWN_FAILED' });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const r = sanitizeWorkerResult(out, err, code, secrets);
      releaseSecrets();
      resolve(r);
    });
    // EPIPE — a worker that exits before reading stdin must not turn the
    // write into an uncaught stream error; 'close' still reports the result.
    child.stdin.on('error', () => {});
    child.stdin.write(payload);
    child.stdin.end();
  });
}
