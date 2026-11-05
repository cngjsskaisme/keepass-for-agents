// Local Unlock Server — loopback-only browser UI for master password entry.
// One-time request token, Host/Origin checks, no-store, attempt limits.
// Password travels POST body → broker memory → KPScript stdin. Never logged, never in URL.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { newToken } from '../security/dpapi.ts';
import { dbState, unlock, readSession } from '../master-key/manager.ts';
import { loadConfig, saveConfig, validateConfig, type AppConfig, type DbConfig } from '../config/config.ts';
import { addDb } from '../database/manager.ts';
import { createProvider } from '../provider/provider.ts';
import { getBrowserCookies, domainMatch, isLoopbackCdpEndpoint, DEFAULT_CDP_ENDPOINT } from '../cdp/cookies.ts';
import { checkWorkerUrl } from '../broker/broker.ts';
import { cp949RoundTrips } from '../keepass/kpscript.ts';
import { generateKeyPairSync, createPrivateKey, privateDecrypt, createDecipheriv, constants } from 'node:crypto';

const __dir = dirname(fileURLToPath(import.meta.url));
const UI_PATH = join(__dir, '..', '..', 'web', 'unlock-ui', 'index.html');
const ONBOARDING_PATH = join(__dir, '..', '..', 'web', 'onboarding', 'index.html');

/** Failed-auth cap per token — reaching it invalidates the pending request. */
const MAX_ATTEMPTS = 5;
/** Single source of truth for the one-time token lifetime (10 minutes). */
export const TOKEN_TTL_MS = 600_000;

export interface EntryPrefill {
  title?: string;
  url?: string;
  username?: string;
  notes?: string;
}

/**
 * Parsed submission context handed to `UnlockRequest.submissionGate` — the
 * concrete values the form actually submitted, not the ones the request
 * declared. Hardened Mode uses this to re-evaluate policy against the real
 * payload before it is applied (prefill/target drift → deny).
 */
export interface SubmissionInfo {
  mode: 'unlock' | 'create' | 'entry' | 'cookies';
  /** Effective db alias the submission will act on (page may switch it). */
  db: string;
  /** Target path (create mode). */
  path?: string;
  /** Entry-level target: id for cookies, title/url for entry adds. */
  entry?: { id?: string; title?: string; url?: string };
  /** Normalized host (cookies domain / entry url). */
  host?: string;
  /** Raw submitted field subset (entry mode) for prefill consistency checks. */
  fields?: Record<string, string>;
}

export interface UnlockRequest {
  token: string;
  db: string;
  /**
   * Declared agent identity that initiated this request (policy engine
   * attribution — self-declared, not authenticated). This is the seam by
   * which a `require_approval` policy decision routes into the web approval
   * flow: the CLI attaches the resolved agent id and the request itself is
   * the approval channel.
   */
  agent?: string;
  /**
   * Optional post-parse gate (Hardened Mode): invoked with the actual
   * submitted values right before they are applied. Returning !ok denies
   * the submission with the given code — the token stays alive (a deny is
   * not an auth failure). Standard Mode never sets this.
   */
  submissionGate?: (s: SubmissionInfo) => { ok: boolean; code?: string; detail?: string };
  mode: 'unlock' | 'create' | 'entry' | 'cookies';
  targetPath?: string;
  keyFile?: string;
  prefill?: EntryPrefill;
  entryUuid?: string;
  domain?: string;
  cdpEndpoint?: string;
  noAutoOpen?: boolean;
  rsaPub?: any;
  rsaPriv?: any;
  createdAt: number;
  expiresAt: number;
  attempts: number;
}

export interface UnlockResult {
  ok: boolean;
  code?: string;
  status?: string;
  database?: string;
  path?: string;
  uuid?: string;
  domain?: string;
  count?: number;
  /** Non-fatal warnings collected while fulfilling the request (entry add). */
  warnings?: string[];
}

// RSA-OAEP key exchange + AES-256-GCM payload encryption. Per-request RSA
// keypair — private key stays in memory; page wraps a fresh AES key with the
// public key and posts {ek.iv.ct} so passwords never travel plaintext.
function newKeyPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'jwk' },
    privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
  } as any); // node typings lack the RSA jwk-encoding overload (runtime supports it)
}

function decryptPayload(p: string, privJwk: any): Record<string, string> | null {
  try {
    const [ek, iv, ct] = p.split('.').map((x) => Buffer.from(x, 'base64url'));
    const key = privateDecrypt(
      { key: createPrivateKey({ key: privJwk, format: 'jwk' }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      ek);
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(ct.subarray(ct.length - 16));
    const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8');
    return JSON.parse(pt);
  } catch { return null; }
}

const pending = new Map<string, UnlockRequest>();

// Session-lifetime choices: value → i18n key into the page's STRINGS table
// (English text below is the server-rendered default; ko applies client-side).
const SESSION_OPTIONS: Array<[number, string, string]> = [
  [900, '15 minutes', 'sess_900'], [1800, '30 minutes', 'sess_1800'],
  [3600, '1 hour', 'sess_3600'], [7200, '2 hours', 'sess_7200'],
  [14400, '4 hours', 'sess_14400'], [28800, '8 hours', 'sess_28800'],
  [86400, '24 hours', 'sess_86400'],
];

function sessionField(current: number, suffix = '', dynamic = false): string {
  const opts = SESSION_OPTIONS.some(([v]) => v === current)
    ? SESSION_OPTIONS
    : [...SESSION_OPTIONS, [current, `Saved value (${Math.round(current / 60)} min)`, 'sess_saved'] as [number, string, string]];
  const items = opts.map(([v, label, key]) => {
    const vars = key === 'sess_saved' ? ` data-i18n-vars='${esc(JSON.stringify({ n: Math.round(v / 60) }))}'` : '';
    return `<option value="${v}" data-i18n="${key}"${vars}${v === current ? ' selected' : ''}>${label}</option>`;
  }).join('');
  const inner = `<label class="field-label" for="session_timeout${suffix}" data-i18n="field_session">Session lifetime</label>`
    + `<select id="session_timeout${suffix}" name="session_timeout">${items}</select>`;
  return dynamic ? `<div data-dynamic-lock="1">${inner}</div>` : inner;
}

// Merge configured DBs with the caller-provided map (param wins — tests and
// CLI pass an explicit subset).
function allDbs(param: Record<string, DbConfig>): Record<string, DbConfig> {
  let cfgDbs: Record<string, DbConfig> = {};
  try { cfgDbs = loadConfig().databases; } catch {}
  return { ...cfgDbs, ...param };
}

function dbSelectField(all: Record<string, DbConfig>, currentAlias: string, defaultAlias: string): string {
  const items = Object.keys(all).map((a) => {
    const isDefault = a === defaultAlias;
    const mark = isDefault ? ' · default' : '';
    const vars = esc(JSON.stringify({ a, s: dbState(a) }));
    return `<option value="${esc(a)}" data-state="${dbState(a)}" data-i18n="${isDefault ? 'db_option_default' : 'db_option'}" data-i18n-vars='${vars}'${a === currentAlias ? ' selected' : ''}>${esc(a)} — ${dbState(a)}${mark}</option>`;
  }).join('');
  return `<label class="field-label" for="db" data-i18n="field_db">Database</label><select id="db" name="db">${items}</select>`;
}

function passwordField(mode: string): string {
  if (mode === 'entry' || mode === 'cookies')
    return '<div data-dynamic-lock="1"><label class="field-label" for="master_password" data-i18n="master_password">Master password</label>'
      + '<input id="master_password" name="master_password" type="password" autocomplete="current-password"></div>';
  const ac = mode === 'create' ? 'new-password' : 'current-password';
  return `<label class="field-label" for="password" data-i18n="master_password">Master password</label>`
    + `<input id="password" name="password" type="password" autofocus autocomplete="${ac}" required>`;
}

function entryFields(p?: EntryPrefill): string {
  const f = (id: string, label: string, key: string, val: string, extra = '') =>
    `<label class="field-label" for="${id}" data-i18n="${key}">${label}</label><input id="${id}" name="${id}" value="${esc(val)}" ${extra}>`;
  return f('title', 'Title', 'field_title', p?.title || '', 'required')
    + f('username', 'Username', 'field_username', p?.username || '')
    + `<label class="field-label" for="password" data-i18n="field_password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" required>`
    + f('url', 'URL', 'field_url', p?.url || '')
    + f('notes', 'Notes', 'field_notes', p?.notes || '');
}

function collectFields(): string {
  return `<label class="field-label" for="username"><span data-i18n="field_id">ID</span> <label class="skip"><input type="checkbox" data-skip="username"><span data-i18n="skip">Skip</span></label></label>`
    + `<input id="username" name="username" autocomplete="off">`
    + `<label class="field-label" for="password"><span data-i18n="field_password">Password</span> <label class="skip"><input type="checkbox" data-skip="password"><span data-i18n="skip">Skip</span></label></label>`
    + `<input id="password" name="password" type="password" autocomplete="off">`;
}

function newDbSection(token: string, currentTimeout: number): string {
  return `<details class="newdb"><summary data-i18n="new_db">Create a new database</summary>`
    + `<form data-async>`
    + `<input type="hidden" name="t" value="${esc(token)}">`
    + `<input type="hidden" name="action" value="create">`
    + `<label class="field-label" for="new_alias" data-i18n="field_alias">Alias</label><input id="new_alias" name="new_alias" required pattern="[A-Za-z0-9_-]+">`
    + `<label class="field-label" for="new_path" data-i18n="field_path">Save path (.kdbx)</label><input id="new_path" name="new_path" required>`
    + `<label class="field-label" for="new_keyfile" data-i18n="keyfile_optional">Key file (optional)</label><input id="new_keyfile" name="new_keyfile">`
    + `<label class="field-label" for="new_password" data-i18n="master_password">Master password</label><input id="new_password" type="password" name="password" autocomplete="new-password" required>`
    + `<label class="field-label" for="new_confirmation" data-i18n="confirm_password">Confirm password</label><input id="new_confirmation" type="password" name="confirmation" autocomplete="new-password" required>`
    + sessionField(currentTimeout, '_new')
    + `<button type="submit" class="primary" data-i18n="submit_create">Create and register</button>`
    + `</form></details>`;
}

function parseSessionTimeout(raw: string): number | 'absent' | 'invalid' {
  if (!raw) return 'absent';
  const t = Number(raw);
  return Number.isInteger(t) && t >= 0 && t <= 86400 ? t : 'invalid';
}

function bodyOf(req: IncomingMessage): Promise<string> {
  return new Promise((res, rej) => {
    let d = '';
    req.on('data', (c) => { d += c; if (d.length > 8192) { rej(new Error('too large')); } });
    req.on('end', () => res(d));
    req.on('error', rej);
  });
}

function hostOk(req: IncomingMessage, cfg: AppConfig): boolean {
  const h = (req.headers.host || '').split(':')[0].toLowerCase();
  return ['127.0.0.1', 'localhost', '[::1]'].includes(h);
}

function originOk(req: IncomingMessage): boolean {
  const o = req.headers.origin;
  if (!o) return true; // form POST may omit origin
  try { return ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(o).hostname.toLowerCase()); }
  catch { return false; }
}

function secHeaders(res: ServerResponse) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
}

function html(res: ServerResponse, status: number, s: string) {
  secHeaders(res);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(s);
}

function json(res: ServerResponse, status: number, o: any) {
  secHeaders(res);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(o));
}

// Single creation path for pending requests — every request type shares the
// same TTL constant and initial state.
function newRequest(init: Omit<UnlockRequest, 'token' | 'createdAt' | 'expiresAt' | 'attempts'>): UnlockRequest {
  const now = Date.now();
  const r: UnlockRequest = {
    ...init, token: newToken(), createdAt: now, expiresAt: now + TOKEN_TTL_MS, attempts: 0,
  };
  pending.set(r.token, r);
  return r;
}

export function requestUnlock(db: string, agent?: string): UnlockRequest {
  return newRequest({ db, agent, mode: 'unlock' });
}

export function requestCreate(db: string, targetPath: string, keyFile?: string, agent?: string): UnlockRequest {
  return newRequest({ db, agent, mode: 'create', targetPath, keyFile });
}

export function requestCookieSync(db: string, entryUuid: string, domain: string, cdpEndpoint?: string, agent?: string): UnlockRequest {
  return newRequest({ db, agent, mode: 'cookies', entryUuid, domain, cdpEndpoint, noAutoOpen: true });
}

export function requestAddEntry(db: string, prefill: EntryPrefill = {}, agent?: string): UnlockRequest {
  return newRequest({ db, agent, mode: 'entry', prefill });
}

export function unlockUrl(cfg: AppConfig, req: UnlockRequest): string {
  return `http://127.0.0.1:${cfg.unlock.port}/unlock?t=${req.token}`;
}

export function openBrowser(url: string) {
  const command = process.platform === 'win32' ? 'rundll32.exe' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['url.dll,FileProtocolHandler', url] : [url];
  spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true }).unref();
}

/**
 * Serve unlock UI until `req.token` completes (resolve) or times out (reject).
 * Server lives only for the pending request duration.
 */
export function waitForUnlock(
  cfg: AppConfig, kpscript: string | string[], req: UnlockRequest, dbs: Record<string, DbConfig>,
  onReady?: (url: string) => void,
): Promise<UnlockResult> {
  // All KDBX file/credential operations go through the credential provider —
  // the kpscript array form is a test hook (same [exe, ...prefix] convention
  // as broker.ts).
  const provider = createProvider(kpscript);
  return new Promise((resolve) => {
    // Failed-auth accounting: wrong passwords and decrypt failures count.
    // Reaching MAX_ATTEMPTS invalidates the token outright — the count itself
    // is never exposed in any response (oracle minimisation).
    const countFailure = (r: UnlockRequest) => {
      r.attempts++;
      if (r.attempts >= MAX_ATTEMPTS) {
        pending.delete(r.token);
        if (r.token === req.token) finish({ ok: false, code: 'MAX_ATTEMPTS_EXCEEDED' });
      }
    };
    const server = createServer(async (ir, res) => {
      try {
        if (!hostOk(ir, cfg) || !originOk(ir)) return json(res, 403, { error: 'forbidden' });
        const u = new URL(ir.url || '/', 'http://x');
        // Onboarding: a tokenless informational page (what this app is, why a
        // browser window just opened). No secrets here — same Host/Origin
        // checks as everything else still apply above.
        if ((u.pathname === '/' || u.pathname === '/onboarding') && ir.method === 'GET') {
          if (!existsSync(ONBOARDING_PATH))
            return html(res, 404, page('error', 'Onboarding page asset (web/onboarding/index.html) is missing.'));
          return html(res, 200, readFileSync(ONBOARDING_PATH, 'utf8'));
        }
        if (u.pathname === '/unlock' && ir.method === 'GET') {
          const t = u.searchParams.get('t') || '';
          const r = pending.get(t);
          if (!r || r.expiresAt < Date.now()) return html(res, 410, page('expired', 'This request has expired.'));
          const db = r.mode === 'create' ? undefined : dbs[r.db];
          if (r.mode !== 'create' && !db) return html(res, 404, page('error', 'Unknown database.'));
          const currentTimeout = r.mode === 'create'
            ? (dbs[cfg.keepass.default_database ?? '']?.session_timeout ?? 900)
            : (db!.session_timeout ?? 900);
          if (!r.rsaPub) { const kp = newKeyPair(); r.rsaPub = kp.publicKey; r.rsaPriv = kp.privateKey; }
          // Fail closed: without the bundled UI there is no encrypted-submit
          // path, and plaintext credential forms are never served.
          if (!existsSync(UI_PATH))
            return html(res, 503, page('error', 'The web UI asset (web/unlock-ui/index.html) is missing; this request cannot be served securely.'));
          let src = readFileSync(UI_PATH, 'utf8');
          src = src
            .replaceAll('{{PUBKEY}}', JSON.stringify(r.rsaPub))
            .replaceAll('{{DB}}', esc(r.db))
            .replaceAll('{{DB_STATE}}', r.mode === 'create' ? 'LOCKED' : dbState(r.db))
            .replaceAll('{{TOKEN}}', esc(r.token))
            .replaceAll('{{MODE}}', r.mode)
            .replaceAll('{{TITLE_KEY}}', r.mode === 'create' ? 'title_create' : r.mode === 'entry' ? 'title_entry' : r.mode === 'cookies' ? 'title_cookies' : 'title_unlock')
            .replaceAll('{{ACTION_TITLE}}', r.mode === 'create' ? 'Create database' : r.mode === 'entry' ? 'Add entry' : r.mode === 'cookies' ? 'Sync cookies' : 'Unlock database')
            // The description carries an i18n key for the plain-text modes;
            // cookies mode embeds its own per-sentence data-i18n spans because
            // the domain must sit mid-sentence inside a real <a> element.
            .replaceAll('{{DESC_ATTR}}', r.mode === 'create' ? ' data-i18n="desc_create"'
              : r.mode === 'entry' ? ' data-i18n="desc_entry"'
              : r.mode === 'cookies' ? ''
              : ' data-i18n="desc_unlock"')
            .replaceAll('{{ACTION_DESCRIPTION}}', r.mode === 'create'
              ? 'The master password is used only on this PC to create and verify the KDBX and to protect the DPAPI session.'
              : r.mode === 'entry'
              ? 'The values you enter are saved as a new entry in the selected KDBX.'
              : r.mode === 'cookies'
              ? `<span data-i18n="ck1a">① In an open browser tab, sign in to</span> <a href="https://${esc(r.domain || '')}" target="_blank" rel="noopener">${esc(r.domain || 'the site')}</a><span data-i18n="ck1b">.</span><br><span data-i18n="ck2">② Enter the ID and password you just used, or skip them.</span><br><span data-i18n="ck3a">③ Submitting stores the browser's</span> ${esc(r.domain || '')} <span data-i18n="ck3b">cookies and the credentials above in this entry.</span>`
              : 'The master password is sent only to this PC\'s KPScript stdin.')
            .replaceAll('{{PATH}}', '')
            .replaceAll('{{PATH_FIELD}}', r.mode === 'create'
              ? `<label class="field-label" for="path" data-i18n="field_path">Save path (.kdbx)</label><input id="path" name="path" value="${esc(r.targetPath || '')}" required>`
              : '')
            .replaceAll('{{KEYFILE}}', (r.keyFile || db?.key_file) ? '<span data-i18n="uses_keyfile">Using a key file</span>' : '')
            // Declared requesting agent (policy engine identity) — the
            // approver sees WHO asked. Charset-restricted + escaped anyway.
            .replaceAll('{{AGENT_FIELD}}', r.agent ? `<span data-i18n="requested_by">Requested by agent:</span> ${esc(r.agent)}` : '')
            .replaceAll('{{CONFIRM_FIELD}}', r.mode === 'create'
              ? '<label class="field-label" for="confirmation" data-i18n="confirm_password">Confirm password</label><input id="confirmation" type="password" name="confirmation" autocomplete="new-password" required data-i18n-placeholder="confirm_ph" placeholder="Re-enter the master password">'
              : '')
            .replaceAll('{{DB_SELECT}}', r.mode === 'create' || r.mode === 'cookies' ? '' : dbSelectField(allDbs(dbs), r.db, cfg.keepass.default_database ?? ''))
            .replaceAll('{{PASSWORD_AUTOCOMPLETE}}', r.mode === 'create' ? 'new-password' : 'current-password')
            .replaceAll('{{ENTRY_FIELDS}}', r.mode === 'entry' ? entryFields(r.prefill) : '')
            .replaceAll('{{COLLECT_FIELDS}}', r.mode === 'cookies' ? collectFields() : '')
            .replaceAll('{{PASSWORD_FIELD}}', passwordField(r.mode))
            .replaceAll('{{SESSION_FIELD}}', sessionField(currentTimeout, '', r.mode === 'entry' || r.mode === 'cookies'))
            .replaceAll('{{NEW_DB_SECTION}}', r.mode === 'unlock' ? newDbSection(r.token, currentTimeout) : '')
            .replaceAll('{{SUBMIT_KEY}}', r.mode === 'create' ? 'submit_create' : r.mode === 'entry' ? 'submit_entry' : r.mode === 'cookies' ? 'submit_cookies' : 'submit_unlock')
            .replaceAll('{{SUBMIT_LABEL}}', r.mode === 'create' ? 'Create and register' : r.mode === 'entry' ? 'Add entry' : r.mode === 'cookies' ? 'Collect credentials' : 'Unlock');
          return html(res, 200, src);
        }
        if (u.pathname === '/unlock' && ir.method === 'POST') {
          const ct = ir.headers['content-type'] || '';
          if (!ct.includes('application/x-www-form-urlencoded') && !ct.includes('application/json'))
            return json(res, 415, { error: 'bad content type' });
          // The encrypted payload `p` is mandatory — plaintext credential
          // fields in the request body are rejected outright. `p` wraps a
          // fresh AES-256-GCM payload under this request's per-token
          // RSA-OAEP public key (issued when the form was served).
          let raw = await bodyOf(ir);
          let enc = '', t = '';
          if (ct.includes('json')) {
            try { const j = JSON.parse(raw); enc = j.p || ''; t = j.t || ''; } catch {}
          } else {
            const q0 = new URLSearchParams(raw);
            enc = q0.get('p') || '';
            t = q0.get('t') || '';
          }
          raw = '';
          if (!enc) return json(res, 400, { ok: false, code: 'PAYLOAD_REQUIRED' });
          const r = pending.get(t);
          if (!r || r.expiresAt < Date.now() || !r.rsaPriv) return json(res, 410, { error: 'expired' });
          const dec = decryptPayload(enc, r.rsaPriv);
          if (!dec) {
            countFailure(r);
            return json(res, 400, { ok: false, code: 'DECRYPT_FAILED' });
          }
          const p = new URLSearchParams();
          for (const [k, v] of Object.entries(dec)) p.set(k, String(v));
          p.set('t', t); // bind decrypted fields to the submitted token
          let pw = p.get('password') || '';
          let confirmation = p.get('confirmation') || '';
          const timeoutRaw = p.get('session_timeout') || '';
          const action = p.get('action') || '';
          const dbField = p.get('db') || '';
          const newAlias = p.get('new_alias') || '';
          const newPath = p.get('new_path') || '';
          const newKeyfile = p.get('new_keyfile') || '';
          const pathField = p.get('path') || '';
          let masterField = p.get('master_password') || '';
          const titleField = p.get('title') || '';
          const userField = p.get('username') || '';
          const urlField = p.get('url') || '';
          const notesField = p.get('notes') || '';
          // T12: CR/LF in a secret would corrupt the KPScript -keyprompt
          // line sequence — reject at the input boundary, all modes.
          if (/[\r\n]/.test(pw) || /[\r\n]/.test(masterField) || /[\r\n]/.test(confirmation))
            return json(res, 400, { ok: false, code: 'INVALID_SECRET_CHARS' });
          if (!pw && r.mode !== 'cookies') return json(res, 400, { ok: false, code: 'PASSWORD_REQUIRED' });
          const parsedTimeout = parseSessionTimeout(timeoutRaw);
          if (parsedTimeout === 'invalid') return json(res, 400, { ok: false, code: 'INVALID_SESSION_TIMEOUT' });
          const pageCreate = r.mode !== 'create' && action === 'create';
          if (r.mode === 'create' || pageCreate) {
            if (pw !== confirmation) {
              pw = '';
              confirmation = '';
              return json(res, 400, { ok: false, code: 'PASSWORD_MISMATCH' });
            }
            const alias = r.mode === 'create' ? r.db : newAlias.trim();
            const targetPath = r.mode === 'create' ? (pathField.trim() || r.targetPath) : newPath.trim();
            const keyFile = r.mode === 'create' ? r.keyFile : (newKeyfile.trim() || undefined);
            const current = loadConfig();
            if (current.databases[alias]) {
              pw = '';
              confirmation = '';
              return json(res, 409, { ok: false, code: 'DATABASE_ALIAS_EXISTS' });
            }
            if (!targetPath) return json(res, 400, { ok: false, code: 'INVALID_PATH' });
            if (existsSync(targetPath)) {
              pw = '';
              confirmation = '';
              return json(res, 409, { ok: false, code: 'DATABASE_ALREADY_EXISTS' });
            }
            // Post-parse gate (hardened): re-check the real submitted target.
            const gc = r.submissionGate?.({ mode: 'create', db: alias, path: targetPath });
            if (gc && !gc.ok) {
              pw = '';
              confirmation = '';
              return json(res, 403, { ok: false, code: gc.code || 'POLICY_DENIED' });
            }
            const db: DbConfig = {
              path: targetPath,
              key_file: keyFile,
              unlock_method: 'local-web',
              session_timeout: parsedTimeout === 'absent' ? 900 : parsedTimeout,
            };
            // Page-supplied values aren't pre-validated by the CLI — validate the
            // candidate config before touching disk.
            const cand = { ...current, databases: { ...current.databases, [alias]: db } };
            const errs = validateConfig(cand);
            if (errs.length) {
              pw = '';
              confirmation = '';
              return json(res, 400, { ok: false, code: 'INVALID_CONFIG', errors: errs });
            }
            const made = await provider.createDb(targetPath, pw, keyFile);
            if (!made.ok) {
              pw = '';
              confirmation = '';
              return json(res, 400, { ok: false, code: made.code || 'KDBX_CREATE_FAILED' });
            }
            const next = loadConfig();
            const added = addDb(next, alias, db);
            if (!added.ok) return json(res, 500, { ok: false, code: 'DATABASE_REGISTRATION_FAILED' });
            const validation = validateConfig(next);
            if (validation.length) {
              pw = '';
              confirmation = '';
              pending.delete(t);
              finish({ ok: false, code: 'DATABASE_REGISTRATION_FAILED' });
              return json(res, 500, { ok: false, code: 'DATABASE_REGISTRATION_FAILED' });
            }
            try { saveConfig(next); }
            catch {
              pw = '';
              confirmation = '';
              pending.delete(t);
              finish({ ok: false, code: 'DATABASE_REGISTRATION_FAILED' });
              return json(res, 500, { ok: false, code: 'DATABASE_REGISTRATION_FAILED', detail: 'KDBX created; run kp db add to register it.' });
            }
            const opened = await unlock(kpscript, alias, db, pw);
            pw = '';
            confirmation = '';
            pending.delete(t);
            finish({ ok: true, status: opened.ok ? 'created_unlocked' : 'created_locked', code: opened.code, database: alias, path: targetPath });
            return json(res, 200, {
              ok: true,
              mode: 'create',
              database: alias,
              path: targetPath,
              status: opened.ok ? 'created_unlocked' : 'created_locked',
              unlockCode: opened.code,
            });
          }
          if (r.mode === 'entry') {
            const all = allDbs(dbs);
            const effAlias = dbField || r.db;
            const targetDb = all[effAlias];
            if (!targetDb) return json(res, 404, { ok: false, code: 'DATABASE_NOT_FOUND' });
            const title = titleField.trim();
            if (!title) return json(res, 400, { ok: false, code: 'TITLE_REQUIRED' });
            const urlTrim = urlField.trim();
            // Post-parse gate (hardened) BEFORE any unlock/session side
            // effect: evaluate() is re-checked against the SUBMITTED values
            // — prefill/target drift is denied here so a rejected entry can
            // never mint a session on a drifted db.
            const ge = r.submissionGate?.({
              mode: 'entry', db: effAlias,
              entry: { title, url: urlTrim },
              fields: { title, url: urlTrim, username: userField, notes: notesField },
            });
            if (ge && !ge.ok) {
              pw = '';
              masterField = '';
              return json(res, 403, { ok: false, code: ge.code || 'POLICY_DENIED', detail: ge.detail });
            }
            let master = '';
            if (masterField) {
              // Locked session — verify the master key and persist it per the
              // chosen session timeout, same as the unlock flow.
              const mdb = parsedTimeout === 'absent' ? targetDb : { ...targetDb, session_timeout: parsedTimeout };
              const un = await unlock(kpscript, effAlias, mdb, masterField);
              if (!un.ok) {
                pw = '';
                masterField = '';
                countFailure(r);
                return json(res, 401, { ok: false, code: un.code });
              }
              master = masterField;
              if (parsedTimeout !== 'absent' && parsedTimeout !== targetDb.session_timeout) {
                try {
                  const current = loadConfig();
                  if (current.databases[effAlias]) {
                    current.databases[effAlias].session_timeout = parsedTimeout;
                    if (!validateConfig(current).length) saveConfig(current);
                  }
                } catch {}
              }
            } else {
              master = (await readSession(effAlias)) || '';
              if (!master) return json(res, 401, { ok: false, code: 'UNLOCK_REQUIRED' });
            }
            const warnings: string[] = [];
            // T4: storing is allowed (intranet http sites), but a URL the
            // worker egress policy would reject gets an explicit warning —
            // `kp login` will refuse to fire against it.
            if (urlTrim) {
              const v = checkWorkerUrl(urlTrim);
              if (!v.ok) warnings.push(`entry_url_not_worker_allowed:${v.reason}`);
            }
            // T12: the Windows KPScript stdout path decodes as CP949 — a
            // password outside that repertoire would come back corrupted.
            if (process.platform === 'win32' && pw) {
              try { if (!cp949RoundTrips(pw)) warnings.push('password_not_cp949_representable'); } catch {}
            }
            const added = await provider.addEntry(targetDb, master, {
              title, username: userField, password: pw, url: urlField, notes: notesField,
            });
            pw = '';
            masterField = '';
            master = '';
            if (!added.ok) return json(res, 400, { ok: false, code: added.code || 'ENTRY_ADD_FAILED' });
            pending.delete(t);
            finish({ ok: true, status: 'entry_added', database: effAlias, uuid: added.uuid, warnings });
            return json(res, 200, { ok: true, mode: 'entry', database: effAlias, status: 'entry_added', uuid: added.uuid, warnings });
          }
          if (r.mode === 'cookies') {
            const targetDb = allDbs(dbs)[r.db];
            if (!targetDb) return json(res, 404, { ok: false, code: 'DATABASE_NOT_FOUND' });
            // Post-parse gate (hardened) BEFORE any unlock/session side
            // effect: uuid/domain are what the harvest will actually touch —
            // a denied submission must not mint a session first.
            const gk = r.submissionGate?.({
              mode: 'cookies', db: r.db,
              entry: { id: r.entryUuid }, host: r.domain,
            });
            if (gk && !gk.ok) { masterField = ''; return json(res, 403, { ok: false, code: gk.code || 'POLICY_DENIED', detail: gk.detail }); }
            let master = '';
            if (masterField) {
              const mdb = parsedTimeout === 'absent' ? targetDb : { ...targetDb, session_timeout: parsedTimeout };
              const un = await unlock(kpscript, r.db, mdb, masterField);
              if (!un.ok) { masterField = ''; countFailure(r); return json(res, 401, { ok: false, code: un.code }); }
              master = masterField;
              masterField = '';
              if (parsedTimeout !== 'absent' && parsedTimeout !== targetDb.session_timeout) {
                try {
                  const current = loadConfig();
                  if (current.databases[r.db]) {
                    current.databases[r.db].session_timeout = parsedTimeout;
                    if (!validateConfig(current).length) saveConfig(current);
                  }
                } catch {}
              }
            } else {
              master = (await readSession(r.db)) || '';
              if (!master) return json(res, 401, { ok: false, code: 'UNLOCK_REQUIRED' });
            }
            let cookies;
            try {
              // T11: re-validate at the point of collection — a non-loopback
              // CDP endpoint could harvest or inject cookies, so the value
              // carried by the request is never trusted blindly.
              const ep = r.cdpEndpoint || DEFAULT_CDP_ENDPOINT;
              if (!isLoopbackCdpEndpoint(ep))
                return json(res, 400, { ok: false, code: 'CDP_ENDPOINT_REJECTED' });
              cookies = (await getBrowserCookies(ep))
                .filter((c) => domainMatch(c.domain, r.domain || ''));
            } catch { return json(res, 502, { ok: false, code: 'CDP_UNAVAILABLE' }); }
            if (!cookies.length) return json(res, 400, { ok: false, code: 'NO_COOKIES', domain: r.domain });
            const fields: Record<string, string> = {
              cookies: JSON.stringify(cookies.map((c) => ({
                name: c.name, value: c.value, domain: c.domain, path: c.path,
                secure: c.secure, httpOnly: c.httpOnly, expires: c.expires, sameSite: c.sameSite,
              }))),
              cookies_domain: r.domain || '',
              cookies_synced_at: new Date().toISOString(),
            };
            if (userField) fields._username = userField;
            if (pw) fields._password = pw;
            const upd = await provider.updateEntryFields(targetDb, master, r.entryUuid!, fields);
            master = '';
            if (!upd.ok) return json(res, 400, { ok: false, code: upd.code });
            pending.delete(t);
            finish({ ok: true, status: 'cookies_synced', database: r.db, domain: r.domain, count: cookies.length });
            return json(res, 200, { ok: true, mode: 'cookies', database: r.db, domain: r.domain, count: cookies.length, names: cookies.map((c) => c.name) });
          }
          // db field lets the page switch the unlock target to another
          // registered DB; falls back to the requested alias.
          const all = allDbs(dbs);
          const effAlias = dbField || r.db;
          const targetDb = all[effAlias];
          if (!targetDb) return json(res, 404, { ok: false, code: 'DATABASE_NOT_FOUND' });
          // Post-parse gate (hardened): the page may have switched the
          // target alias — deny an unlock that drifted from the approved db.
          const gu = r.submissionGate?.({ mode: 'unlock', db: effAlias });
          if (gu && !gu.ok) {
            pw = '';
            confirmation = '';
            return json(res, 403, { ok: false, code: gu.code || 'POLICY_DENIED', detail: gu.detail });
          }
          const db = parsedTimeout === 'absent' ? targetDb : { ...targetDb, session_timeout: parsedTimeout };
          const out = await unlock(kpscript, effAlias, db, pw);
          pw = '';
          confirmation = '';
          if (out.ok) {
            if (parsedTimeout !== 'absent' && parsedTimeout !== targetDb.session_timeout) {
              try {
                const current = loadConfig();
                if (current.databases[effAlias]) {
                  current.databases[effAlias].session_timeout = parsedTimeout;
                  if (!validateConfig(current).length) saveConfig(current);
                }
              } catch {}
            }
            pending.delete(t);
            finish({ ok: true, status: 'unlocked', database: effAlias });
            return json(res, 200, { ok: true, database: effAlias });
          }
          countFailure(r);
          return json(res, 401, { ok: false, code: out.code });
        }
        if (u.pathname === '/cancel' && ir.method === 'POST') {
          const t = u.searchParams.get('t') || '';
          if (pending.has(t)) { pending.delete(t); finish({ ok: false, code: 'USER_INTERACTION_REQUIRED' }); return json(res, 200, { ok: true }); }
        }
        return json(res, 404, { error: 'not found' });
      } catch {
        return json(res, 500, { error: 'internal' });
      }
    });
    const timer = setTimeout(() => finish({ ok: false, code: 'UNLOCK_TIMEOUT' }), Math.max(130_000, req.expiresAt - Date.now() + 30_000));
    let finished = false;
    function finish(result: UnlockResult) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      pending.delete(req.token);
      // Defer close one tick so the caller's res.end() is queued first.
      setImmediate(() => {
        // close() alone hangs on idle keep-alive connections (the browser holds
        // one open) — close them explicitly, and never let a stuck close block
        // promise resolution.
        server.closeIdleConnections?.();
        server.close(() => resolve(result));
        setTimeout(() => resolve(result), 2_000).unref();
      });
    }
    // Port binding (F5): try the configured port first (single-request
    // behavior unchanged); on EADDRINUSE — a parallel approval already holds
    // it — retry on an ephemeral port so concurrent requests never collide
    // or get sabotaged by a squatter. The URL always reflects the actual
    // bound port.
    const listenOnce = (port: number, fallbackAllowed: boolean) => {
      server.once('error', (e: any) => {
        if (fallbackAllowed && e?.code === 'EADDRINUSE') return listenOnce(0, false);
        finish({ ok: false, code: 'UNLOCK_SERVER_ERROR' });
      });
      server.listen(port, '127.0.0.1', () => {
        const actualPort = (server.address() as any)?.port ?? cfg.unlock.port;
        const url = `http://127.0.0.1:${actualPort}/unlock?t=${req.token}`;
        onReady?.(url);
        if (cfg.unlock.auto_open_browser && !req.noAutoOpen) openBrowser(url);
      });
    };
    listenOnce(cfg.unlock.port, true);
  });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function page(title: string, msg: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font-family:sans-serif;max-width:400px;margin:60px auto;text-align:center"><h2>${esc(title)}</h2><p>${esc(msg)}</p></body>`;
}
// No plaintext fallback page: when web/unlock-ui/index.html is missing the
// GET handler above returns a 503 error page instead of serving a form that
// could only submit unencrypted credentials.
