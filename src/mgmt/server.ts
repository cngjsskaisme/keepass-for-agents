// Management Server — loopback-only operator console (`kp ui`).
//
// Same transport security model as the unlock server: loopback bind,
// Host/Origin checks, no-store, CSP. Token model: TWO tokens per run —
//   - pageToken: ONE-TIME, embedded in the launch URL (`/?t=`). The URL
//     transits the browser-spawn argv, which same-UID processes can read
//     briefly — so the token it carries is consumed on first page serve
//     and worthless afterwards. An argv-rescued URL is dead on arrival.
//   - apiToken: the actual session credential, embedded only in the served
//     page (x-kp-ui-token header on every /api call; 401 without it). It
//     never crosses argv, URLs, stdout, stderr, or the audit log.
// A SameSite=Strict HttpOnly cookie carrying apiToken is set on the first
// page serve so a same-browser reload re-serves the console (cross-site
// navigations never send it; mutations still require the header, which
// JS — and any cookie thief — cannot read). The apiToken is never written
// to stdout, stderr, or the audit log — an agent process cannot mint or
// learn it, and a request without it gets 401 before any handler runs.
//
// Identity model: a request may declare an agent id via `x-kp-agent` — such
// calls are policy-gated through the normal engine under the `ui.*` action
// namespace (deny-by-default, same rules as the CLI). A request without the
// header is the operator console itself and runs as the reserved identity
// `operator`, which bypasses [agents.*] UNLESS the operator explicitly
// configured `[agents.operator]` (self-scoping). This mirrors filesystem
// reality: the token holder already proved themselves by launching the
// gated `kp ui`, and the operator can edit config.toml / session files
// directly anyway. Every call — read or mutation — writes one audit record
// with action `ui.*` so UI-originated activity is distinguishable in the
// log, satisfying the "operator or UI-specific marker" requirement.
//
// No secrets: this server never receives or returns master keys, entry
// passwords, or cookie values. Unlock requests are delegated to the
// existing one-time-token approval flow — the API returns the approval URL
// for the operator's browser to open; the master key still travels only
// browser → unlock server → provider stdin.
//
// Hardened Mode: reads/mutations route over authenticated service IPC
// (`status`/`audit`/`lock`/`approval` ops) under the declared agent (or the
// `kp ui` launcher's declared identity for operator requests) — the service
// re-evaluates policy per op exactly as if the launcher had run the
// matching kp commands. Policy writes (POST /api/agents) stay a local
// config.toml write — config is operator-owned in every mode.

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { newToken } from '../security/dpapi.ts';
import { dbState, lock } from '../master-key/manager.ts';
import {
  loadConfig, saveConfig, validateConfig,
  FORBIDDEN_TOML_KEYS, type AppConfig, type AgentPolicy,
} from '../config/config.ts';
import { listDbs, getDb } from '../database/manager.ts';
import { evaluate, resolveAgentId } from '../policy/engine.ts';
import { audit, readAudit, AUDIT_MAX_BYTES_DEFAULT } from '../policy/audit.ts';
import { requestUnlock, waitForUnlock, TOKEN_TTL_MS, type UnlockResult } from '../unlock-server/server.ts';
import { callService } from '../service/client.ts';
import { hardenedEnabled } from '../service/mode.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const UI_PATH = join(__dir, '..', '..', 'web', 'mgmt-ui', 'index.html');

/** Default UI session lifetime — the server exits when it elapses. */
export const MGMT_TTL_MS_DEFAULT = 4 * 3600 * 1000; // 4h
/** POST body cap — agents policies are a few KB at most. */
const MAX_BODY_BYTES = 64 * 1024;
/**
 * Concurrent approval-request cap — each /api/unlock starts a listener
 * (its own server + ~10min timer); unbounded fan-out is a resource
 * exhaustion vector even on loopback.
 */
export const MAX_PENDING_APPROVALS = 3;

/** Actions the management API is gated under (`ui.*` namespace). */
const ROUTES: Record<string, { action: string; post: boolean }> = {
  'GET /api/dbs': { action: 'ui.dbs', post: false },
  'GET /api/audit': { action: 'ui.audit', post: false },
  'GET /api/agents': { action: 'ui.agents.read', post: false },
  'POST /api/agents': { action: 'ui.agents.write', post: true },
  'POST /api/session/lock': { action: 'ui.lock', post: true },
  'POST /api/unlock': { action: 'ui.unlock', post: true },
  'POST /api/shutdown': { action: 'ui.shutdown', post: true },
};
const API_PATHS = new Set(Object.keys(ROUTES).map((k) => k.split(' ')[1]));

/**
 * Operator-only actions — policy writes change WHO gets access, so even a
 * token-holding caller that declares an agent identity (x-kp-agent) may
 * not perform them regardless of that agent's [agents.*] grants. The
 * console's operator channel is the only policy-write path here.
 */
const OPERATOR_ONLY_ACTIONS = new Set(['ui.agents.write']);

/** Agent-policy list fields accepted by POST /api/agents. */
const AGENT_LIST_FIELDS = ['allowed', 'require_approval', 'allowed_entries', 'denied_entries', 'allowed_hosts'] as const;

export interface MgmtServerOpts {
  /**
   * kpscript reference for standard-mode unlock verification — plain path or
   * the [exe, ...prefix] test-hook form (same convention as the unlock server).
   */
  kpscript: string | string[];
  /** Declared identity that ran `kp ui` — used for hardened IPC calls. */
  launchAgent: string;
  /** Session token TTL in ms (server exits when it elapses). */
  ttlMs?: number;
}

export interface MgmtServer {
  port: number;
  /** API session token (x-kp-ui-token) — embedded in the page only. */
  token: string;
  /** `http://127.0.0.1:<port>/?t=<pageToken>` — one-time page token, for openBrowser only. */
  url: string;
  /** Resolves when the console ends: UI_SHUTDOWN | UI_TOKEN_EXPIRED | UI_SERVER_ERROR. */
  done: Promise<{ code: string }>;
  close(code?: string): void;
}

function tokenEq(a: string, b: string): boolean {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** Cookie carrying the apiToken — lets a same-browser reload re-serve the
 *  console without putting a token back in any URL. HttpOnly (JS can't
 *  read it), SameSite=Strict (never sent cross-site). */
function apiCookieOk(ir: IncomingMessage, apiToken: string): boolean {
  const c = ir.headers.cookie;
  if (!c) return false;
  for (const part of c.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === 'kpui' && tokenEq(part.slice(i + 1).trim(), apiToken))
      return true;
  }
  return false;
}

function hostOk(ir: IncomingMessage): boolean {
  const h = (ir.headers.host || '').split(':')[0].toLowerCase();
  return ['127.0.0.1', 'localhost', '[::1]'].includes(h);
}

function originOk(ir: IncomingMessage): boolean {
  const o = ir.headers.origin;
  if (!o) return true;
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

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function errPage(title: string, msg: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font-family:sans-serif;max-width:400px;margin:60px auto;text-align:center"><h2>${esc(title)}</h2><p>${esc(msg)}</p></body>`;
}

function bodyOf(ir: IncomingMessage): Promise<string> {
  return new Promise((res, rej) => {
    let d = '';
    ir.on('data', (c) => { d += c; if (d.length > MAX_BODY_BYTES) { rej(new Error('too large')); } });
    ir.on('end', () => res(d));
    ir.on('error', rej);
  });
}

/** Sanitize a policy-list item — bounded length, no control characters. */
function cleanListItem(v: unknown): string | null {
  if (typeof v !== 'string' || !v) return null;
  const s = v.replace(/[\x00-\x1f\x7f-\x9f]/g, '').slice(0, 256);
  return s || null;
}

/**
 * Start the management server. Resolves once it is listening on an
 * ephemeral loopback port. `done` settles on /api/shutdown, token TTL
 * expiry, or a fatal bind error.
 */
export function startMgmtServer(opts: MgmtServerOpts): Promise<MgmtServer> {
  // Two tokens: the launch URL carries pageToken (one-time — argv-recovered
  // copies are dead after first serve); apiToken is the actual session
  // credential and only ever lives inside the served page.
  const pageToken = newToken();
  const apiToken = newToken();
  let pageTokenUsed = false;
  const ttlMs = opts.ttlMs ?? MGMT_TTL_MS_DEFAULT;
  let pendingApprovals = 0;
  let lastGoodCfg: AppConfig | null = null;

  const freshCfg = (): AppConfig => {
    try { lastGoodCfg = loadConfig(); } catch { /* keep last good copy */ }
    if (!lastGoodCfg) throw new Error('CONFIG_NOT_FOUND');
    return lastGoodCfg;
  };

  const auditMaxBytes = (): number =>
    lastGoodCfg?.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT;

  const mgmtAudit = (
    agent: string, action: string,
    e: { db?: string; target?: string; decision?: string; result_code: string },
  ) => audit({ agent, action, db: e.db, target: e.target, decision: e.decision, result_code: e.result_code }, auditMaxBytes());

  return new Promise((resolveStart, rejectStart) => {
    let doneResolve: (r: { code: string }) => void;
    const done = new Promise<{ code: string }>((res) => { doneResolve = res; });
    let finished = false;
    let listening = false;
    let server: Server;
    let ttlTimer: ReturnType<typeof setTimeout>;

    const finish = (code: string) => {
      if (finished) return;
      finished = true;
      clearTimeout(ttlTimer);
      setImmediate(() => {
        server.closeIdleConnections?.();
        server.close(() => doneResolve({ code }));
        setTimeout(() => doneResolve({ code }), 2_000).unref();
      });
    };

    /**
     * Policy gate for one API call. `operator` (no x-kp-agent header, or the
     * header literally declaring it — identical outcome either way since the
     * identity is self-declared) bypasses [agents.*] unless the operator
     * configured an explicit [agents.operator] section. Every other declared
     * id is evaluated deny-by-default; require_approval is satisfied only by
     * ui.unlock because that endpoint IS the approval channel.
     */
    const authorize = (
      cfg: AppConfig, agent: string, action: string,
    ): { ok: boolean; decision: string; code?: string; detail?: string; policy?: string } => {
      if (agent === 'operator' && !Object.hasOwn(cfg.agents ?? {}, 'operator'))
        return { ok: true, decision: 'allow' };
      const ev = evaluate(cfg, agent, action);
      if (ev.decision === 'allow') return { ok: true, decision: ev.decision };
      if (ev.decision === 'require_approval' && action === 'ui.unlock')
        return { ok: true, decision: ev.decision };
      return {
        ok: false, decision: ev.decision,
        code: ev.decision === 'require_approval' ? 'POLICY_APPROVAL_REQUIRED' : 'POLICY_DENIED',
        detail: ev.reason.slice(0, 200), policy: ev.policy,
      };
    };

    /** Read a POST JSON body — strict content-type + parse, fail-closed. */
    const readJsonBody = async (ir: IncomingMessage): Promise<{ ok: true; body: Record<string, any> } | { ok: false; code: string }> => {
      const ct = ir.headers['content-type'] || '';
      if (!ct.includes('application/json')) return { ok: false, code: 'BAD_CONTENT_TYPE' };
      let raw = '';
      try { raw = await bodyOf(ir); } catch { return { ok: false, code: 'BODY_TOO_LARGE' }; }
      try {
        const b = JSON.parse(raw);
        if (!b || typeof b !== 'object' || Array.isArray(b)) return { ok: false, code: 'INVALID_JSON' };
        return { ok: true, body: b };
      } catch { return { ok: false, code: 'INVALID_JSON' }; }
    };

    // --- handlers (ctx: caller agent, svcAgent for hardened IPC, fresh cfg) ---

    interface Ctx { caller: string; svcAgent: string; cfg: AppConfig; action: string }

    const handleDbs = async (ctx: Ctx, res: ServerResponse) => {
      const { cfg, caller } = ctx;
      const hard = hardenedEnabled(cfg);
      let states: Record<string, string> | null = null;
      let service: { state: string; code?: string } | undefined;
      if (hard) {
        const r = await callService(cfg, 'status', { agent: ctx.svcAgent });
        if (r.ok) { states = r.states ?? {}; service = { state: 'up' }; }
        else {
          // Fail-closed like `kp status`: local session files are NOT the
          // authoritative state under hardened mode (they live with the
          // service principal) — a down service reports UNAVAILABLE, never
          // a misleading local LOCKED reading.
          states = {};
          service = { state: 'down', code: r.code || 'HARDENED_IPC_ERROR' };
        }
      }
      const databases = listDbs(cfg).map((d) => ({
        alias: d.alias,
        path: d.db.path,
        exists: d.exists,
        default: d.default,
        key_file: !!d.db.key_file,
        unlock_method: d.db.unlock_method || 'local-web',
        session_timeout: d.db.session_timeout ?? 900,
        state: states ? (states[d.alias] ?? 'UNAVAILABLE') : dbState(d.alias),
      }));
      mgmtAudit(caller, ctx.action, { decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, mode: hard ? 'hardened' : 'standard', ...(service ? { service } : {}), databases });
    };

    const handleAudit = async (ctx: Ctx, res: ServerResponse, u: URL) => {
      const { cfg, caller } = ctx;
      let limit = Number(u.searchParams.get('limit') || 100);
      if (!Number.isInteger(limit)) limit = 100;
      limit = Math.max(1, Math.min(limit, 1000));
      const fAgent = u.searchParams.get('agent');
      const fAction = u.searchParams.get('action');
      let events;
      if (hardenedEnabled(cfg)) {
        const r = await callService(cfg, 'audit', { agent: ctx.svcAgent, limit });
        if (!r.ok) {
          mgmtAudit(caller, ctx.action, { decision: 'allow', result_code: r.code || 'HARDENED_IPC_ERROR' });
          return json(res, 502, { ok: false, code: r.code || 'HARDENED_IPC_ERROR', detail: r.detail });
        }
        events = r.events ?? [];
      } else {
        events = readAudit(limit);
      }
      const filtered = events.filter((e: any) =>
        (fAgent == null || fAgent === '' || e.agent === fAgent)
        && (fAction == null || fAction === '' || e.action === fAction));
      mgmtAudit(caller, ctx.action, { decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, events: filtered });
    };

    const handleAgentsRead = async (ctx: Ctx, res: ServerResponse) => {
      mgmtAudit(ctx.caller, ctx.action, { decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, agents: JSON.parse(JSON.stringify(ctx.cfg.agents ?? {})) });
    };

    const handleAgentsWrite = async (ctx: Ctx, res: ServerResponse, _u: URL, body: Record<string, any>) => {
      const { caller } = ctx;
      const target = `agents.${typeof body.name === 'string' ? body.name : '?'}`;
      const deny = (code: string, extra: Record<string, any> = {}) => {
        mgmtAudit(caller, ctx.action, { target, decision: 'allow', result_code: code });
        json(res, 400, { ok: false, code, ...extra });
      };
      const name = typeof body.name === 'string' ? body.name : '';
      if (!/^[a-z0-9_-]{1,64}$/i.test(name) || FORBIDDEN_TOML_KEYS.has(name.toLowerCase()))
        return deny('INVALID_CONFIG', { detail: 'agent name must match [a-z0-9_-]{1,64} and not be a reserved key' });
      // Clone → mutate → validate → save → swap: mutating the shared
      // lastGoodCfg in place would leak a rejected write into every later
      // freshCfg() read (the cache must only ever hold saved states).
      const next: AppConfig = JSON.parse(JSON.stringify(freshCfg()));
      if (body.delete === true) {
        if (!Object.hasOwn(next.agents, name))
          return deny('AGENT_NOT_FOUND');
        delete next.agents[name];
      } else {
        const p = body.policy;
        if (!p || typeof p !== 'object' || Array.isArray(p))
          return deny('INVALID_CONFIG', { detail: 'policy object required' });
        const pol: AgentPolicy = {};
        for (const f of AGENT_LIST_FIELDS) {
          const v = (p as any)[f];
          if (v == null) continue;
          if (!Array.isArray(v) || v.length > 64)
            return deny('INVALID_CONFIG', { detail: `policy.${f} must be an array of ≤64 strings` });
          const items = v.map(cleanListItem);
          if (items.some((x) => x === null))
            return deny('INVALID_CONFIG', { detail: `policy.${f} items must be non-empty strings` });
          // A present-but-empty list clears the field (UI sends all five).
          if (items.length) (pol as any)[f] = items;
        }
        next.agents[name] = pol;
      }
      const errs = validateConfig(next);
      if (errs.length) return deny('INVALID_CONFIG', { errors: errs });
      saveConfig(next);
      lastGoodCfg = next; // swap only after a successful save
      mgmtAudit(caller, ctx.action, { target, decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, agent: name, deleted: body.delete === true });
    };

    const handleLock = async (ctx: Ctx, res: ServerResponse, _u: URL, body: Record<string, any>) => {
      const { caller } = ctx;
      const alias = typeof body.db === 'string' ? body.db : '';
      if (!/^[a-z0-9_-]{1,64}$/i.test(alias)) {
        mgmtAudit(caller, ctx.action, { decision: 'allow', result_code: 'INVALID_CONFIG' });
        return json(res, 400, { ok: false, code: 'INVALID_CONFIG', detail: 'db alias required' });
      }
      if (hardenedEnabled(ctx.cfg)) {
        const r = await callService(ctx.cfg, 'lock', { agent: ctx.svcAgent, db: alias });
        mgmtAudit(caller, ctx.action, { db: alias, decision: 'allow', result_code: r.ok ? 'OK' : r.code || 'HARDENED_IPC_ERROR' });
        if (!r.ok) return json(res, 502, { ok: false, code: r.code || 'HARDENED_IPC_ERROR', detail: r.detail });
        return json(res, 200, { ok: true, alias, status: 'locked' });
      }
      lock(alias);
      mgmtAudit(caller, ctx.action, { db: alias, decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, alias, status: 'locked' });
    };

    const handleUnlock = async (ctx: Ctx, res: ServerResponse, _u: URL, body: Record<string, any>) => {
      const { caller, cfg } = ctx;
      const alias = typeof body.db === 'string' ? body.db : '';
      const r0 = getDb(cfg, alias);
      if (!r0.ok) {
        mgmtAudit(caller, ctx.action, { db: alias || undefined, decision: 'allow', result_code: r0.code! });
        return json(res, 404, { ok: false, code: r0.code, alias: r0.alias });
      }
      const respondOnce = (() => {
        let sent = false;
        return (status: number, o: Record<string, any>) => { if (!sent) { sent = true; json(res, status, o); } };
      })();
      if (hardenedEnabled(cfg)) {
        // The approval round-trip executes inside the service; the interim
        // frame carries the loopback approval URL we hand to the browser.
        if (pendingApprovals >= MAX_PENDING_APPROVALS) {
          mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: 'UNLOCK_BUSY' });
          return respondOnce(429, { ok: false, code: 'UNLOCK_BUSY', detail: 'too many concurrent approval requests' });
        }
        pendingApprovals++;
        mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: 'UNLOCK_REQUESTED' });
        const p = callService(cfg, 'approval', { agent: ctx.svcAgent, mode: 'unlock', db: r0.alias }, {
          onInterim: (m) => {
            if (typeof m?.url === 'string' && m.url)
              respondOnce(200, { ok: true, url: m.url, expires_in_seconds: TOKEN_TTL_MS / 1000 });
          },
        });
        void p.then((r) => {
          pendingApprovals--;
          mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: r.ok ? 'OK' : r.code || 'HARDENED_IPC_ERROR' });
          if (!r.ok) respondOnce(502, { ok: false, code: r.code || 'HARDENED_IPC_ERROR', detail: r.detail });
          else respondOnce(200, { ok: true, status: r.status });
        });
        return;
      }
      const ks = opts.kpscript;
      const ksMissing = Array.isArray(ks) ? !ks.length || !ks[0] : !ks;
      if (ksMissing && process.platform === 'win32') {
        mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: 'INVALID_CONFIG' });
        return respondOnce(400, { ok: false, code: 'INVALID_CONFIG', detail: 'keepass.kpscript not configured' });
      }
      if (pendingApprovals >= MAX_PENDING_APPROVALS) {
        mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: 'UNLOCK_BUSY' });
        return respondOnce(429, { ok: false, code: 'UNLOCK_BUSY', detail: 'too many concurrent approval requests' });
      }
      pendingApprovals++;
      const req = requestUnlock(r0.alias!, caller);
      req.noAutoOpen = true; // the approval URL goes to the operator's tab via API, not a second browser launch
      mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: 'UNLOCK_REQUESTED' });
      const done = waitForUnlock(cfg, ks, req, { [r0.alias!]: r0.db! }, (url) => {
        respondOnce(200, { ok: true, url, expires_in_seconds: TOKEN_TTL_MS / 1000 });
      });
      void done.then((r: UnlockResult) => {
        pendingApprovals--;
        mgmtAudit(caller, ctx.action, { db: r0.alias, decision: 'allow', result_code: r.ok ? 'OK' : r.code || 'UNLOCK_FAILED' });
        if (!r.ok) respondOnce(502, { ok: false, code: r.code || 'UNLOCK_FAILED' });
      });
    };

    const handleShutdown = async (ctx: Ctx, res: ServerResponse) => {
      mgmtAudit(ctx.caller, ctx.action, { decision: 'allow', result_code: 'OK' });
      json(res, 200, { ok: true, status: 'shutting_down' });
      setImmediate(() => finish('UI_SHUTDOWN'));
    };

    server = createServer(async (ir, res) => {
      try {
        if (!hostOk(ir) || !originOk(ir)) return json(res, 403, { ok: false, code: 'FORBIDDEN' });
        const u = new URL(ir.url || '/', 'http://x');

        // The page itself: the ONE-TIME page token travels in the launch
        // URL's query string (it transits the browser-spawn argv, so it is
        // consumed on first serve — an argv-rescued URL is dead). The real
        // session credential (apiToken) is embedded in the served page and
        // required as a header on every /api call. A SameSite=Strict
        // HttpOnly cookie also carries it so a same-browser reload can
        // re-serve the console without a URL token.
        if (u.pathname === '/' || u.pathname === '/index.html') {
          if (ir.method !== 'GET') return json(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });
          const viaUrl = !pageTokenUsed && tokenEq(u.searchParams.get('t') || '', pageToken);
          if (!viaUrl && !apiCookieOk(ir, apiToken))
            return html(res, 403, errPage('forbidden', 'The console token is invalid or already consumed.'));
          if (viaUrl) pageTokenUsed = true;
          if (!existsSync(UI_PATH))
            return html(res, 503, errPage('error', 'The web UI asset (web/mgmt-ui/index.html) is missing.'));
          const src = readFileSync(UI_PATH, 'utf8')
            .replaceAll('{{TOKEN}}', JSON.stringify(apiToken))
            .replaceAll('{{LAUNCH_AGENT}}', esc(opts.launchAgent))
            .replaceAll('{{TTL_S}}', String(Math.round(ttlMs / 1000)));
          res.setHeader('Set-Cookie', `kpui=${apiToken}; HttpOnly; SameSite=Strict; Path=/`);
          return html(res, 200, src);
        }

        if (!u.pathname.startsWith('/api/')) return json(res, 404, { ok: false, code: 'NOT_FOUND' });
        if (!API_PATHS.has(u.pathname)) return json(res, 404, { ok: false, code: 'NOT_FOUND' });

        // Session token — required for every API call before anything else.
        const tk = ir.headers['x-kp-ui-token'];
        if (typeof tk !== 'string' || !tokenEq(tk, apiToken))
          return json(res, 401, { ok: false, code: 'UI_TOKEN_INVALID' });

        const key = `${ir.method} ${u.pathname}`;
        const route = ROUTES[key];
        if (!route) return json(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED' });

        // Declared agent identity (optional x-kp-agent header → policy gate;
        // absent → the operator console). 'operator' declared via the header
        // is the same identity — self-declared ids are not authentication.
        // An empty or non-string header is INVALID — it must never silently
        // degrade to operator (F-3).
        let caller = 'operator';
        const ah = ir.headers['x-kp-agent'];
        if (ah !== undefined && ah !== 'operator') {
          const ar = typeof ah === 'string' && ah !== '' ? resolveAgentId(process.env, ah) : { ok: false as const, reason: 'bad header' };
          if (!ar.ok) {
            mgmtAudit('unknown', route.action, { decision: 'deny', result_code: 'INVALID_AGENT_ID' });
            return json(res, 403, { ok: false, code: 'INVALID_AGENT_ID' });
          }
          caller = ar.agent;
        }
        const svcAgent = caller === 'operator' ? opts.launchAgent : caller;

        // Operator-only actions: policy writes change who gets access, so a
        // caller that declares a non-operator agent identity can never reach
        // them — its [agents.*] grants are irrelevant (MED-3).
        if (caller !== 'operator' && OPERATOR_ONLY_ACTIONS.has(route.action)) {
          mgmtAudit(caller, route.action, { decision: 'deny', result_code: 'OPERATOR_ONLY' });
          return json(res, 403, { ok: false, code: 'OPERATOR_ONLY', detail: `${route.action} is operator-console only` });
        }

        let cfg: AppConfig;
        try { cfg = freshCfg(); }
        catch { return json(res, 500, { ok: false, code: 'CONFIG_NOT_FOUND' }); }

        const az = authorize(cfg, caller, route.action);
        if (!az.ok) {
          mgmtAudit(caller, route.action, { decision: az.decision, result_code: az.code! });
          return json(res, 403, { ok: false, code: az.code, detail: az.detail, policy: az.policy });
        }

        let body: Record<string, any> = {};
        if (route.post) {
          const b = await readJsonBody(ir);
          if (!b.ok) {
            mgmtAudit(caller, route.action, { decision: az.decision, result_code: b.code });
            return json(res, b.code === 'BODY_TOO_LARGE' ? 413 : 400, { ok: false, code: b.code });
          }
          body = b.body;
        }

        const ctx: Ctx = { caller, svcAgent, cfg, action: route.action };
        switch (key) {
          case 'GET /api/dbs': return await handleDbs(ctx, res);
          case 'GET /api/audit': return await handleAudit(ctx, res, u);
          case 'GET /api/agents': return await handleAgentsRead(ctx, res);
          case 'POST /api/agents': return await handleAgentsWrite(ctx, res, u, body);
          case 'POST /api/session/lock': return await handleLock(ctx, res, u, body);
          case 'POST /api/unlock': return await handleUnlock(ctx, res, u, body);
          case 'POST /api/shutdown': return await handleShutdown(ctx, res);
          default: return json(res, 404, { ok: false, code: 'NOT_FOUND' });
        }
      } catch {
        return json(res, 500, { ok: false, code: 'INTERNAL_ERROR' });
      }
    });

    ttlTimer = setTimeout(() => finish('UI_TOKEN_EXPIRED'), ttlMs);
    ttlTimer.unref?.();

    server.once('error', (e) => {
      if (!listening) { finished = true; return rejectStart(e); }
      finish('UI_SERVER_ERROR');
    });
    server.listen(0, '127.0.0.1', () => {
      listening = true;
      const port = (server.address() as any)?.port ?? 0;
      resolveStart({
        port,
        token: apiToken,
        url: `http://127.0.0.1:${port}/?t=${pageToken}`,
        done,
        close: (code = 'UI_SHUTDOWN') => finish(code),
      });
    });
  });
}
