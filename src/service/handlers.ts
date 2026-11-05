// Credential Service — request handlers. This is the secret boundary: every
// op that touches master keys, sessions, KDBX contents, or worker stdin runs
// HERE, inside the service process / service OS principal. The IPC wire only
// ever carries metadata and sanitized results.
//
// Policy is re-evaluated service-side on every op (the declared agent id is
// part of the request — same declared-identity model as the CLI, enforced at
// the trust boundary so a hand-rolled IPC client cannot skip the CLI gate).
// Each handled op writes exactly one audit record to the SERVICE-side audit
// log (agent-unreadable — the authoritative hardened audit trail).

import { evaluate, agentPolicy, entryPermitted, resolveAgentId } from '../policy/engine.ts';
import { loadConfig } from '../config/config.ts';
import { audit, readAudit, AUDIT_MAX_BYTES_DEFAULT } from '../policy/audit.ts';
import { listEntries, pipeSecretToWorker, normalizeHost } from '../broker/broker.ts';
import { dbState, lock } from '../master-key/manager.ts';
import { resolveWorker } from '../worker/registry.ts';
import { requestUnlock, requestCreate, requestAddEntry, requestCookieSync, waitForUnlock, type UnlockRequest, type SubmissionInfo } from '../unlock-server/server.ts';
import { openPage, isLoopbackCdpEndpoint } from '../cdp/cookies.ts';
import type { AppConfig, DbConfig } from '../config/config.ts';
import type { WireMsg } from './protocol.ts';

export interface ServiceContext {
  cfg: AppConfig;
  kpscript: string | string[];
  auditMaxBytes: number;
}

/** Action each op/mode is gated under (policy + audit action name). */
const OP_ACTION: Record<string, string | undefined> = {
  hello: undefined,           // unauthenticated-shape health — no policy record
  status: 'status',
  list: 'search',
  login: 'login',
  lock: 'lock',
  audit: 'audit.read',
};
const APPROVAL_ACTION: Record<string, string> = {
  unlock: 'unlock',
  create: 'db.create',
  entry: 'entry.add',
  cookies: 'entry.sync-cookies', // capture variant re-gated by client detail
};

interface GateFail { ok: false; code: string; detail?: string; policy?: string }

/**
 * Service-side gate: evaluate the declared agent's policy for the action;
 * `require_approval` satisfies approval ops only (the op IS the approval
 * channel — same rule as the CLI's APPROVABLE_ACTIONS check). A non-'allow'
 * decision for a non-approval op denies with an explicit code.
 */
function gate(ctx: ServiceContext, agent: string, action: string, db: string | undefined,
  target: Parameters<typeof evaluate>[3], isApprovalOp: boolean): GateFail | null {
  const ev = evaluate(ctx.cfg, agent, action, target);
  const auditDecision = ev.decision;
  const deny = (code: string): GateFail => {
    audit({ agent, action, db, decision: auditDecision, result_code: code }, ctx.auditMaxBytes);
    return { ok: false, code, detail: ev.reason.slice(0, 200), policy: ev.policy };
  };
  if (ev.decision === 'allow') return null;
  if (ev.decision === 'require_approval' && isApprovalOp) return null;
  return deny(ev.decision === 'require_approval' ? 'POLICY_APPROVAL_REQUIRED' : 'POLICY_DENIED');
}

function ok(extra: WireMsg = {}): WireMsg { return { ok: true, ...extra }; }
function bad(code: string, extra: WireMsg = {}): WireMsg { return { ok: false, code, ...extra }; }

function dbOf(ctx: ServiceContext, alias: string | undefined): { ok: true; alias: string; db: DbConfig } | { ok: false; code: string } {
  const a = alias || ctx.cfg.keepass.default_database || '';
  const db = ctx.cfg.databases[a];
  if (!a || !db) return { ok: false, code: 'DATABASE_NOT_FOUND' };
  return { ok: true, alias: a, db };
}

/**
 * Dispatch a validated request. `sendInterim` streams non-final frames
 * (approval URL) to the client while the op is in flight.
 */
export async function handleRequest(
  msg: { op: string; agent?: string } & WireMsg,
  ctx: ServiceContext,
  sendInterim: (m: WireMsg) => void,
): Promise<WireMsg> {
  // Config may change between service start and now (db add/remove, policy
  // edits) — refresh per request; keep the last good copy on read failure.
  try { ctx.cfg = loadConfig(); } catch { /* keep last good cfg */ }
  const agentRes = resolveAgentId(process.env, msg.agent);
  const agent = agentRes.ok ? agentRes.agent : 'unknown';
  const dbAlias = typeof msg.db === 'string' ? msg.db : undefined;

  // 'hello' is the only unauthenticated-shape op — it proves the handshake
  // completed (the caller already holds the capability token) without
  // touching any credential surface.
  if (msg.op === 'hello') {
    // Minimised health response — pid/uptime are unnecessary disclosures to
    // any token-holding caller; uid stays because it proves the principal.
    return ok({
      service: 'kp-credential-service',
      version: 1,
      platform: process.platform,
      uid: typeof process.getuid === 'function' ? process.getuid() : undefined,
    });
  }

  if (!agentRes.ok) {
    audit({ agent, action: msg.op, db: dbAlias, decision: 'deny', result_code: 'INVALID_AGENT_ID' }, ctx.auditMaxBytes);
    return bad('INVALID_AGENT_ID', { detail: 'agent id must match [A-Za-z0-9_-]{1,64}' });
  }

  switch (msg.op) {
    case 'status': {
      const g = gate(ctx, agent, 'status', dbAlias, {}, false);
      if (g) return g;
      const states = dbAlias
        ? { [dbAlias]: dbState(dbAlias) }
        : Object.fromEntries(Object.keys(ctx.cfg.databases).map((a) => [a, dbState(a)]));
      audit({ agent, action: 'status', db: dbAlias, decision: 'allow', result_code: 'OK' }, ctx.auditMaxBytes);
      return ok({ states });
    }

    case 'list': {
      const r = dbOf(ctx, dbAlias);
      if (!r.ok) return bad(r.code);
      const g = gate(ctx, agent, 'search', r.alias, {}, false);
      if (g) return g;
      const l = await listEntries(ctx.kpscript, r.alias, r.db);
      if (!l.ok) {
        audit({ agent, action: 'search', db: r.alias, decision: 'allow', result_code: l.code }, ctx.auditMaxBytes);
        return bad(l.code!);
      }
      // Entry remit applied service-side — out-of-remit entries never leave.
      const pol = agentPolicy(ctx.cfg, agent);
      const entries = (l.entries ?? []).filter((e) => entryPermitted(pol, e));
      audit({ agent, action: 'search', db: r.alias, decision: 'allow', result_code: 'OK' }, ctx.auditMaxBytes);
      return ok({ entries });
    }

    case 'login': {
      const r = dbOf(ctx, dbAlias);
      if (!r.ok) return bad(r.code);
      const uuid = typeof msg.entry === 'string' ? msg.entry : '';
      const workerName = typeof msg.worker === 'string' ? msg.worker : 'local-test';
      const w = resolveWorker(workerName);
      if (!w.ok) return bad('UNSUPPORTED_WORKER');
      const l = await listEntries(ctx.kpscript, r.alias, r.db);
      if (!l.ok) {
        audit({ agent, action: 'login', db: r.alias, decision: 'allow', result_code: l.code }, ctx.auditMaxBytes);
        return bad(l.code!);
      }
      const entry = l.entries?.find((e) => e.id === uuid);
      if (!entry) {
        audit({ agent, action: 'login', db: r.alias, decision: 'allow', result_code: 'ENTRY_NOT_FOUND', target: `entry:${uuid}` }, ctx.auditMaxBytes);
        return bad('ENTRY_NOT_FOUND', { entry: uuid });
      }
      const host = normalizeHost(entry.url) ?? '';
      const g = gate(ctx, agent, 'login', r.alias, { entry: { id: entry.id, title: entry.title, url: entry.url }, host }, false);
      if (g) return g;
      // The service resolves the worker AND builds the args/meta itself —
      // meta.url is always the vault entry's URL, never client-supplied.
      const res = await pipeSecretToWorker(
        ctx.kpscript, r.alias, r.db, entry.id, w.cmd!,
        ['--url', entry.url || ''],
        { db: r.alias, entry: entry.id, username: entry.username, url: entry.url || '' },
        {
          timeoutMs: w.timeoutMs,
          // Pipe-boundary re-check, same as the Standard Mode broker path.
          policyGate: () => evaluate(ctx.cfg, agent, 'login',
            { entry: { id: entry.id, title: entry.title, url: entry.url }, host }),
        },
      );
      audit({
        agent, action: 'login', db: r.alias, target: `entry:${entry.id}`,
        decision: 'allow', result_code: res.ok ? 'OK' : res.code,
      }, ctx.auditMaxBytes);
      return { ok: res.ok, ...(res.ok ? { status: res.detail || 'authenticated' } : { code: res.code, detail: res.detail }) };
    }

    case 'lock': {
      const r = dbOf(ctx, dbAlias);
      if (!r.ok) return bad(r.code);
      const g = gate(ctx, agent, 'lock', r.alias, {}, false);
      if (g) return g;
      lock(r.alias);
      audit({ agent, action: 'lock', db: r.alias, decision: 'allow', result_code: 'OK' }, ctx.auditMaxBytes);
      return ok({ status: 'locked' });
    }

    case 'audit': {
      const g = gate(ctx, agent, 'audit.read', undefined, {}, false);
      if (g) return g;
      const n = Number.isInteger(msg.limit) ? msg.limit : 100;
      const events = readAudit(Math.max(1, Math.min(n, 1000)));
      audit({ agent, action: 'audit.read', decision: 'allow', result_code: 'OK' }, ctx.auditMaxBytes);
      return ok({ events });
    }

    case 'approval':
      return handleApproval(msg, ctx, agent, sendInterim);

    default:
      return bad('HARDENED_IPC_ERROR', { detail: 'unknown op' });
  }
}

/**
 * Post-parse submission gate (F1) — attached to every service-created
 * approval request and invoked inside the web flow AFTER the form's real
 * values are parsed but BEFORE they are applied. Two checks:
 *   1. evaluate() against the SUBMITTED target (entry url/title, cookies
 *      domain/uuid, unlock db) — a request gated on `target={}` at creation
 *      cannot hide behind a form the human (or a script) edited.
 *   2. Final-payload consistency: for entry adds the submitted fields must
 *      match the declared prefill; for cookies/unlock the submitted target
 *      must not drift from the approved request. Mismatch → POLICY_DENIED.
 */
export function makeSubmissionGate(
  ctx: ServiceContext, agent: string, cookieAction: string, req: UnlockRequest,
): (s: SubmissionInfo) => { ok: boolean; code?: string; detail?: string } {
  return (s) => {
    const action = s.mode === 'cookies' ? cookieAction
      : s.mode === 'create' ? 'db.create'
      : s.mode === 'entry' ? 'entry.add' : 'unlock';
    const target: Parameters<typeof evaluate>[3] = {};
    if (s.entry) target.entry = s.entry;
    const host = s.host || (s.entry?.url ? normalizeHost(s.entry.url) ?? '' : '');
    if (host) target.host = host;
    const ev = evaluate(ctx.cfg, agent, action, target);
    // Cross-action submissions (e.g. an unlock-mode page posting its create
    // section) were approved for a DIFFERENT action than the submitted one —
    // require_approval is satisfied only when the request itself is the
    // matching approval channel, so cross-action requires a strict 'allow'.
    const crossAction = s.mode !== req.mode;
    const satisfied = ev.decision === 'allow' || (!crossAction && ev.decision === 'require_approval');
    if (!satisfied) {
      audit({
        agent, action, db: s.db, decision: ev.decision, result_code: 'POLICY_DENIED',
        target: s.entry?.id ? `entry:${s.entry.id}` : s.entry?.title ? `title:${s.entry.title}`
          : host ? `host:${host}` : undefined,
      }, ctx.auditMaxBytes);
      return { ok: false, code: 'POLICY_DENIED', detail: ev.reason.slice(0, 200) };
    }
    // Target drift — the submitted db must equal the approved request's db
    // for every same-action mode (entry/cookies/unlock), and a create-mode
    // request also pins its declared alias+path. pageCreate (unlock-mode req
    // submitting action=create) has no declared target to compare.
    if (s.mode === 'create') {
      if (req.mode === 'create' && (s.db !== req.db || s.path !== req.targetPath))
        return { ok: false, code: 'POLICY_DENIED', detail: 'create target drifted from approved request' };
    } else if (s.db !== req.db)
      return { ok: false, code: 'POLICY_DENIED', detail: 'target db drifted from approved request' };
    if (s.mode === 'entry' && req.prefill) {
      // Declared-vs-submitted consistency for the concrete payload fields.
      // `url` compares on normalized host (cosmetic URL edits are cosmetic);
      // the rest compare verbatim — any drift means the approved intent no
      // longer matches what would be written.
      const wantUrl = req.prefill.url;
      if (wantUrl && normalizeHost(s.fields?.url ?? '') !== normalizeHost(wantUrl))
        return { ok: false, code: 'POLICY_DENIED', detail: "submission 'url' differs from approved prefill" };
      for (const f of ['title', 'username', 'notes'] as const) {
        const want = req.prefill[f];
        if (want != null && want !== '' && (s.fields?.[f] ?? '') !== want)
          return { ok: false, code: 'POLICY_DENIED', detail: `submission '${f}' differs from approved prefill` };
      }
    }
    if (s.mode === 'cookies'
      && (s.entry?.id !== req.entryUuid || (s.host ?? '') !== (req.domain ?? '')))
      return { ok: false, code: 'POLICY_DENIED', detail: 'cookies target drifted from approved request' };
    return { ok: true };
  };
}

/**
 * Web-approval ops — the browser round-trip runs INSIDE the service: the
 * master key travels browser → service directly and never transits the agent
 * process or the IPC channel. The service emits the approval URL as an
 * interim frame; the client decides how to open it (local browser per
 * cfg.unlock.auto_open_browser, or CDP page for login-capture).
 */
async function handleApproval(
  msg: WireMsg, ctx: ServiceContext, agent: string,
  sendInterim: (m: WireMsg) => void,
): Promise<WireMsg> {
  const mode = String(msg.mode || '');
  const action = APPROVAL_ACTION[mode];
  if (!action) return bad('HARDENED_IPC_ERROR', { detail: 'approval mode invalid' });
  const dbAlias = typeof msg.db === 'string' ? msg.db : undefined;

  // Entry-scoped pre-gate for entry.add prefill / cookies targets — mirrors
  // the CLI's gate() target evaluation so the service denies the same set.
  const target: Parameters<typeof evaluate>[3] = {};
  if (mode === 'entry' && (msg.prefill?.title || msg.prefill?.url)) {
    target.entry = { title: msg.prefill.title, url: msg.prefill.url };
    if (msg.prefill.url) target.host = normalizeHost(String(msg.prefill.url)) ?? '';
  }
  // login-capture carries its own action name for policy scoping.
  const effAction = (mode === 'cookies' && msg.capture === true) ? 'entry.login-capture' : action;
  const g = gate(ctx, agent, effAction, dbAlias, target, true);
  if (g) return g;

  let req: UnlockRequest;
  const dbs: Record<string, DbConfig> = {};
  if (mode === 'create') {
    const targetPath = typeof msg.targetPath === 'string' ? msg.targetPath : '';
    if (!targetPath) return bad('INVALID_CONFIG', { detail: 'targetPath required' });
    req = requestCreate(dbAlias || '', targetPath, typeof msg.keyFile === 'string' ? msg.keyFile : undefined, agent);
  } else {
    const r = dbOf(ctx, dbAlias);
    if (!r.ok) return bad(r.code);
    dbs[r.alias] = r.db;
    if (mode === 'unlock') {
      req = requestUnlock(r.alias, agent);
    } else if (mode === 'entry') {
      const p = (msg.prefill && typeof msg.prefill === 'object') ? msg.prefill : {};
      req = requestAddEntry(r.alias, {
        title: typeof p.title === 'string' ? p.title : undefined,
        url: typeof p.url === 'string' ? p.url : undefined,
        username: typeof p.username === 'string' ? p.username : undefined,
        notes: typeof p.notes === 'string' ? p.notes : undefined,
      }, agent);
    } else {
      // cookies — entry uuid + domain + endpoint arrive from the client's
      // already-resolved entry; the service re-validates endpoint loopback.
      const entryUuid = typeof msg.entryUuid === 'string' ? msg.entryUuid : '';
      const domain = typeof msg.domain === 'string' ? msg.domain : '';
      const ep = typeof msg.cdpEndpoint === 'string' ? msg.cdpEndpoint : '';
      if (!entryUuid || !domain) return bad('INVALID_CONFIG', { detail: 'entryUuid and domain required' });
      if (!isLoopbackCdpEndpoint(ep)) return bad('CDP_ENDPOINT_REJECTED');
      req = requestCookieSync(r.alias, entryUuid, domain, ep, agent);
      if (typeof msg.openUrl === 'string' && msg.openUrl) {
        // login-capture: service drives the user's CDP browser (loopback) —
        // open the entry URL now; the approval page follows in the interim
        // callback once the URL exists. Only http(s) may be navigated —
        // file:/javascript:/data: URLs are rejected outright (F6).
        let proto = '';
        try { proto = new URL(msg.openUrl).protocol; } catch {}
        if (proto !== 'http:' && proto !== 'https:')
          return bad('INVALID_CONFIG', { detail: 'openUrl must be an http(s) URL' });
        await openPage(ep, msg.openUrl);
        (req as any).__cdpOpen = { ep };
      }
    }
  }
  // The service never spawns a local browser — URL delivery is interim-frame
  // only; the client (operator principal) opens it.
  req.noAutoOpen = true;
  // Post-parse gate: the web flow re-validates the ACTUAL submitted values
  // against policy + approved targets before applying them (F1).
  req.submissionGate = makeSubmissionGate(ctx, agent, effAction, req);

  const res = await waitForUnlock(ctx.cfg, ctx.kpscript, req, { ...ctx.cfg.databases, ...dbs }, async (url) => {
    sendInterim({ url });
    const cdpOpen = (req as any).__cdpOpen;
    if (cdpOpen) { try { await openPage(cdpOpen.ep, url); } catch {} }
  });
  if (!res.ok) {
    audit({ agent, action: effAction, db: dbAlias, decision: 'allow', result_code: res.code }, ctx.auditMaxBytes);
    return bad(res.code || 'APPROVAL_FAILED', { detail: res.status });
  }
  audit({
    agent, action: effAction, db: res.database || dbAlias,
    target: res.uuid ? `entry:${res.uuid}` : undefined,
    decision: 'allow', result_code: 'OK',
  }, ctx.auditMaxBytes);
  return ok({
    status: res.status, database: res.database, path: res.path,
    uuid: res.uuid, domain: res.domain, count: res.count,
    warnings: res.warnings,
  });
}
