// MCP Adapter — tool definitions and policy/audit-gated handlers.
//
// Shared application layer: handlers dispatch into the SAME modules the
// CLI routes through (broker / master-key / unlock-server / policy engine /
// hardened service client). kp.ts's argument-parsing glue is intentionally
// not exported — this file re-implements only the thin orchestration for
// the exposed tools, preserving every security decision the CLI makes:
//
//   - every tool call is evaluate()d deny-by-default under the canonical
//     CLI action name (search/unlock/status/login/lock/audit.read) — the
//     operator's [agents.*] policy applies verbatim across transports;
//   - exactly one audit record per call, action = `mcp.<tool>`;
//   - no handler ever touches a secret-bearing API: listEntries returns
//     metadata only, pipeSecretToWorker returns a sanitized worker result,
//     and hardened IPC carries no secrets by design;
//   - response objects follow the CLI JSON family — {success,...} or
//     {success:false,code,detail} — with no password/secret/cookie fields.
//
// Hardened Mode (hardened.enabled=true) is supported: tools route through
// callService like the CLI (agent → MCP → Credential Service), including
// the same pre-flight ACL gate. No standard-mode fallback ever happens.

import { homedir } from 'node:os';
import { basename } from 'node:path';
import { CONFIG_DIR, loadConfig, fileExists, type AppConfig, type DbConfig } from '../config/config.ts';
import { getDb } from '../database/manager.ts';
import { dbState, lock } from '../master-key/manager.ts';
import { requestUnlock, waitForUnlock, openBrowser, TOKEN_TTL_MS } from '../unlock-server/server.ts';
import { listEntries, searchEntries, pipeSecretToWorker, normalizeHost, type Entry } from '../broker/broker.ts';
import { evaluate, agentPolicy, entryPermitted, APPROVABLE_ACTIONS } from '../policy/engine.ts';
import { audit, readAudit, AUDIT_MAX_BYTES_DEFAULT } from '../policy/audit.ts';
import { callService, type IpcResponse } from '../service/client.ts';
import { hardenedEnabled, resolveTokenFile } from '../service/mode.ts';
import { verifyHardenedEnvironment } from '../service/acl.ts';
import { resolveWorker, workerNames } from '../worker/registry.ts';

type JsonOut = Record<string, any>;

/** A started MCP session — the identity resolved at initialize time. */
export interface McpSession {
  /** Declared agent identity for this session (self-declared, like --agent). */
  agent: string;
  /** False when the declared identity failed charset validation — calls fail INVALID_AGENT_ID. */
  agentOk: boolean;
  /** Config snapshot kept as the last-good fallback between per-call reloads
   *  (undefined until a config.toml can be loaded). */
  cfg: AppConfig | undefined;
  /**
   * Provider backend override — same `string | string[]` argv convention as
   * `ServiceContext.kpscript` (the [exe, ...prefix] form lets tests inject a
   * mock backend). Unset → derived from cfg.keepass.kpscript.
   */
  kpscript?: string | string[];
  /** Diagnostics sink — stderr in production; stdout stays protocol-only. */
  log: (line: string) => void;
}

/** Error-path hygiene identical to kp.ts's sanitizeDetail (T8). */
function sanitizeDetail(s: string): string {
  return s.replaceAll(CONFIG_DIR, basename(CONFIG_DIR)).replaceAll(homedir(), '~').slice(0, 200);
}

function fail(code: string, extra: JsonOut = {}): JsonOut {
  return { success: false, code, ...extra };
}

interface ToolDef {
  /** Canonical CLI action name the call is policy-gated under. */
  action: string;
  description: string;
  inputSchema: Record<string, any>;
  run: (ctx: CallCtx, args: Record<string, any>) => Promise<JsonOut>;
}

/** Per-call mutable context — the audit record fields assembled in flight. */
interface CallCtx {
  session: McpSession;
  cfg: AppConfig;
  action: string;
  db?: string;
  decision: string;
  target?: string;
  hard: boolean;
  kpscript: string | string[];
}

/**
 * Filesystem-side hardened isolation gate — identical checks to kp.ts's
 * hardGate(): token file ACL plus per-KDBX isolation before a request is
 * attempted. Returns the failure object or null.
 */
function hardGate(ctx: CallCtx, kdbxPaths: string[] = []): JsonOut | null {
  const fails = verifyHardenedEnvironment(ctx.cfg, {
    tokenPath: resolveTokenFile(ctx.cfg), kdbxPaths,
  });
  if (!fails.length) return null;
  return fail('HARDENED_ACL_UNMET', {
    detail: fails.map((f) => `${f.check}:${f.detail ?? 'unmet'}`).join('; '),
    checks: fails.map((f) => ({ check: f.check, path: f.path, detail: f.detail })),
  });
}

function svc(ctx: CallCtx, op: string, params: Record<string, any> = {},
  opts: { timeoutMs?: number; onInterim?: (m: Record<string, any>) => void } = {}): Promise<IpcResponse> {
  return callService(ctx.cfg, op, { agent: ctx.session.agent, ...params }, opts);
}

/**
 * Second-phase entry gate — same as kp.ts's gateEntry(): applies
 * allowed_entries/denied_entries and (for login) allowed_hosts against the
 * concrete resolved entry, and stamps the audit target with its uuid.
 */
function gateEntry(ctx: CallCtx, entry: { id: string; title: string; url: string }): JsonOut | null {
  ctx.target = `entry:${entry.id}`;
  const ev = evaluate(ctx.cfg, ctx.session.agent, ctx.action,
    { entry, host: normalizeHost(entry.url) ?? '' });
  if (ev.decision === 'allow') return null;
  ctx.decision = ev.decision;
  if (ev.decision === 'require_approval' && APPROVABLE_ACTIONS.has(ctx.action)) return null;
  return fail(ev.decision === 'require_approval' ? 'POLICY_APPROVAL_REQUIRED' : 'POLICY_DENIED',
    { detail: sanitizeDetail(ev.reason), policy: ev.policy, entry: entry.id });
}

function resolveDb(ctx: CallCtx, raw: unknown): { ok: true; alias: string; db: DbConfig } | { ok: false; out: JsonOut } {
  const r = getDb(ctx.cfg, typeof raw === 'string' ? raw : '');
  if (!r.ok) return { ok: false, out: fail(r.code!, { alias: r.alias }) };
  ctx.db = r.alias;
  return { ok: true, alias: r.alias!, db: r.db! };
}

const kpscriptPath = (cfg: AppConfig): string =>
  cfg.keepass.kpscript && fileExists(cfg.keepass.kpscript) ? cfg.keepass.kpscript : '';

/** Entry list for the resolved db — service IPC in hardened mode, provider otherwise. */
async function entryList(ctx: CallCtx, alias: string, db: DbConfig): Promise<{ ok: boolean; out?: JsonOut; entries?: Entry[] }> {
  if (ctx.hard) {
    const g = hardGate(ctx, [db.path]);
    if (g) return { ok: false, out: g };
    const r = await svc(ctx, 'list', { db: alias });
    if (!r.ok) return { ok: false, out: fail(r.code || 'HARDENED_IPC_ERROR', { detail: r.detail }) };
    return { ok: true, entries: (r.entries ?? []) as Entry[] };
  }
  const l = await listEntries(ctx.kpscript, alias, db);
  if (!l.ok) return { ok: false, out: fail(l.code!) };
  return { ok: true, entries: l.entries };
}

/** The projection every entry surface is constrained to — never more. */
const publicEntry = (e: Entry) => ({ id: e.id, title: e.title, username: e.username, url: e.url });

const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);

// --- tool definitions ---------------------------------------------------

const TOOLS: Record<string, ToolDef> = {
  search_entries: {
    action: 'search',
    description: 'Search vault entries. Returns id/title/username/url metadata ONLY — passwords and secrets are never returned.',
    inputSchema: {
      type: 'object',
      properties: {
        db: { type: 'string', description: 'database alias (default: configured default_database)' },
        query: { type: 'string', description: 'substring matched against title, username, and url' },
        site: { type: 'string', description: 'host/domain filter (dot-boundary)' },
        title: { type: 'string' },
        username: { type: 'string' },
      },
      additionalProperties: false,
    },
    async run(ctx, a) {
      const query = str(a.query), site = str(a.site), title = str(a.title), username = str(a.username);
      if (!query && !site && !title && !username)
        return fail('INVALID_CONFIG', { detail: 'provide query, site, title, or username' });
      const r = resolveDb(ctx, a.db);
      if (!r.ok) return r.out;
      if (!ctx.hard && dbState(r.alias) !== 'UNLOCKED')
        return fail('UNLOCK_REQUIRED', { database: r.alias, status: 'locked', action: 'user_unlock_required' });
      const l = await entryList(ctx, r.alias, r.db);
      if (!l.ok) return l.out!;
      ctx.target = `query:${[query, site, title, username].filter(Boolean).join('|')}`;
      const needle = query?.toLowerCase();
      let matches = needle
        ? l.entries!.filter((e) => [e.title, e.username, e.url].some((f) => f?.toLowerCase().includes(needle)))
        : searchEntries(l.entries!, { site, title, username });
      // Entry remit filter, same as the CLI — out-of-remit entries are
      // invisible even in search results.
      const pol = agentPolicy(ctx.cfg, ctx.session.agent);
      matches = matches.filter((e) => entryPermitted(pol, e));
      return { success: true, database: r.alias, matches: matches.map(publicEntry) };
    },
  },

  request_unlock: {
    action: 'unlock',
    description: 'Request a vault unlock via the local web approval flow. Returns a one-time approval URL for the human — master keys are never collected through MCP.',
    inputSchema: {
      type: 'object',
      properties: { db: { type: 'string', description: 'database alias (default: configured default_database)' } },
      additionalProperties: false,
    },
    async run(ctx, a) {
      const r = resolveDb(ctx, a.db);
      if (!r.ok) return r.out;
      const method = r.db.unlock_method || 'local-web';
      if (method !== 'local-web')
        return fail('INVALID_CONFIG', { detail: `unlock_method '${method}' is not supported via MCP — run 'kp unlock' (external launch is outside the MCP surface)` });
      if (ctx.hard) {
        const g = hardGate(ctx, [r.db.path]);
        if (g) return g;
        // The approval round-trip executes inside the service; the URL
        // arrives as an interim frame — respond as soon as it lands and let
        // the approval conclude in the background (session_status polls).
        return await new Promise<JsonOut>((resolve) => {
          let delivered = false;
          void svc(ctx, 'approval', { mode: 'unlock', db: r.alias }, {
            onInterim: (m) => {
              if (delivered || typeof m?.url !== 'string' || !m.url) return;
              delivered = true;
              if (ctx.cfg.unlock.auto_open_browser) { try { openBrowser(m.url); } catch {} }
              resolve({ success: true, database: r.alias, status: 'awaiting_user_input', url: m.url, expires_in_seconds: TOKEN_TTL_MS / 1000 });
            },
          }).then((res) => {
            if (!delivered) resolve(fail(res.code || 'HARDENED_IPC_ERROR', { detail: res.detail }));
            else ctx.session.log(`mcp: unlock ${r.alias} finished: ${res.ok ? res.status || 'unlocked' : res.code}`);
          });
        });
      }
      if (!ctx.kpscript && process.platform === 'win32')
        return fail('INVALID_CONFIG', { detail: 'keepass.kpscript not configured' });
      // The unlock server binds inside this process — auto-open honors the
      // same cfg.unlock.auto_open_browser flag as the CLI, and the served
      // URL reports the actual bound port (ephemeral fallback on collision).
      return await new Promise<JsonOut>((resolve) => {
        let delivered = false;
        const req = requestUnlock(r.alias!, ctx.session.agent);
        void waitForUnlock(ctx.cfg, ctx.kpscript, req, { [r.alias!]: r.db }, (url) => {
          delivered = true;
          resolve({ success: true, database: r.alias, status: 'awaiting_user_input', url, expires_in_seconds: TOKEN_TTL_MS / 1000 });
        }).then((res) => {
          if (!delivered) resolve(fail(res.code || 'UNLOCK_SERVER_ERROR'));
          else ctx.session.log(`mcp: unlock ${res.database || r.alias} finished: ${res.ok ? res.status || 'unlocked' : res.code}`);
        });
      });
    },
  },

  session_status: {
    action: 'status',
    description: 'Report per-database session state (LOCKED/UNLOCKED/EXPIRED; UNAVAILABLE when the hardened service is down).',
    inputSchema: {
      type: 'object',
      properties: { db: { type: 'string', description: 'database alias — omit for all databases' } },
      additionalProperties: false,
    },
    async run(ctx, a) {
      const alias = str(a.db);
      if (!ctx.hard) {
        if (alias) {
          const r = resolveDb(ctx, a.db);
          if (!r.ok) return r.out;
          return { success: true, mode: 'standard', alias: r.alias, status: dbState(r.alias) };
        }
        const all = Object.fromEntries(Object.keys(ctx.cfg.databases).map((d) => [d, dbState(d)]));
        return { success: true, mode: 'standard', databases: all };
      }
      // Hardened: session state lives with the service principal. Transport
      // failures report UNAVAILABLE (the same reporting contract as
      // `kp status`); service-level denials surface as failures.
      if (alias) {
        const r = resolveDb(ctx, a.db);
        if (!r.ok) return r.out;
      }
      const res = await svc(ctx, 'status', alias ? { db: alias } : {});
      if (!res.ok && String(res.code || '').startsWith('HARDENED_')) {
        if (alias) return { success: true, mode: 'unavailable', alias, status: 'UNAVAILABLE' };
        return {
          success: true, mode: 'unavailable',
          databases: Object.fromEntries(Object.keys(ctx.cfg.databases).map((d) => [d, 'UNAVAILABLE'])),
        };
      }
      if (!res.ok) return fail(res.code || 'HARDENED_IPC_ERROR', { detail: res.detail });
      const states = res.states ?? {};
      if (alias) return { success: true, mode: 'hardened', alias, status: states[alias] ?? 'LOCKED' };
      return { success: true, mode: 'hardened', databases: states };
    },
  },

  request_login: {
    action: 'login',
    description: 'Pipe an entry credential to an approved worker. Returns the sanitized worker result ({success,status} or {success:false,code}) — the secret is never returned.',
    inputSchema: {
      type: 'object',
      properties: {
        db: { type: 'string' },
        entry: { type: 'string', description: 'entry uuid' },
        title: { type: 'string' },
        site: { type: 'string' },
        username: { type: 'string' },
        worker: { type: 'string', description: `worker name (allowlisted; default 'local-test')` },
      },
      additionalProperties: false,
    },
    async run(ctx, a) {
      const r = resolveDb(ctx, a.db);
      if (!r.ok) return r.out;
      if (!ctx.hard && dbState(r.alias) !== 'UNLOCKED')
        return fail('UNLOCK_REQUIRED', { database: r.alias, status: 'locked', action: 'user_unlock_required' });
      const l = await entryList(ctx, r.alias, r.db);
      if (!l.ok) return l.out!;
      const entries = l.entries!;
      let uuid = str(a.entry) || '';
      if (!uuid) {
        // Out-of-remit entries must not appear in the AMBIGUOUS_ENTRY list.
        const pol = agentPolicy(ctx.cfg, ctx.session.agent);
        const matches = searchEntries(entries, {
          title: str(a.title), site: str(a.site), username: str(a.username),
        }).filter((e) => entryPermitted(pol, e));
        if (matches.length === 0) return fail('ENTRY_NOT_FOUND');
        if (matches.length > 1) return fail('AMBIGUOUS_ENTRY', { matches: matches.map((e) => ({ id: e.id, title: e.title })) });
        uuid = matches[0].id;
      }
      const workerName = str(a.worker) || 'local-test';
      const worker = resolveWorker(workerName);
      if (!worker.ok) return fail('UNSUPPORTED_WORKER', { available: workerNames() });
      const entry = entries.find((e) => e.id === uuid);
      if (!entry) return fail('ENTRY_NOT_FOUND', { entry: uuid });
      const g = gateEntry(ctx, entry);
      if (g) return g;
      if (ctx.hard) {
        // Secret boundary: the service resolves the worker and pipes the
        // secret itself — nothing secret exists in this process.
        const res = await svc(ctx, 'login', { db: r.alias, entry: uuid, worker: workerName });
        if (!res.ok) return fail(res.code || 'HARDENED_IPC_ERROR', { detail: res.detail, entry_id: uuid });
        return { success: true, database: r.alias, entry_id: uuid, status: res.status || 'authenticated' };
      }
      const res = await pipeSecretToWorker(
        ctx.kpscript, r.alias, r.db, uuid, worker.cmd!,
        ['--url', entry.url || ''],
        { db: r.alias, entry: uuid, username: entry.username, url: entry.url || '' },
        {
          timeoutMs: worker.timeoutMs,
          // Pipe-boundary re-check — same backstop as the CLI path.
          policyGate: () => evaluate(ctx.cfg, ctx.session.agent, 'login',
            { entry: { id: entry.id, title: entry.title, url: entry.url }, host: normalizeHost(entry.url) ?? '' }),
        },
      );
      return {
        success: res.ok, database: r.alias, entry_id: uuid,
        status: res.detail || (res.ok ? 'authenticated' : res.code),
        ...(res.ok ? {} : { code: res.code }),
      };
    },
  },

  logout: {
    action: 'lock',
    description: 'Revoke the session for a database (drops the cached master key).',
    inputSchema: {
      type: 'object',
      properties: { db: { type: 'string', description: 'database alias (default: configured default_database)' } },
      additionalProperties: false,
    },
    async run(ctx, a) { return logoutRun(ctx, a); },
  },

  revoke_session: {
    action: 'lock',
    description: 'Alias of logout — revoke the session for a database.',
    inputSchema: {
      type: 'object',
      properties: { db: { type: 'string', description: 'database alias (default: configured default_database)' } },
      additionalProperties: false,
    },
    async run(ctx, a) { return logoutRun(ctx, a); },
  },

  audit_tail: {
    action: 'audit.read',
    description: 'Read the JSONL audit log tail (policy-gated). Records contain no secrets — {ts, agent, action, target, decision, result_code, db}.',
    inputSchema: {
      type: 'object',
      properties: { limit: { type: 'integer', minimum: 1, maximum: 1000 } },
      additionalProperties: false,
    },
    async run(ctx, a) {
      const n = Number.isInteger(a.limit) ? Math.max(1, Math.min(Number(a.limit), 1000)) : 100;
      if (ctx.hard) {
        const res = await svc(ctx, 'audit', { limit: n });
        if (!res.ok) return fail(res.code || 'HARDENED_IPC_ERROR', { detail: res.detail });
        return { success: true, events: res.events ?? [] };
      }
      return { success: true, events: readAudit(n) };
    },
  },
};

async function logoutRun(ctx: CallCtx, a: Record<string, any>): Promise<JsonOut> {
  const alias = str(a.db) || ctx.cfg.keepass.default_database || '';
  ctx.db = alias || undefined;
  if (ctx.hard) {
    const g = hardGate(ctx);
    if (g) return g;
    const res = await svc(ctx, 'lock', { db: alias });
    if (!res.ok) return fail(res.code || 'HARDENED_IPC_ERROR', { detail: res.detail });
    return { success: true, alias, status: res.status || 'locked' };
  }
  lock(alias);
  return { success: true, alias, status: 'locked' };
}

/** Tool descriptors for tools/list — name/description/inputSchema only. */
export function toolList(): { name: string; description: string; inputSchema: Record<string, any> }[] {
  return Object.entries(TOOLS).map(([name, t]) => ({
    name, description: t.description, inputSchema: t.inputSchema,
  }));
}

export function hasTool(name: string): boolean {
  return Object.hasOwn(TOOLS, name);
}

/**
 * Execute one tool call. Config is reloaded per call (same rule as the
 * Credential Service — a live policy/config edit takes effect without
 * restarting the MCP session; the last-good snapshot survives a read
 * failure). Exactly one audit record is written per call — action is
 * `mcp.<tool>` while the POLICY decision uses the canonical CLI action so
 * `[agents.*]` rules apply identically across transports.
 */
export async function callTool(session: McpSession, name: string, args: Record<string, any>): Promise<JsonOut> {
  const def = TOOLS[name];
  try { session.cfg = loadConfig(); } catch { /* keep last good cfg */ }
  const ctx: CallCtx = {
    session,
    cfg: session.cfg as AppConfig,
    action: def.action,
    decision: 'deny',
    hard: session.cfg ? hardenedEnabled(session.cfg) : false,
    kpscript: session.kpscript ?? (session.cfg ? kpscriptPath(session.cfg) : ''),
  };
  let result: JsonOut;
  try {
    if (!session.cfg) {
      result = fail('CONFIG_NOT_FOUND', { hint: 'run: kp config init' });
    } else if (!session.agentOk) {
      result = fail('INVALID_AGENT_ID', { detail: 'agent id must match [A-Za-z0-9_-]{1,64}' });
    } else {
      const ev = evaluate(ctx.cfg, session.agent, ctx.action, {});
      ctx.decision = ev.decision;
      if (ev.decision === 'deny') {
        result = fail('POLICY_DENIED', {
          detail: sanitizeDetail(ev.reason),
          policy: ev.policy,
        });
      } else if (ev.decision === 'require_approval' && !APPROVABLE_ACTIONS.has(ctx.action)) {
        result = fail('POLICY_APPROVAL_REQUIRED', {
          detail: sanitizeDetail(`${ev.reason} — no approval channel exists for '${ctx.action}' yet`),
          policy: ev.policy,
        });
      } else {
        result = await def.run(ctx, args);
      }
    }
  } catch (e) {
    result = fail('INTERNAL_ERROR', { detail: sanitizeDetail(String((e as any)?.message || e)) });
  }
  audit({
    agent: session.agentOk ? session.agent : 'unknown',
    action: `mcp.${name}`, db: ctx.db, target: ctx.target, decision: ctx.decision,
    result_code: result.success ? 'OK' : String(result.code || 'FAIL'),
  }, session.cfg?.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT);
  return result;
}
