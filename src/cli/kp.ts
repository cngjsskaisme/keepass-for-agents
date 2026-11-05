// kp — credential gateway CLI. Thin router: parse → dispatch → JSON out.
// Secrets never appear in any stdout/stderr path.

import { loadConfig, saveConfig, validateConfig, configExists, defaultConfig, CONFIG_PATH, CONFIG_DIR, fileExists, FORBIDDEN_TOML_KEYS, type AgentPolicy, type AppConfig } from '../config/config.ts';
import { listDbs, getDb, addDb, removeDb, setDefault } from '../database/manager.ts';
import { dbState, lock } from '../master-key/manager.ts';
import { requestAddEntry, requestCookieSync, requestCreate, requestUnlock, waitForUnlock, openBrowser, TOKEN_TTL_MS } from '../unlock-server/server.ts';
import { listEntries, searchEntries, pipeSecretToWorker, normalizeHost } from '../broker/broker.ts';
import { resolveAgentId, evaluate, agentPolicy, entryPermitted, APPROVABLE_ACTIONS, type EvalTarget } from '../policy/engine.ts';
import { audit, readAudit, AUDIT_MAX_BYTES_DEFAULT } from '../policy/audit.ts';
import { openPage, isLoopbackCdpEndpoint, DEFAULT_CDP_ENDPOINT } from '../cdp/cookies.ts';
import { callService, probeService, type IpcResponse } from '../service/client.ts';
import { hardenedEnabled, resolveEndpoint, resolveTokenFile } from '../service/mode.ts';
import { verifyHardenedEnvironment } from '../service/acl.ts';
import { resolveWorker, workerNames } from '../worker/registry.ts';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { homedir } from 'node:os';

const EXIT = { ok: 0, fail: 1, config: 2, unlock: 3, auth: 4 } as const;

/**
 * Sprite exec command — tests/CI may set KEEPASS_AGENT_SPRITE_CMD to a JSON
 * argv array (e.g. ["node","tests/fixtures/mock-sprite.mjs"]) replacing the
 * sprite executable; args are always appended, never shell-interpolated.
 * Production callers never set it; behavior is identical when unset.
 */
let spriteOverrideWarned = false;
/** One-shot stderr warning for the CDP endpoint env test-hook (F-1). */
let cdpEnvWarned = false;
function spriteCmd(): { exe: string; prefix: string[] } {
  const raw = process.env.KEEPASS_AGENT_SPRITE_CMD;
  if (raw) {
    if (!spriteOverrideWarned) {
      spriteOverrideWarned = true;
      process.stderr.write('kp: warning: KEEPASS_AGENT_SPRITE_CMD override active — db sync commands route to a test double\n');
    }
    try {
      const a = JSON.parse(raw);
      if (Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === 'string'))
        return { exe: a[0], prefix: a.slice(1) };
    } catch { /* not JSON — treat as a bare executable path */ }
    return { exe: raw, prefix: [] };
  }
  return { exe: process.env.LOCALAPPDATA + '/Programs/Sprite/sprite.exe', prefix: [] };
}

function spriteRun(args: string[]): Promise<{ ok: boolean; out: string; err: string }> {
  return new Promise((resolve) => {
    const { exe, prefix } = spriteCmd();
    const c = spawn(exe, [...prefix, ...args], { windowsHide: true, cwd: process.env.SPRITE_CWD, env: { ...process.env, MSYS2_ARG_CONV_EXCL: '*', MSYS_NO_PATHCONV: '1' } });
    let out = '', err = '';
    c.stdout.on('data', (d) => (out += d));
    c.stderr.on('data', (d) => (err += d));
    c.on('close', (code) => resolve({ ok: code === 0, out, err }));
    c.on('error', (e) => resolve({ ok: false, out, err: String(e) }));
  });
}

type JsonOut = Record<string, any>;

/**
 * Audit context of the in-flight gated command — set by gate()/gateEntry()
 * in main() and flushed exactly once by out()/fail() (the single exit
 * funnel), so every gated action logs one record carrying the policy
 * decision AND the outcome code — success, failure, and denial alike.
 */
let auditCtx: { agent: string; action: string; target?: string; db?: string; decision: string } | null = null;
let auditMaxBytes = AUDIT_MAX_BYTES_DEFAULT;

function flushAudit(resultCode: string): void {
  if (!auditCtx) return;
  const ctx = auditCtx;
  auditCtx = null;
  audit({ ...ctx, result_code: resultCode }, auditMaxBytes);
}

function out(o: JsonOut, code: number = o.success ? EXIT.ok : EXIT.fail): never {
  flushAudit(o.success ? 'OK' : String(o.code || 'FAIL'));
  console.log(JSON.stringify(o, null, 0));
  process.exit(code);
}

function fail(code: string, extra: JsonOut = {}): never {
  out({ success: false, code, ...extra }, code === 'UNLOCK_REQUIRED' ? EXIT.unlock : EXIT.fail);
}

/**
 * Error-path hygiene for agent-visible `detail` text (T8): cap at 200 chars
 * and collapse absolute paths — external/child error text must never carry
 * real filesystem locations (or, by extension, anything sensitive).
 */
function sanitizeDetail(s: string): string {
  return s.replaceAll(CONFIG_DIR, basename(CONFIG_DIR)).replaceAll(homedir(), '~').slice(0, 200);
}

function parseArgs(argv: string[]): { cmd: string[]; flags: Record<string, string | boolean> } {
  const cmd: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) flags[k] = argv[++i];
      else flags[k] = true;
    } else cmd.push(a);
  }
  return { cmd, flags };
}

function findEntry(entries: any[], flags: Record<string, string | boolean>) {
  if (flags.entry) return entries.find((e) => e.id.toLowerCase() === String(flags.entry).replace(/-/g, '').toLowerCase());
  if (flags.title) return searchEntries(entries, { title: String(flags.title) })[0];
  if (flags.site) { const want = normalizeHost(String(flags.site)); return entries.find((e) => normalizeHost(e.url) === want); }
}

// stderr so stdout stays a single JSON result; token URL is a one-time grant,
// same as what the auto-opened browser receives.
function reportUrl(url: string) {
  console.error(JSON.stringify({ notice: 'awaiting_user_input', url, expires_in_seconds: TOKEN_TTL_MS / 1000 }));
}

function kpscriptPath(cfg: any): string {
  const p = cfg.keepass.kpscript;
  return p && fileExists(p) ? p : '';
}

/** db sync sprite name — safe argv token only (no flag-looking or shell chars). */
const SPRITE_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * Remote KDBX path for `db sync` — absolute POSIX, no traversal, no shell
 * metacharacters. Validated even though the value is argv-passed (never
 * shell-interpolated): the remote side is a shared operator environment
 * and a typo'd path is a data-loss vector, not just an injection one (T2).
 */
const REMOTE_PATH_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;
function validRemotePath(p: string): boolean {
  return REMOTE_PATH_RE.test(p) && !p.includes('..') && !p.includes('//');
}

/**
 * --cdp flag policy (T11): the endpoint must be loopback — a remote or
 * attacker-controlled debug socket could both harvest and inject cookies.
 * Same rule applies to the config-less default; the unlock server
 * re-validates the endpoint on the approval path too.
 */
function cdpEndpointArg(flags: Record<string, string | boolean>): string {
  const e = String(flags.cdp || DEFAULT_CDP_ENDPOINT);
  if (!isLoopbackCdpEndpoint(e))
    fail('CDP_ENDPOINT_REJECTED', { detail: 'CDP endpoint must be loopback (127.0.0.1 / localhost / [::1]), any port' });
  return e;
}

async function main() {
  const { cmd, flags } = parseArgs(process.argv.slice(2));
  const [grp, sub] = cmd;

  // Declared agent identity — `--agent` wins over KEEPASS_AGENT_ID; neither →
  // 'default'. Self-declared (not authenticated): it scopes policy + audit
  // attribution only. See src/policy/engine.ts.
  const agentRes = resolveAgentId(process.env, flags.agent);
  const auditAgent = agentRes.ok ? agentRes.agent : 'unknown';

  if (flags.help || grp === 'help' || !grp) return usage();

  // --- config ---
  if (grp === 'config') {
    if (sub === 'init') {
      if (configExists()) return out({ success: true, message: 'config already exists', path: CONFIG_PATH });
      const c = defaultConfig();
      saveConfig(c);
      return out({ success: true, path: CONFIG_PATH });
    }
    if (sub === 'show') {
      if (!configExists()) return fail('CONFIG_NOT_FOUND');
      const c = loadConfig();
      return out({ success: true, config: c, path: CONFIG_PATH });
    }
    if (sub === 'validate') {
      if (!configExists()) return fail('CONFIG_NOT_FOUND');
      const c = loadConfig();
      const errs = validateConfig(c);
      return out({ success: errs.length === 0, errors: errs });
    }
    if (sub === 'set') {
      // kp config set keepass.kpscript "path"
      // Policy keys (agents.<name>.<list-field> as CSV, policy.audit_max_bytes
      // as int) are settable here too — policy change control is delegated to
      // OS file permissions on config.toml (any same-UID process can edit the
      // file anyway). Every change *attempt* is audit-logged — success and
      // failure alike — so a rejected policy write still leaves a trace.
      const key = String(flags.key || cmd[2] || '');
      const val = String(flags.value || cmd[3] || '');
      let c: AppConfig | undefined;
      const auditSet = (rc: string) =>
        audit({ agent: auditAgent, action: 'config.set', target: key || '?', result_code: rc },
          c?.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT);
      if (!key || !val) { auditSet('INVALID_CONFIG'); return fail('INVALID_CONFIG', { detail: 'key and value required' }); }
      try { c = loadConfig(); }
      catch { auditSet('CONFIG_NOT_FOUND'); return fail('CONFIG_NOT_FOUND'); }
      const AGENT_FIELDS = ['allowed', 'require_approval', 'allowed_entries', 'denied_entries', 'allowed_hosts'];
      // F3: hardened.* is operator-managed — letting any same-UID caller flip
      // `hardened.enabled` via `config set` would silently downgrade the
      // isolation mode. cdp.* is the same class: the login worker types vault
      // secrets into the configured endpoint and allow_default_context gates
      // profile mixing — a same-UID caller must not toggle either via
      // `config set`. These keys may only be changed by editing config.toml
      // directly; every attempt is audit-logged.
      if (key.startsWith('hardened.') || key.startsWith('cdp.')) {
        auditSet('CONFIG_KEY_READONLY');
        return fail('CONFIG_KEY_READONLY', { detail: 'hardened.*/cdp.* are operator-managed — edit config.toml directly' });
      }
      if (key === 'keepass.kpscript') c.keepass.kpscript = val;
      else if (key === 'keepass.executable') c.keepass.executable = val;
      else if (key === 'keepass.default_database') c.keepass.default_database = val;
      else if (key === 'policy.audit_max_bytes') {
        const n = Number(val);
        if (!Number.isInteger(n)) { auditSet('INVALID_CONFIG'); return fail('INVALID_CONFIG', { detail: 'policy.audit_max_bytes must be an integer' }); }
        c.policy.audit_max_bytes = n;
      } else if (key.startsWith('agents.')) {
        const parts = key.split('.');
        const field = parts.pop()!;
        const name = parts.slice(1).join('.');
        if (!name || !AGENT_FIELDS.includes(field)) {
          auditSet('INVALID_CONFIG');
          return fail('INVALID_CONFIG', { detail: `unknown agents key ${key} (fields: ${AGENT_FIELDS.join(', ')})` });
        }
        // Object.prototype keys would poison c.agents — rejected explicitly
        // (the name charset alone admits __proto__/constructor/prototype).
        if (FORBIDDEN_TOML_KEYS.has(name.toLowerCase())) {
          auditSet('INVALID_CONFIG');
          return fail('INVALID_CONFIG', { detail: `agents.${name} is a reserved name` });
        }
        if (!Object.hasOwn(c.agents, name)) c.agents[name] = {};
        c.agents[name][field as keyof AgentPolicy] = val.split(',').map((s) => s.trim()).filter(Boolean);
      } else { auditSet('INVALID_CONFIG'); return fail('INVALID_CONFIG', { detail: `unknown key ${key}` }); }
      const errs = validateConfig(c);
      if (errs.length) { auditSet('INVALID_CONFIG'); return fail('INVALID_CONFIG', { errors: errs }); }
      saveConfig(c);
      auditSet('OK');
      return out({ success: true });
    }
    if (sub === 'migrate') {
      // Persist pending schema migrations: loadConfig already upgraded the
      // in-memory view; saving stamps schema_version on disk. A no-op when
      // the file is current. Same contract as `config set` — validate before
      // saving, audit after the save succeeds (and on every failure path).
      let c: AppConfig | undefined;
      const auditMigrate = (rc: string) =>
        audit({ agent: auditAgent, action: 'config.migrate', result_code: rc },
          c?.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT);
      try { c = loadConfig(); }
      catch { auditMigrate('CONFIG_NOT_FOUND'); return fail('CONFIG_NOT_FOUND'); }
      const errs = validateConfig(c);
      if (errs.length) { auditMigrate('INVALID_CONFIG'); return fail('INVALID_CONFIG', { errors: errs }); }
      const applied = c.migrations_applied ?? [];
      if (!applied.length) {
        auditMigrate('OK');
        return out({ success: true, migrated: false, schema_version: c.schema_version });
      }
      saveConfig(c);
      auditMigrate('OK');
      return out({ success: true, migrated: true, applied, schema_version: c.schema_version });
    }
  }

  // --- doctor — read-only environment/dependency diagnostics. Ungated (must
  // work before `config init` and without any policy grant): every probe is
  // stat/spawn-only and nothing here touches secrets. ---
  if (grp === 'doctor') {
    const { runDoctor } = await import('./doctor.ts');
    const report = await runDoctor();
    return out({ ...report, code: report.success ? undefined : 'DOCTOR_FAILED' });
  }

  if (!configExists()) return fail('CONFIG_NOT_FOUND', { hint: 'run: kp config init' });
  const cfg = loadConfig();

  // --- mcp — stdio MCP adapter (JSON-RPC; stdout is protocol-only) ---
  // Every tools/call is policy-gated + audited inside src/mcp/tools.ts — the
  // subcommand itself is not gated (like `config`), it only launches the
  // adapter. An invalid declared identity fails closed before the protocol
  // starts. --agent becomes the session's declared-identity fallback.
  if (grp === 'mcp') {
    if (!agentRes.ok)
      return fail('INVALID_AGENT_ID', { detail: '--agent / KEEPASS_AGENT_ID must match [A-Za-z0-9_-]{1,64}' });
    const { serveMcp } = await import('../mcp/server.ts');
    await serveMcp({ cliAgent: typeof flags.agent === 'string' ? flags.agent : undefined });
    return;
  }
  auditMaxBytes = cfg.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT;
  const agentId = agentRes.ok ? agentRes.agent : 'default';

  /**
   * Hardened Mode dispatch — every credential-touching command below branches
   * on HARD: when enabled, the work happens inside the Credential Service
   * (separate OS principal) over authenticated IPC and NEVER falls back to
   * the in-process Standard path. hardGate() enforces the filesystem-side of
   * the isolation contract before a request is even attempted — token file
   * ACL plus per-KDBX isolation; a failed check is HARDENED_ACL_UNMET.
   */
  const HARD = hardenedEnabled(cfg);
  const hardGate = (kdbxPaths: string[] = []): void => {
    const fails = verifyHardenedEnvironment(cfg, { tokenPath: resolveTokenFile(cfg), kdbxPaths });
    if (fails.length)
      fail('HARDENED_ACL_UNMET', {
        detail: fails.map((f) => `${f.check}:${f.detail ?? 'unmet'}`).join('; '),
        checks: fails.map((f) => ({ check: f.check, path: f.path, detail: f.detail })),
      });
  };
  const svc = (op: string, params: Record<string, any> = {}, opts: { timeoutMs?: number; onInterim?: (m: Record<string, any>) => void } = {}): Promise<IpcResponse> =>
    callService(cfg, op, { agent: agentId, ...params }, opts);
  const svcOrFail = async (op: string, params: Record<string, any> = {}): Promise<IpcResponse> => {
    const r = await svc(op, params);
    if (!r.ok) fail(r.code || 'HARDENED_IPC_ERROR', { detail: r.detail });
    return r;
  };
  /** Session states for status/reporting — 'UNAVAILABLE' when the service is down. */
  const svcStates = async (): Promise<Record<string, string>> => {
    const r = await svc('status');
    return r.ok ? (r.states ?? {}) : {};
  };
  /**
   * Web-approval ops in hardened mode: the browser round-trip executes inside
   * the service (master key travels browser → service, never through the
   * agent process). The approval URL arrives as an interim frame — reported
   * on stderr like the Standard path, and opened locally when configured
   * (login-capture opts out: its page is driven via CDP service-side).
   */
  const runApproval = async (params: Record<string, any>, opts: { openBrowserLocal?: boolean } = {}): Promise<IpcResponse> => {
    let opened = false;
    const r = await svc('approval', params, {
      onInterim: (m) => {
        if (typeof m?.url !== 'string' || !m.url) return;
        reportUrl(m.url);
        if (!opened && (opts.openBrowserLocal ?? cfg.unlock.auto_open_browser)) { openBrowser(m.url); opened = true; }
      },
    });
    if (!r.ok) fail(r.code || 'HARDENED_IPC_ERROR', { detail: r.detail });
    return r;
  };

  /**
   * Policy gate — deny-by-default. Evaluates the action for the declared
   * agent; records the audit context so the eventual out()/fail() logs
   * decision + result together. deny → POLICY_DENIED; require_approval →
   * proceeds only for actions the existing web approval flow can satisfy
   * (APPROVABLE_ACTIONS), otherwise POLICY_APPROVAL_REQUIRED.
   */
  const gate = (action: string, db?: string, target?: EvalTarget): void => {
    if (!agentRes.ok) {
      auditCtx = { agent: auditAgent, action, db, decision: 'deny' };
      fail('INVALID_AGENT_ID', { detail: '--agent / KEEPASS_AGENT_ID must match [A-Za-z0-9_-]{1,64}' });
    }
    const ev = evaluate(cfg, agentId, action, target);
    auditCtx = {
      agent: agentId, action, db, decision: ev.decision,
      target: target?.entry?.id ? `entry:${target.entry.id}`
        : target?.entry?.title ? `title:${target.entry.title}`
        : target?.host ? `host:${target.host}` : undefined,
    };
    if (ev.decision === 'deny')
      fail('POLICY_DENIED', {
        detail: ev.reason + (ev.policy === 'none'
          ? ` — bootstrap: kp config set agents.${agentId === 'default' ? 'default' : agentId}.allowed "<action-list>" or edit config.toml`
          : ''),
        policy: ev.policy,
      });
    if (ev.decision === 'require_approval' && !APPROVABLE_ACTIONS.has(action))
      fail('POLICY_APPROVAL_REQUIRED', { detail: `${ev.reason} — no approval channel exists for '${action}' yet`, policy: ev.policy });
  };

  /**
   * Second-phase gate once the concrete entry is resolved — applies
   * allowed_entries/denied_entries and (for login) allowed_hosts. Also stamps
   * the audit target with the entry uuid.
   */
  const gateEntry = (action: string, entry: { id: string; title: string; url: string }): void => {
    const host = normalizeHost(entry.url) ?? '';
    if (auditCtx) auditCtx.target = `entry:${entry.id}`;
    const ev = evaluate(cfg, agentId, action, { entry, host });
    if (ev.decision === 'allow') return;
    if (auditCtx) auditCtx.decision = ev.decision;
    if (ev.decision === 'require_approval' && APPROVABLE_ACTIONS.has(action)) return;
    fail(ev.decision === 'require_approval' ? 'POLICY_APPROVAL_REQUIRED' : 'POLICY_DENIED',
      { detail: ev.reason, policy: ev.policy, entry: entry.id });
  };

  // --- db ---
  if (grp === 'db') {
    // Every db subcommand is policy-gated; switch/use/default share 'db.switch'.
    const DB_ACTION: Record<string, string> = {
      list: 'db.list', current: 'db.current', switch: 'db.switch', use: 'db.switch',
      default: 'db.switch', add: 'db.add', sync: 'db.sync', remove: 'db.remove',
      info: 'db.info', create: 'db.create',
    };
    if (DB_ACTION[sub]) gate(DB_ACTION[sub], String(flags.db || cmd[2] || cfg.keepass.default_database || ''));
    if (sub === 'list') {
      // Hardened: session state lives with the service principal — ask it;
      // a down service reports UNAVAILABLE rather than a misleading LOCKED.
      const states = HARD ? await svcStates() : null;
      return out({ success: true, databases: listDbs(cfg).map((d) => ({ ...d, state: states ? (states[d.alias] ?? 'UNAVAILABLE') : dbState(d.alias) })) });
    }
    if (sub === 'current') {
      const a = cfg.keepass.default_database || '';
      const states = HARD ? await svcStates() : null;
      return out({ success: true, alias: a || null, state: a ? (states ? (states[a] ?? 'UNAVAILABLE') : dbState(a)) : 'LOCKED' });
    }
    if (sub === 'switch' || sub === 'use') {
      const a = String(cmd[2] || '');
      const r = setDefault(cfg, a);
      if (!r.ok) return fail(r.code!);
      saveConfig(cfg);
      return out({ success: true, alias: a, state: dbState(a), note: 'default database switched' });
    }
    if (sub === 'add') {
      const alias = cmd[2];
      const path = String(flags.path || '');
      if (!alias || !path) return fail('INVALID_CONFIG', { detail: 'alias and --path required' });
      const r = addDb(cfg, alias, {
        path,
        key_file: flags['key-file'] ? String(flags['key-file']) : undefined,
        unlock_method: flags['unlock-method'] ? String(flags['unlock-method']) : undefined,
        session_timeout: flags.timeout ? parseInt(String(flags.timeout), 10) : undefined,
      });
      if (!r.ok) return fail(r.code!);
      saveConfig(cfg);
      return out({ success: true, alias });
    }
    if (sub === 'sync') {
      const alias = String(flags.db || cfg.keepass.default_database || 'personal');
      const db = cfg.databases[alias];
      if (!db?.path) return fail('DATABASE_NOT_FOUND', { detail: alias });
      const sprite = String(flags.sprite || 'hub-test');
      const remote = String(flags.remote || `/root/.config/keepass-agent/${basename(db.path)}`);
      const pull = !!flags.pull, force = !!flags.force;
      // T2: sprite name and remote path travel as individual argv entries —
      // `sh -c` is never constructed — and both are validated to a
      // metacharacter-free charset before spawn, so a value like
      // `--remote "x'; id; #"` is rejected rather than executed.
      if (!SPRITE_NAME_RE.test(sprite))
        return fail('INVALID_SPRITE', { detail: 'sprite name must match [A-Za-z0-9._-]{1,64}' });
      if (!validRemotePath(remote))
        return fail('INVALID_REMOTE_PATH', { detail: 'remote must be an absolute POSIX path ([A-Za-z0-9._/-]); spaces, .., quotes, and shell metacharacters are not allowed' });
      if (!fileExists(db.path)) return fail('FILE_NOT_FOUND', { detail: basename(db.path) });
      // Hardened: only principals with KDBX read access (operator/service)
      // may sync the vault file — an agent without read permission fails
      // with an explicit code rather than an opaque IO exception.
      if (HARD) {
        try { readFileSync(db.path); } catch {
          return fail('HARDENED_KDBX_ACCESS_DENIED', { detail: 'db sync requires direct KDBX read access — run it as the operator or service principal' });
        }
      }
      const lmd5 = createHash('md5').update(readFileSync(db.path)).digest('hex');
      const lmt = Math.floor(statSync(db.path).mtimeMs / 1000);
      // Remote probes are argv-only. A non-zero probe = remote file absent
      // (push will create it; pull fails cleanly at the download step).
      const pMd5 = await spriteRun(['exec', '-s', sprite, '--no-stdin', '--', 'md5sum', remote]);
      const pMtime = await spriteRun(['exec', '-s', sprite, '--no-stdin', '--', 'stat', '-c', '%Y', remote]);
      const rmd5 = pMd5.ok ? (pMd5.out.trim().split(/\s+/)[0] || '') : '';
      const rmt = pMtime.ok && /^\d+$/.test(pMtime.out.trim()) ? Number(pMtime.out.trim()) : 0;
      if (rmd5 && rmd5 === lmd5) return out({ success: true, direction: 'none', md5: lmd5, note: 'identical' });
      if (!pull && !force && rmt > lmt) return fail('REMOTE_NEWER', { detail: 'remote kdbx is newer — use --pull or --force', remote_mtime: rmt, local_mtime: lmt });
      if (pull && !force && lmt > rmt) return fail('LOCAL_NEWER', { detail: 'local kdbx is newer — use push or --force', remote_mtime: rmt, local_mtime: lmt });
      if (!pull) {
        process.env.SPRITE_CWD = dirname(db.path);
        const up = await spriteRun(['exec', '-s', sprite, '--no-stdin', '--file', `${basename(db.path)}:${remote}`, '--', 'true']);
        delete process.env.SPRITE_CWD;
        if (!up.ok) return fail('SYNC_UPLOAD_FAILED', { detail: sanitizeDetail(up.err) });
        const chk = await spriteRun(['exec', '-s', sprite, '--no-stdin', '--', 'md5sum', remote]);
        const remoteMd5 = chk.out.trim().split(/\s+/)[0] || '';
        const ok = chk.ok && remoteMd5 === lmd5;
        return out({ success: ok, direction: 'push', md5: lmd5, remote_md5: remoteMd5, bytes: statSync(db.path).size, code: ok ? undefined : 'MD5_MISMATCH' });
      }
      const b64 = await spriteRun(['exec', '-s', sprite, '--no-stdin', '--', 'base64', remote]);
      if (!b64.ok || !b64.out.trim()) return fail('SYNC_DOWNLOAD_FAILED', { detail: sanitizeDetail(b64.err) });
      const buf = Buffer.from(b64.out.trim().replace(/\s+/g, ''), 'base64');
      if (!buf.length) return fail('SYNC_DOWNLOAD_FAILED', { detail: 'empty remote payload' });
      // Atomic replace: stage → md5-verify → .bak backup → same-dir rename.
      // Any failure before the rename leaves the working KDBX untouched.
      const dir = dirname(db.path), base = basename(db.path);
      const tmp = join(dir, `.${base}.pull-${process.pid}-${Date.now()}.tmp`);
      try {
        writeFileSync(tmp, buf);
        const dlMd5 = createHash('md5').update(readFileSync(tmp)).digest('hex');
        if (rmd5 && dlMd5 !== rmd5) {
          try { unlinkSync(tmp); } catch {}
          return fail('MD5_MISMATCH', { detail: 'downloaded KDBX failed integrity check — original preserved', remote_md5: rmd5, local_md5: dlMd5 });
        }
        copyFileSync(db.path, db.path + '.bak');
        renameSync(tmp, db.path);
        return out({ success: true, direction: 'pull', md5: dlMd5, bytes: statSync(db.path).size, backup: `${base}.bak` });
      } catch (e: any) {
        try { unlinkSync(tmp); } catch {}
        return fail('SYNC_REPLACE_FAILED', { detail: sanitizeDetail(String(e?.message || e)) });
      }
    }
    if (sub === 'remove') {
      const alias = cmd[2];
      if (!alias) return fail('DATABASE_NOT_FOUND');
      const r = removeDb(cfg, alias);
      if (!r.ok) return fail(r.code!);
      // Best-effort service-side session drop — config bookkeeping proceeds
      // even when the service is down (a stale service session is harmless).
      if (HARD) await svc('lock', { db: alias });
      saveConfig(cfg);
      return out({ success: true, removed: alias, note: 'kdbx file left on disk' });
    }
    if (sub === 'default') {
      const r = setDefault(cfg, String(cmd[2] || ''));
      if (!r.ok) return fail(r.code!);
      saveConfig(cfg);
      return out({ success: true });
    }
    if (sub === 'info') {
      const r = getDb(cfg, String(flags.db || cmd[2] || ''));
      if (!r.ok) return fail(r.code!, { alias: r.alias });
      const states = HARD ? await svcStates() : null;
      return out({ success: true, alias: r.alias, ...r.db, state: states ? (states[r.alias!] ?? 'UNAVAILABLE') : dbState(r.alias!) });
    }
    if (sub === 'create') {
      const alias = cmd[2];
      const path = String(flags.path || '');
      if (!alias || !path) return fail('INVALID_CONFIG', { detail: 'alias and --path required' });
      if (!/^[a-z0-9_-]+$/i.test(alias)) return fail('INVALID_CONFIG', { detail: 'invalid database alias' });
      if (cfg.databases[alias]) return fail('DATABASE_ALREADY_REGISTERED', { alias });
      if (fileExists(path)) return fail('DATABASE_ALREADY_EXISTS', { alias });
      const ks = kpscriptPath(cfg);
      if (!ks && process.platform === 'win32' && !HARD) return fail('INVALID_CONFIG', { detail: 'keepass.kpscript not configured' });
      const keyFile = flags['key-file'] ? String(flags['key-file']) : undefined;
      const candidate = { ...cfg, databases: { ...cfg.databases, [alias]: { path, key_file: keyFile } } };
      const errors = validateConfig(candidate);
      if (errors.length) return fail('INVALID_CONFIG', { errors });
      if (HARD) {
        // The KDBX is created by (and owned by) the service principal; the
        // approval round-trip runs inside it, master key never transits here.
        hardGate();
        const res = await runApproval({ mode: 'create', db: alias, targetPath: path, keyFile });
        return out({ success: true, database: res.database || alias, path: res.path || path, status: res.status || 'created' });
      }
      const req = requestCreate(alias, path, keyFile, agentId);
      const result = await waitForUnlock(cfg, ks, req, cfg.databases, reportUrl);
      if (!result.ok) return fail(result.code || 'KDBX_CREATE_FAILED', { alias });
      return out({ success: true, database: result.database || alias, path: result.path || path, status: result.status || 'created' });
    }
  }

  // --- unlock / lock / status ---
  if (grp === 'unlock') {
    gate('unlock', String(flags.db || cfg.keepass.default_database || ''));
    const alias = String(flags.db || '');
    const r = getDb(cfg, alias);
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    const ks = kpscriptPath(cfg);
    if (!ks && process.platform === 'win32' && !HARD) return fail('INVALID_CONFIG', { detail: 'keepass.kpscript not configured' });
    const db = r.db!;
    const method = db.unlock_method || 'local-web';
    if (method === 'keepass-gui') {
      // launch KeePass.exe with the DB — user unlocks there; session via -guikeyprompt later
      spawn(cfg.keepass.executable || 'KeePass.exe', [db.path], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
      return out({ success: true, alias: r.alias, method: 'keepass-gui', note: 'KeePass GUI launched; unlock sessions via kp unlock still need local-web or guikeyprompt' });
    }
    if (HARD) {
      hardGate([db.path]);
      const res = await runApproval({ mode: 'unlock', db: r.alias });
      return out({ success: true, alias: res.database || r.alias, status: res.status || 'unlocked' });
    }
    const req = requestUnlock(r.alias!, agentId);
    const res = await waitForUnlock(cfg, ks, req, { [r.alias!]: db }, reportUrl);
    if (!res.ok) return fail(res.code || 'AUTHENTICATION_FAILED', { alias: r.alias });
    return out({ success: true, alias: res.database || r.alias, status: res.status || 'unlocked' });
  }

  if (grp === 'lock') {
    gate('lock', String(flags.db || cfg.keepass.default_database || ''));
    const alias = String(flags.db || cfg.keepass.default_database);
    if (HARD) {
      hardGate();
      const r = await svcOrFail('lock', { db: alias });
      return out({ success: true, alias, status: r.status || 'locked' });
    }
    lock(alias);
    return out({ success: true, alias, status: 'locked' });
  }

  if (grp === 'status') {
    gate('status', String(flags.db || ''));
    const alias = String(flags.db || '');
    if (!HARD) {
      if (alias) {
        const r = getDb(cfg, alias);
        if (!r.ok) return fail(r.code!, { alias: r.alias });
        return out({ success: true, mode: 'standard', alias: r.alias, status: dbState(r.alias!) });
      }
      const all = Object.fromEntries(Object.keys(cfg.databases).map((a) => [a, dbState(a)]));
      return out({ success: true, mode: 'standard', databases: all });
    }
    // Hardened status: probe the service (full handshake) + run the
    // filesystem-side isolation checks. mode is 'unavailable' when hardened
    // is configured but the service cannot be reached — never a silent
    // standard-mode reading.
    const probe = await probeService(cfg);
    const serviceInfo = {
      endpoint: resolveEndpoint(cfg),
      state: probe.down ? 'down' : 'up',
      ...(probe.down ? { error: probe.code } : { info: probe.info }),
    };
    const envFails = verifyHardenedEnvironment(cfg, {
      tokenPath: resolveTokenFile(cfg),
      kdbxPaths: Object.values(cfg.databases).map((d) => d.path).filter((p) => fileExists(p)),
    });
    const isolation = {
      ok: envFails.length === 0,
      ...(envFails.length ? { failures: envFails.map((f) => ({ check: f.check, path: f.path, detail: f.detail })) } : {}),
    };
    const mode = probe.down ? 'unavailable' : 'hardened';
    if (alias) {
      const r = getDb(cfg, alias);
      if (!r.ok) return fail(r.code!, { alias: r.alias });
      const st = probe.down ? 'UNAVAILABLE' : (await svcOrFail('status', { db: r.alias })).states?.[r.alias!] ?? 'LOCKED';
      return out({ success: true, mode, service: serviceInfo, isolation, alias: r.alias, status: st });
    }
    const states = probe.down
      ? Object.fromEntries(Object.keys(cfg.databases).map((a) => [a, 'UNAVAILABLE']))
      : (await svcOrFail('status')).states;
    return out({ success: true, mode, service: serviceInfo, isolation, databases: states });
  }

  // --- entry add (local web form; --title/--url/--username/--notes prefill) ---
  if (grp === 'entry' && sub === 'add') {
    // Prefill values participate in policy when given — an agent cannot seed
    // credentials outside its entry/host remit. An unprefilled form is filled
    // by the human in the approval UI, so no entry target is checked here.
    const prefill: EvalTarget = {};
    if (flags.title || flags.url) {
      prefill.entry = { title: flags.title ? String(flags.title) : undefined, url: flags.url ? String(flags.url) : undefined };
      if (flags.url) prefill.host = normalizeHost(String(flags.url)) ?? '';
    }
    gate('entry.add', String(flags.db || ''), prefill);
    const r = getDb(cfg, String(flags.db || ''));
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    const ks = kpscriptPath(cfg);
    if (!ks && process.platform === 'win32' && !HARD) return fail('INVALID_CONFIG', { detail: 'keepass.kpscript not configured' });
    if (HARD) {
      hardGate([r.db!.path]);
      const res = await runApproval({
        mode: 'entry', db: r.alias,
        prefill: {
          title: flags.title ? String(flags.title) : undefined,
          url: flags.url ? String(flags.url) : undefined,
          username: flags.username ? String(flags.username) : undefined,
          notes: flags.notes ? String(flags.notes) : undefined,
        },
      });
      if (auditCtx && res.uuid) auditCtx.target = `entry:${res.uuid}`;
      return out({
        success: true, database: res.database || r.alias, status: res.status || 'entry_added',
        entry_uuid: res.uuid,
        ...(res.warnings?.length ? { warning: res.warnings.join('; ') } : {}),
      });
    }
    const req = requestAddEntry(r.alias!, {
      title: flags.title ? String(flags.title) : undefined,
      url: flags.url ? String(flags.url) : undefined,
      username: flags.username ? String(flags.username) : undefined,
      notes: flags.notes ? String(flags.notes) : undefined,
    }, agentId);
    const res = await waitForUnlock(cfg, ks, req, { [r.alias!]: r.db! }, reportUrl);
    if (!res.ok) return fail(res.code || 'ENTRY_ADD_FAILED', { alias: r.alias });
    if (auditCtx && res.uuid) auditCtx.target = `entry:${res.uuid}`;
    // The URL is stored as entered, but anything the worker egress policy
    // would reject surfaces as a warning — `kp login` will refuse it later.
    return out({
      success: true, database: res.database || r.alias, status: res.status || 'entry_added',
      entry_uuid: res.uuid,
      ...(res.warnings?.length ? { warning: res.warnings.join('; ') } : {}),
    });
  }

  // --- entry sync-cookies (web approval → CDP harvest by unlock server) ---
  if (grp === 'entry' && sub === 'sync-cookies') {
    gate('entry.sync-cookies', String(flags.db || ''));
    const r = getDb(cfg, String(flags.db || ''));
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    const endpoint = cdpEndpointArg(flags);
    if (HARD) {
      hardGate([r.db!.path]);
      const st = await svcOrFail('status', { db: r.alias });
      if (st.states?.[r.alias!] !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias });
      const l = await svcOrFail('list', { db: r.alias });
      const entry = findEntry(l.entries || [], flags);
      if (!entry) return fail('ENTRY_NOT_FOUND');
      gateEntry('entry.sync-cookies', entry);
      const host = normalizeHost(entry.url);
      if (!host) return fail('ENTRY_NO_URL', { entry: entry.id });
      const res = await runApproval({
        mode: 'cookies', db: r.alias, entryUuid: entry.id, domain: host, cdpEndpoint: endpoint,
      });
      return out({ success: true, database: r.alias, entry: entry.id, domain: res.domain || host, count: res.count, status: res.status });
    }
    if (dbState(r.alias!) !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias });
    const ks = kpscriptPath(cfg);
    const l = await listEntries(ks, r.alias!, r.db!);
    if (!l.ok) return fail(l.code!);
    const entry = findEntry(l.entries || [], flags);
    if (!entry) return fail('ENTRY_NOT_FOUND');
    gateEntry('entry.sync-cookies', entry);
    const host = normalizeHost(entry.url);
    if (!host) return fail('ENTRY_NO_URL', { entry: entry.id });
    // T7: cookies are authentication-grade secrets — harvesting them always
    // goes through the same one-time-token web approval as login-capture.
    // There is deliberately no direct CLI collection path.
    const req = requestCookieSync(r.alias!, entry.id, host, endpoint, agentId);
    req.noAutoOpen = false; // no CDP page to drive here — use the normal local browser
    const res = await waitForUnlock(cfg, ks, req, { [r.alias!]: r.db! }, reportUrl);
    if (!res.ok) return fail(res.code || 'COOKIE_SYNC_FAILED', { entry: entry.id });
    return out({ success: true, database: r.alias, entry: entry.id, domain: res.domain || host, count: res.count, status: res.status });
  }

  // --- entry login-capture (open site in CDP → web button → sync cookies) ---
  if (grp === 'entry' && sub === 'login-capture') {
    gate('entry.login-capture', String(flags.db || ''));
    const r = getDb(cfg, String(flags.db || ''));
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    const endpoint = cdpEndpointArg(flags);
    if (HARD) {
      hardGate([r.db!.path]);
      const st = await svcOrFail('status', { db: r.alias });
      if (st.states?.[r.alias!] !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias });
      const l = await svcOrFail('list', { db: r.alias });
      const entry = findEntry(l.entries || [], flags);
      if (!entry) return fail('ENTRY_NOT_FOUND');
      gateEntry('entry.login-capture', entry);
      const host = normalizeHost(entry.url);
      if (!host) return fail('ENTRY_NO_URL', { entry: entry.id });
      // The service drives the CDP browser (entry page + approval page) —
      // nothing secret-related ever opens locally.
      const res = await runApproval({
        mode: 'cookies', db: r.alias, entryUuid: entry.id, domain: host,
        cdpEndpoint: endpoint, openUrl: entry.url, capture: true,
      }, { openBrowserLocal: false });
      return out({ success: true, database: r.alias, entry: entry.id, domain: res.domain || host, count: res.count, status: res.status });
    }
    if (dbState(r.alias!) !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias });
    const ks = kpscriptPath(cfg);
    const l = await listEntries(ks, r.alias!, r.db!);
    if (!l.ok) return fail(l.code!);
    const entry = findEntry(l.entries || [], flags);
    if (!entry) return fail('ENTRY_NOT_FOUND');
    gateEntry('entry.login-capture', entry);
    const host = normalizeHost(entry.url);
    if (!host) return fail('ENTRY_NO_URL', { entry: entry.id });
    const opened = await openPage(endpoint, entry.url);
    const req = requestCookieSync(r.alias!, entry.id, host, endpoint, agentId);
    // Open the approval page from the onReady URL — it carries the ACTUAL
    // bound port (ephemeral fallback on collision, F5).
    const res = await waitForUnlock(cfg, ks, req, { [r.alias!]: r.db! }, (url) => {
      reportUrl(url);
      void openPage(endpoint, url);
    });
    if (!res.ok) return fail(res.code || 'COOKIE_SYNC_FAILED', { entry: entry.id });
    return out({ success: true, database: r.alias, entry: entry.id, domain: res.domain || host, count: res.count, status: res.status, browser_page_opened: opened });
  }

  // --- master change ---
  if (grp === 'master' && sub === 'change') {
    gate('master.change', String(flags.db || cfg.keepass.default_database || ''));
    const alias = String(flags.db || '');
    const r = getDb(cfg, alias);
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    // KeePass GUI path — launch DB; user changes master key in KeePass UI (real KDBX re-encrypt)
    spawn(cfg.keepass.executable || 'KeePass.exe', [r.db!.path], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    if (HARD) {
      const lr = await svc('lock', { db: r.alias });
      return out({
        success: true, alias: r.alias, action: 'gui_launched',
        ...(lr.ok ? {} : { warning: `service session invalidation failed: ${lr.code}` }),
        note: 'change master key in KeePass UI; session invalidated',
      });
    }
    lock(r.alias!); // invalidate any cached session — master key about to change
    return out({ success: true, alias: r.alias, action: 'gui_launched', note: 'change master key in KeePass UI; session invalidated' });
  }

  // --- search ---
  if (grp === 'search') {
    gate('search', String(flags.db || ''));
    const alias = String(flags.db || '');
    const r = getDb(cfg, alias);
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    let l: { ok: boolean; code?: string; entries?: any[] };
    if (HARD) {
      hardGate([r.db!.path]);
      l = await svcOrFail('list', { db: r.alias });
    } else {
      if (dbState(r.alias!) !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias, status: 'locked', action: 'user_unlock_required' });
      const ks = kpscriptPath(cfg);
      l = await listEntries(ks, r.alias!, r.db!);
    }
    if (!l.ok) return fail(l.code!);
    const q = { site: flags.site ? String(flags.site) : undefined, username: flags.username ? String(flags.username) : undefined, title: flags.title ? String(flags.title) : undefined };
    if (!q.site && !q.username && !q.title) return fail('INVALID_CONFIG', { detail: 'provide --site, --username, or --title' });
    if (auditCtx) auditCtx.target = `query:${[q.site, q.title, q.username].filter(Boolean).join('|')}`;
    // Results are filtered through the agent's entry policy — allowed_entries
    // scopes what the agent may even see; denied_entries always wins.
    const pol = agentPolicy(cfg, agentId);
    const matches = searchEntries(l.entries!, q).filter((e) => entryPermitted(pol, e));
    return out({ success: true, database: r.alias, matches: matches.map((e) => ({ id: e.id, title: e.title, username: e.username, url: e.url })) });
  }

  // --- login ---
  if (grp === 'login') {
    gate('login', String(flags.db || ''));
    // F-1: the CDP endpoint is where vault secrets get typed — it must be
    // operator-managed ([cdp] endpoint in config.toml), never an agent
    // flag. An agent-chosen endpoint could be a hostile loopback socket
    // that harvests the credentials the worker types.
    if (flags.cdp)
      return fail('INVALID_CONFIG', { detail: 'login --cdp removed — set cdp.endpoint in config.toml (operator-managed, loopback-only)' });
    // F-3: default-context logins share the user's cookie jar — only
    // permitted when the operator opts in for dedicated-profile instances.
    if (flags['no-isolate'] && !cfg.cdp?.allow_default_context)
      return fail('INVALID_CONFIG', { detail: '--no-isolate requires cdp.allow_default_context=true (dedicated-profile CDP instances only)' });
    if (process.env.KEEPASS_AGENT_CDP_ENDPOINT && !cdpEnvWarned) {
      cdpEnvWarned = true;
      process.stderr.write('kp: warning: KEEPASS_AGENT_CDP_ENDPOINT override active — login worker receives vault secrets via this endpoint\n');
    }
    const alias = String(flags.db || '');
    const r = getDb(cfg, alias);
    if (!r.ok) return fail(r.code!, { alias: r.alias });
    if (HARD) {
      // Secret boundary: the service resolves the entry, re-checks policy,
      // spawns the worker, and pipes the secret itself — no key/session/
      // secret material ever exists in this process.
      hardGate([r.db!.path]);
      const workerName = String(flags.worker || 'local-test');
      let uuid = String(flags.entry || '');
      const l = await svcOrFail('list', { db: r.alias });
      const entries = l.entries ?? [];
      if (!uuid) {
        const pol = agentPolicy(cfg, agentId);
        const matches = searchEntries(entries, {
          title: flags.title ? String(flags.title) : undefined,
          site: flags.site ? String(flags.site) : undefined,
          username: flags.username ? String(flags.username) : undefined,
        }).filter((e) => entryPermitted(pol, e));
        if (matches.length === 0) return fail('ENTRY_NOT_FOUND');
        if (matches.length > 1) return fail('AMBIGUOUS_ENTRY', { matches: matches.map((e) => ({ id: e.id, title: e.title })) });
        uuid = matches[0].id;
      }
      const worker = resolveWorker(workerName);
      if (!worker.ok) return fail('UNSUPPORTED_WORKER', { available: workerNames() });
      const entry = entries.find((e: any) => e.id === uuid);
      if (!entry) return fail('ENTRY_NOT_FOUND', { entry: uuid });
      gateEntry('login', entry);
      const res = await svcOrFail('login', { db: r.alias, entry: uuid, worker: workerName });
      return out({ success: true, database: r.alias, entry_id: uuid, status: res.status || 'authenticated' });
    }
    if (dbState(r.alias!) !== 'UNLOCKED') return fail('UNLOCK_REQUIRED', { database: r.alias, status: 'locked', action: 'user_unlock_required' });
    const ks = kpscriptPath(cfg);
    let uuid = String(flags.entry || '');
    if (!uuid) {
      const l = await listEntries(ks, r.alias!, r.db!);
      if (!l.ok) return fail(l.code!);
      // Filter through the agent's entry remit BEFORE any ambiguity/
      // not-found response — out-of-remit entries must not appear in the
      // AMBIGUOUS_ENTRY match list (same rule as `search` result filtering).
      const pol = agentPolicy(cfg, agentId);
      const matches = searchEntries(l.entries!, {
        title: flags.title ? String(flags.title) : undefined,
        site: flags.site ? String(flags.site) : undefined,
        username: flags.username ? String(flags.username) : undefined,
      }).filter((e) => entryPermitted(pol, e));
      if (matches.length === 0) return fail('ENTRY_NOT_FOUND');
      if (matches.length > 1) return fail('AMBIGUOUS_ENTRY', { matches: matches.map((e) => ({ id: e.id, title: e.title })) });
      uuid = matches[0].id;
    }
    const worker = resolveWorker(String(flags.worker || 'local-test'));
    if (!worker.ok) return fail('UNSUPPORTED_WORKER', { available: workerNames() });
    const l2 = await listEntries(ks, r.alias!, r.db!);
    const entry = l2.entries?.find((e) => e.id === uuid);
    if (!entry) return fail('ENTRY_NOT_FOUND', { entry: uuid });
    // Phase-2: entry remit (allowed/denied entries) + worker URL host
    // allowlist (allowed_hosts) on the concrete credential.
    gateEntry('login', entry);
    const res = await pipeSecretToWorker(
      ks, r.alias!, r.db!, uuid, worker.cmd!,
      ['--url', entry.url || ''],
      {
        db: r.alias!, entry: uuid, username: entry.username, url: entry.url || '',
        // playwright worker knobs — the endpoint is operator config only
        // (F-1); --no-isolate was already gated on cdp.allow_default_context.
        // Other workers ignore extra meta fields.
        ...(cfg.cdp?.endpoint ? { cdp: cfg.cdp.endpoint } : {}),
        ...(flags['no-isolate'] ? { isolated: '0' } : {}),
      },
      {
        timeoutMs: worker.timeoutMs,
        // Broker-side backstop: re-evaluate at the pipe boundary so no secret
        // leaves the vault on a stale/mid-flight denial.
        policyGate: () => evaluate(cfg, agentId, 'login',
          { entry: { id: entry.id, title: entry.title, url: entry.url }, host: normalizeHost(entry.url) ?? '' }),
      },
    );
    return out({
      success: res.ok, database: r.alias, entry_id: uuid,
      status: res.detail || (res.ok ? 'authenticated' : res.code),
      ...(res.ok ? {} : { code: res.code }),
    }, res.ok ? 0 : 1);
  }

  // --- audit (read the JSONL audit log tail) ---
  if (grp === 'audit') {
    gate('audit.read');
    const n = flags.limit ? parseInt(String(flags.limit), 10) : 100;
    if (HARD) {
      // The service-side log is authoritative in hardened mode (it records
      // the boundary-level decisions a bypassed CLI could never write).
      const r = await svcOrFail('audit', { limit: Number.isInteger(n) ? n : 100 });
      return out({ success: true, events: r.events ?? [] });
    }
    return out({ success: true, events: readAudit(Number.isInteger(n) ? n : 100) });
  }

  // --- ui — operator management console (loopback web UI + JSON API) ---
  if (grp === 'ui') {
    gate('ui');
    if (HARD) hardGate();
    const ttlSec = flags.ttl ? Number(flags.ttl) : 4 * 3600;
    if (!Number.isInteger(ttlSec) || ttlSec < 60 || ttlSec > 86400)
      return fail('INVALID_CONFIG', { detail: '--ttl must be an integer in 60..86400 seconds' });
    const { startMgmtServer } = await import('../mgmt/server.ts');
    const srv = await startMgmtServer({ kpscript: kpscriptPath(cfg), launchAgent: agentId, ttlMs: ttlSec * 1000 });
    // srv.url carries the ONE-TIME page token (srv.token is the API session
    // token — it is embedded in the served page and never goes in a URL).
    const url = srv.url;
    const noOpen = !!flags['no-open'] || !cfg.unlock.auto_open_browser;
    if (!noOpen) openBrowser(url);
    // The launch URL's one-time token transits the browser-spawn argv —
    // same-UID processes can read command lines briefly. The token is
    // consumed on first page serve (the API credential is separate and
    // never in the URL), but the residual argv window is documented.
    if (!noOpen)
      process.stderr.write('kp ui: note: the one-time launch token transits the browser command line — briefly visible to same-user processes (see docs/security.md)\n');
    // The URL token is deliberately absent from stdout/stderr unless the
    // browser cannot be opened or --print-url is requested — always with a
    // warning, louder when the declared identity is an agent-style id.
    if (noOpen || !!flags['print-url']) {
      process.stderr.write(`kp ui: ${url}\n`);
      process.stderr.write(`kp ui: warning: this URL carries the one-time console token — do not forward it to agents or logs`
        + (agentId !== 'operator' ? ` (declared agent: ${agentId})` : '') + '\n');
    }
    // MED-3: the console's operator channel bypasses [agents.*] for the
    // launcher — an agent granted `ui` gets operator-equivalent reach.
    if (agentId !== 'operator' && agentId !== 'default')
      process.stderr.write(`kp ui: warning: declared agent '${agentId}' — the management console runs with operator privileges; granting 'ui' to agents is operator-equivalent\n`);
    process.stderr.write(`kp ui: management console on 127.0.0.1:${srv.port} (ttl ${ttlSec}s) — ${noOpen ? 'open the printed URL in a browser' : 'opened in browser'}; Ctrl+C or Shut down console to stop\n`);
    const end = await srv.done;
    return out({ success: true, status: 'ui_closed', reason: end.code });
  }

  return usage();
}

function usage(): never {
  console.log(`kp — KeePass credential gateway
config init|show|validate|set <key> <value>|migrate   (agents.<name>.<field> as CSV, policy.audit_max_bytes — audited; hardened.* is operator-edited only; migrate persists schema upgrades)
doctor                                        (read-only diagnostics: node/config/KeePass/python/sessions/hardened — ok|warn|fail + fix hints)
db list|current|switch <alias>|sync [--pull] [--force] [--sprite s] [--remote p]|add <alias> --path <kdbx> [--key-file f]|remove <alias>|default <alias>|info|create <alias> --path <kdbx> [--key-file f] (local web form)
unlock --db <alias>|lock --db <alias>|status [--db]
entry add [--db <alias>] [--title t] [--url u] [--username n] [--notes n] (local web form)
entry sync-cookies [--db <alias>] --entry <uuid>|--title|--site [--cdp http://127.0.0.1:9222] (local web approval; --cdp is loopback-only)
entry login-capture [--db <alias>] --entry <uuid>|--title|--site [--cdp http://127.0.0.1:9222] (site + local web button; --cdp is loopback-only)
master change --db <alias>
mcp                                           (stdio MCP server — JSON-RPC on stdout, logs on stderr; tools are policy-gated)
search [--db] --site|--username|--title [--json]
login [--db] --entry <uuid>|--title|--site [--worker local-test|playwright] [--no-isolate]  (CDP endpoint: cdp.endpoint config; --no-isolate needs cdp.allow_default_context)
audit [--limit N]
ui [--ttl seconds] [--no-open] [--print-url]     (operator console: sessions/audit/agents/unlock; loopback + session token, browser-delivered)
global: --agent <id> or KEEPASS_AGENT_ID — declared identity for policy+audit (default: 'default'); every command above is policy-gated (deny-by-default, see [agents.*] in config.toml)`);
  process.exit(0);
}

main().catch((e) => out({ success: false, code: 'INTERNAL_ERROR', detail: sanitizeDetail(String(e?.message || e)) }));
