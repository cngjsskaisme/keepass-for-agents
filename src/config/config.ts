// Config Manager — ~/.config/keepass-agent/config.toml
// Loads, validates, and atomically saves the gateway config.
// Never stores master passwords — only file paths and policy.

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, unlinkSync, statSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve, isAbsolute } from 'node:path';
import { isLoopbackCdpEndpoint } from '../cdp/cookies.ts';

export const CONFIG_DIR = join(homedir(), '.config', 'keepass-agent');
/**
 * Config path override — lets the Credential Service (hardened mode, a
 * separate OS principal with its own HOME/SESSION_DIR) read the *operator's*
 * config.toml while keeping sessions under its own account. When unset the
 * path is homedir-derived exactly as before — Standard Mode is unchanged.
 */
export const CONFIG_PATH = process.env.KEEPASS_AGENT_CONFIG
  ? resolve(process.env.KEEPASS_AGENT_CONFIG)
  : join(CONFIG_DIR, 'config.toml');
export const SESSION_DIR = join(CONFIG_DIR, 'sessions');

/** Keys that must never be created on a plain object — `[agents.__proto__]`
 *  or `__proto__ = x` would otherwise write onto Object.prototype and turn
 *  inherited properties into attacker-controlled policy. */
export const FORBIDDEN_TOML_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * config.toml schema version. Files written before versioning carry no
 * `schema_version` key and are treated as version 0; every save stamps the
 * current version as a top-level key (`schema_version = 1`, before [keepass]).
 * Bump CONFIG_SCHEMA_VERSION AND register a SCHEMA_MIGRATIONS step whenever
 * the on-disk shape changes — loadConfig() then upgrades in memory and
 * `kp config migrate` persists the upgrade.
 */
export const CONFIG_SCHEMA_VERSION = 1;

/** One schema upgrade step. `apply` receives the raw parsed TOML tree for a
 *  document at version (target-1) and returns the version-`target` tree. */
export interface SchemaMigration {
  /** Human-readable note surfaced by `kp config migrate` / `kp doctor`. */
  note: string;
  apply: (raw: Record<string, any>) => Record<string, any>;
}

/**
 * Ordered migration registry — key = the version ENTERED by that step
 * (entry `1` upgrades a v0/pre-versioned document to v1). The v1 step is the
 * baseline: pre-versioned configs needed no structural changes, so it only
 * records that the upgrade path ran. Future schema changes append here.
 */
export const SCHEMA_MIGRATIONS: Record<number, SchemaMigration> = {
  1: {
    note: 'pre-versioned config adopted as schema v1 (no structural changes)',
    apply: (raw) => raw,
  },
};

/** Version recorded in a parsed config document; absent key → 0 (pre-versioned). */
export function schemaVersionOf(raw: Record<string, any> | null | undefined): number {
  const v = raw?.schema_version;
  return Number.isInteger(v) && (v as number) >= 0 ? (v as number) : 0;
}

/** Schema version stored in the on-disk config file; null when absent/unreadable. */
export function readSchemaVersion(): number | null {
  try {
    if (!existsSync(CONFIG_PATH)) return null;
    return schemaVersionOf(parseToml(readFileSync(CONFIG_PATH, 'utf8')));
  } catch { return null; }
}

export interface SchemaMigrationResult {
  /** Possibly-upgraded raw TOML tree. */
  raw: Record<string, any>;
  /** Version the document started at (0 = pre-versioned). */
  from: number;
  /** Version after all applicable steps ran (≤ CONFIG_SCHEMA_VERSION). */
  to: number;
  /** Applied step notes, in order. */
  applied: string[];
  /** True when the file declares a version NEWER than this build knows. */
  fromNewer: boolean;
}

/**
 * Apply every migration step between the document's recorded version and
 * CONFIG_SCHEMA_VERSION. A document declaring a NEWER version is returned
 * untouched (`fromNewer`) — loading continues best-effort and `kp doctor`
 * reports the mismatch.
 */
export function migrateSchema(raw: Record<string, any>): SchemaMigrationResult {
  const from = schemaVersionOf(raw);
  if (from > CONFIG_SCHEMA_VERSION)
    return { raw, from, to: from, applied: [], fromNewer: true };
  const applied: string[] = [];
  let data = raw;
  let v = from;
  while (v < CONFIG_SCHEMA_VERSION) {
    const m = SCHEMA_MIGRATIONS[v + 1];
    if (!m) break; // gap in the registry — proceed best-effort, doctor warns
    data = m.apply(data);
    applied.push(`v${v}→v${v + 1}: ${m.note}`);
    v++;
  }
  return { raw: data, from, to: v, applied, fromNewer: false };
}

/** TOML array literal — JSON-style `["a","b"]` first, then a forgiving
 *  single/double-quoted comma-split fallback (this parser is a subset). */
function parseTomlArray(raw: string): any[] {
  try {
    const j = JSON.parse(raw);
    if (Array.isArray(j)) return j;
  } catch {}
  const inner = raw.slice(1, -1);
  if (!inner.trim()) return [];
  return inner.split(',').map((s) => s.trim().replace(/^(['"])(.*)\1$/, '$2')).filter((s) => s.length);
}

/**
 * Strip a TOML `#` comment that sits OUTSIDE string literals. Walks the line
 * tracking `"`/`'` string state (backslash escapes inside double-quoted
 * strings) so `["a #b","c"]` keeps the `#b` but `["a"] # note` loses the
 * comment. This parser is a subset: `#` inside a bare (unquoted) value is
 * also treated as comment start for arrays.
 */
function stripTomlComment(v: string): string {
  let inStr = false, quote = '', esc = false;
  for (let i = 0; i < v.length; i++) {
    const ch = v[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === quote) inStr = false;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = true; quote = ch; continue; }
    if (ch === '#') return v.slice(0, i);
  }
  return v;
}

// --- minimal TOML subset parser (sections, dotted sections, k=v scalars,
//     one-line arrays of scalars) ---
export function parseToml(text: string): Record<string, any> {
  const root: Record<string, any> = {};
  let cur: any = root;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      cur = root;
      let dead = false;
      for (const part of sec[1].split('.')) {
        const k = part.trim();
        // A section path containing __proto__/constructor/prototype would
        // write onto Object.prototype — divert its keys into a detached sink.
        if (FORBIDDEN_TOML_KEYS.has(k)) { dead = true; break; }
        // Only own object slots may be traversed — an inherited name
        // (toString, hasOwnProperty, …) or a scalar must never become a
        // section object (prototype walk / strict-mode crash).
        if (!Object.hasOwn(cur, k) || typeof cur[k] !== 'object' || cur[k] === null) cur[k] = {};
        cur = cur[k];
      }
      if (dead) cur = {};
      continue;
    }
    const kv = line.match(/^([A-Za-z_][\w.-]*)\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = kv[1];
    if (FORBIDDEN_TOML_KEYS.has(key)) continue;
    let v: any = kv[2].trim();
    if (v.startsWith('[')) {
      // Strip a trailing ` # comment` — string-aware so `#` inside a quoted
      // array item survives; scalars keep the old no-comment behaviour.
      const noComment = stripTomlComment(v).trimEnd();
      if (noComment.endsWith(']')) { v = parseTomlArray(noComment); cur[key] = v; continue; }
    }
    if (v.startsWith('"') && v.endsWith('"')) { try { v = JSON.parse(v); } catch { v = v.slice(1, -1); } }
    else if (v === 'true' || v === 'false') v = v === 'true';
    else if (/^-?\d+$/.test(v)) v = parseInt(v, 10);
    cur[key] = v;
  }
  return root;
}

export function tomlEscape(s: string): string {
  return JSON.stringify(s);
}

export interface DbConfig {
  path: string;
  key_file?: string;
  unlock_method?: string;   // 'local-web' | 'keepass-gui'
  session_timeout?: number; // seconds
}

/**
 * Per-agent policy (`[agents.<name>]`). `allowed`/`require_approval` hold
 * action patterns (glob; `*` or `db.*` allowed). Entry lists hold title/host
 * globs or `uuid:<id>`; `allowed_hosts` holds hostnames or host globs
 * applied to the worker login URL. An action not listed anywhere is DENIED
 * (deny-by-default).
 */
export interface AgentPolicy {
  allowed?: string[];
  require_approval?: string[];
  allowed_entries?: string[];
  denied_entries?: string[];
  allowed_hosts?: string[];
}

/** `[policy]` — engine-wide knobs (audit sink tuning only, for now). */
export interface PolicyConfig {
  audit_max_bytes?: number;
}

/**
 * `[hardened]` — Hardened Mode (Credential Service isolation). Opt-in and
 * fail-closed: when `enabled` is true, every credential-touching command is
 * routed to the service over authenticated IPC and NEVER falls back to the
 * in-process (Standard Mode) path.
 *
 * The service itself runs as a distinct OS principal; this section only tells
 * the client side where to reach it and which isolation checks to enforce.
 * See docs/security.md "Hardened Mode" for the principal model.
 */
export interface HardenedConfig {
  /** Master switch. Default false → Standard Mode, byte-identical behavior. */
  enabled: boolean;
  /**
   * IPC endpoint. POSIX: absolute unix-socket path. Windows: named-pipe name
   * (`keepass-agent-svc` form — the `\\.\pipe\` prefix is implied). When
   * unset, platform defaults apply (see src/service/mode.ts).
   */
  endpoint?: string;
  /**
   * Capability token file — the IPC authentication anchor. Must be readable
   * only by principals allowed to call the service (POSIX ≤0640 with no
   * 'other' bits; Windows: NTFS ACL denying Everyone/Users/AuthUsers).
   * Default: `<endpoint-dir>/ipc-token` (POSIX) / `<CONFIG_DIR>/service/ipc-token` (Windows).
   */
  token_file?: string;
  /**
   * Service-side state directory (sessions/socket/token live there on the
   * service account). Informational for provisioning; the service binds its
   * own paths from its own HOME at runtime.
   */
  state_dir?: string;
  /**
   * POSIX only: expected owner uid of every registered KDBX file. When set,
   * the isolation check fails (HARDENED_ACL_UNMET) if any KDBX is owned by a
   * different uid — proving the agent principal does not own the vault.
   * Provisioning writes it once the service account uid is known.
   */
  service_uid?: number;
  /**
   * Peer-credential verification tier (POSIX): 'auto' verifies via ss+procfs
   * when available, 'strict' rejects the connection when verification is
   * unavailable or the peer uid is not in `allowed_uids`, 'off' disables.
   * Windows has no pure-Node peer API (documented) — this knob is POSIX-only.
   */
  peer_verify?: 'auto' | 'strict' | 'off';
  /** POSIX uids allowed to connect when peer_verify is 'strict'. */
  allowed_uids?: number[];
  /**
   * Windows allow-list for file-ACL checks — every principal granted on the
   * token file and each KDBX must appear here (icacls display form, e.g.
   * `BUILTIN\\Administrators`, `NT AUTHORITY\\SYSTEM`, `MACHINE\\kpa-svc`, or
   * a raw `S-1-5-…` sid). Unset on Windows → the check fails closed
   * (HARDENED_ACL_UNMET): the mode cannot be claimed with an unverified ACL.
   * Provisioning writes the exact principal set it granted.
   */
  allowed_sids?: string[];
  /** IPC connect/response timeout in ms (default 5000; approvals exempt). */
  connect_timeout_ms?: number;
}

/**
 * `[mcp.clients.<name>]` — bind a connecting MCP client to a declared agent
 * identity. `<name>` is the client's `clientInfo.name` normalized to
 * lowercase `[a-z0-9_-]` (non-matching runs collapse to `-`, e.g.
 * `"Visual Studio Code"` → `visual-studio-code`); exact-match keys are
 * tried first. Same self-declared identity model as `--agent` — it scopes
 * policy + audit attribution, it does not authenticate the client.
 */
export interface McpClientConfig {
  agent?: string;
}

/**
 * `[mcp]` — MCP adapter (`src/mcp/`). Identity fallback chain for a stdio
 * session: initialize `params.agent` → `[mcp.clients.<clientInfo.name>]`
 * mapping → `kp mcp --agent` / `KEEPASS_AGENT_ID` env → `mcp.agent` →
 * `default`. Operator-managed like `hardened.*`/`agents.*` — `config set`
 * does not write `mcp.*` keys; edit config.toml directly.
 */
export interface McpConfig {
  /** Lowest-priority declared agent id for MCP sessions. */
  agent?: string;
  clients: Record<string, McpClientConfig>;
}

/**
 * `[cdp]` — operator-managed CDP policy for credential-touching browser
 * workers (`login --worker playwright`). The endpoint is the destination
 * vault secrets are typed into, so it must come from the operator config —
 * never from an agent-settable flag or env var (see security.md).
 */
export interface CdpConfig {
  /** Loopback CDP endpoint for the login worker. Default http://127.0.0.1:9222. */
  endpoint?: string;
  /**
   * Permit `--no-isolate` logins (default browser context instead of an
   * isolated one). Only meaningful for CDP instances that ARE a dedicated
   * profile — on a shared user browser it would mix vault logins with the
   * user's real sessions. Default false.
   */
  allow_default_context?: boolean;
}

export interface AppConfig {
  /** Effective schema version of this config — always CONFIG_SCHEMA_VERSION
   *  on a loaded/saved config (migrations normalize on load). */
  schema_version: number;
  /** Migration steps applied while loading (in-memory view only — never
   *  persisted; absent when the file was already current). */
  migrations_applied?: string[];
  keepass: { executable?: string; kpscript?: string; default_database?: string };
  databases: Record<string, DbConfig>;
  // transport is deprecated — unlock submissions are always POST with an
  // encrypted payload. The field survives load/save only so existing config
  // files still validate; the unlock server ignores it entirely.
  unlock: { host: string; port: number; auto_open_browser: boolean; transport: 'get' | 'post' };
  agents: Record<string, AgentPolicy>;
  policy: PolicyConfig;
  hardened: HardenedConfig;
  mcp: McpConfig;
  cdp: CdpConfig;
}

const AGENT_LIST_FIELDS = ['allowed', 'require_approval', 'allowed_entries', 'denied_entries', 'allowed_hosts'] as const;

/** Coerce a TOML value into a string list (accepts a bare scalar too). */
function strList(v: any): string[] | undefined {
  if (v == null) return undefined;
  const a = Array.isArray(v) ? v : [v];
  const out = a.filter((x): x is string => typeof x === 'string');
  return out.length ? out : undefined;
}

export function normalize(c: any): AppConfig {
  const agents: Record<string, AgentPolicy> = {};
  for (const [name, raw] of Object.entries(c.agents ?? {})) {
    const a = raw as any;
    const pol: AgentPolicy = {};
    for (const f of AGENT_LIST_FIELDS) {
      const v = strList(a?.[f]);
      if (v) pol[f] = v;
    }
    agents[name] = pol;
  }
  return {
    schema_version: CONFIG_SCHEMA_VERSION,
    keepass: c.keepass ?? {},
    databases: c.databases ?? {},
    unlock: {
      host: c.unlock?.host ?? '127.0.0.1',
      port: c.unlock?.port ?? 8765,
      auto_open_browser: c.unlock?.auto_open_browser ?? true,
      transport: c.unlock?.transport ?? 'post',
    },
    agents,
    policy: {
      audit_max_bytes:
        Number.isInteger(c.policy?.audit_max_bytes) ? c.policy.audit_max_bytes : undefined,
    },
    hardened: normalizeHardened(c.hardened),
    mcp: normalizeMcp(c.mcp),
    cdp: normalizeCdp(c.cdp),
  };
}

function normalizeCdp(c: any): CdpConfig {
  const ep = typeof c?.endpoint === 'string' && c.endpoint.trim() ? c.endpoint.trim() : undefined;
  return { endpoint: ep, allow_default_context: c?.allow_default_context === true };
}

function normalizeMcp(m: any): McpConfig {
  const clients: Record<string, McpClientConfig> = {};
  for (const [name, raw] of Object.entries(m?.clients ?? {})) {
    const a = (raw as any)?.agent;
    clients[name] = { agent: typeof a === 'string' && a ? a : undefined };
  }
  return {
    agent: typeof m?.agent === 'string' && m.agent ? m.agent : undefined,
    clients,
  };
}

function normalizeHardened(h: any): HardenedConfig {
  const str = (v: any) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  const int = (v: any) => (Number.isInteger(v) ? v : undefined);
  const uids = Array.isArray(h?.allowed_uids)
    ? h.allowed_uids.filter((x: any) => Number.isInteger(x))
    : undefined;
  const sids = Array.isArray(h?.allowed_sids)
    ? h.allowed_sids.filter((x: any): x is string => typeof x === 'string' && x.length > 0)
    : undefined;
  const pv = str(h?.peer_verify);
  return {
    enabled: h?.enabled === true,
    endpoint: str(h?.endpoint),
    token_file: str(h?.token_file),
    state_dir: str(h?.state_dir),
    service_uid: int(h?.service_uid),
    peer_verify: pv === 'auto' || pv === 'strict' || pv === 'off' ? pv : undefined,
    allowed_uids: uids?.length ? uids : undefined,
    allowed_sids: sids?.length ? sids : undefined,
    connect_timeout_ms: int(h?.connect_timeout_ms),
  };
}

export function loadConfig(): AppConfig {
  if (!existsSync(CONFIG_PATH)) throw new Error('CONFIG_NOT_FOUND');
  // Older config.toml files upgrade in memory via migrateSchema — the file
  // itself is untouched until the next save (or an explicit
  // `kp config migrate`), so read paths never write.
  const m = migrateSchema(parseToml(readFileSync(CONFIG_PATH, 'utf8')));
  const cfg = normalize(m.raw);
  if (m.applied.length) cfg.migrations_applied = m.applied;
  return cfg;
}

export function defaultConfig(): AppConfig {
  return normalize({
    keepass: {
      executable: 'C:/Program Files/KeePass Password Safe 2/KeePass.exe',
      kpscript: '',
    },
    databases: {},
    // Usability seed for fresh installs: the unidentified ('default') agent
    // starts allow-all so a first `kp` run works out of the box. This is an
    // INITIAL PERMISSIVE posture — operators should scope it down (or delete
    // the section) before granting agents access; the policy engine itself
    // remains strictly deny-by-default. See docs/configuration.md.
    agents: { default: { allowed: ['*'] } },
  });
}

export function configExists(): boolean {
  return existsSync(CONFIG_PATH);
}

function validatePath(p: string, what: string): string[] {
  const errs: string[] = [];
  if (!isAbsolute(p) && !/^[A-Za-z]:[\/]/.test(p)) errs.push(`${what} not absolute: ${p}`);
  if (p.includes('..')) errs.push(`${what} contains '..': ${p}`);
  return errs;
}

export function validateConfig(c: AppConfig): string[] {
  const errs: string[] = [];
  for (const [alias, db] of Object.entries(c.databases)) {
    if (!/^[a-z0-9_-]+$/i.test(alias)) errs.push(`db alias invalid: ${alias}`);
    errs.push(...validatePath(db.path, `databases.${alias}.path`));
    if (db.key_file) errs.push(...validatePath(db.key_file, `databases.${alias}.key_file`));
    if (db.session_timeout != null && (db.session_timeout < 0 || db.session_timeout > 86400))
      errs.push(`databases.${alias}.session_timeout out of range`);
    if (db.unlock_method && !['local-web', 'keepass-gui'].includes(db.unlock_method))
      errs.push(`databases.${alias}.unlock_method invalid`);
  }
  if (c.keepass.kpscript) errs.push(...validatePath(c.keepass.kpscript, 'keepass.kpscript'));
  if (c.keepass.executable) errs.push(...validatePath(c.keepass.executable, 'keepass.executable'));
  if (c.unlock.port < 1 || c.unlock.port > 65535) errs.push('unlock.port out of range');
  if (!['127.0.0.1', 'localhost', '::1'].includes(c.unlock.host)) errs.push('unlock.host must be loopback');
  if (!['get', 'post'].includes(c.unlock.transport)) errs.push('unlock.transport must be get|post');
  for (const [name, a] of Object.entries(c.agents ?? {})) {
    if (!/^[a-z0-9_-]{1,64}$/i.test(name) || FORBIDDEN_TOML_KEYS.has(name.toLowerCase()))
      errs.push(`agents.${name} name invalid (no dots — TOML section path; no prototype keys)`);
    for (const f of AGENT_LIST_FIELDS) {
      const v = (a as any)[f];
      if (v != null && (!Array.isArray(v) || v.some((x) => typeof x !== 'string')))
        errs.push(`agents.${name}.${f} must be a string list`);
    }
  }
  if (c.policy.audit_max_bytes != null &&
      (c.policy.audit_max_bytes < 1024 || c.policy.audit_max_bytes > 1 << 30))
    errs.push('policy.audit_max_bytes out of range (1024..1073741824)');
  // [hardened] — fail-closed knobs must themselves be well-formed.
  const h = c.hardened;
  if (h.enabled != null && typeof h.enabled !== 'boolean') errs.push('hardened.enabled must be boolean');
  for (const [k, v] of [['hardened.endpoint', h.endpoint], ['hardened.token_file', h.token_file], ['hardened.state_dir', h.state_dir]] as const) {
    // POSIX endpoint may be a bare pipe-style name on win32; absolute paths
    // required only where a filesystem path is expected (non-endpoint keys
    // and POSIX endpoints).
    if (!v) continue;
    if (k === 'hardened.endpoint' && process.platform === 'win32') {
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(v)) errs.push('hardened.endpoint must be a pipe name ([A-Za-z0-9._-]{1,128})');
    } else errs.push(...validatePath(v, k));
  }
  if (h.service_uid != null && (!Number.isInteger(h.service_uid) || h.service_uid < 0))
    errs.push('hardened.service_uid must be a non-negative integer');
  if (h.peer_verify != null && !['auto', 'strict', 'off'].includes(h.peer_verify))
    errs.push('hardened.peer_verify must be auto|strict|off');
  if (h.allowed_uids != null && (!Array.isArray(h.allowed_uids) || h.allowed_uids.some((x) => !Number.isInteger(x) || x < 0)))
    errs.push('hardened.allowed_uids must be a non-negative integer list');
  if (h.allowed_sids != null && (!Array.isArray(h.allowed_sids) || h.allowed_sids.some((x) => typeof x !== 'string' || !x.length)))
    errs.push('hardened.allowed_sids must be a string list');
  if (h.peer_verify === 'strict' && !h.allowed_uids?.length)
    errs.push('hardened.peer_verify=strict requires hardened.allowed_uids');
  if (h.connect_timeout_ms != null && (h.connect_timeout_ms < 100 || h.connect_timeout_ms > 600_000))
    errs.push('hardened.connect_timeout_ms out of range (100..600000)');
  // [mcp] — declared identities only; same charset as agent ids.
  const AGENT_ID_LIKE = /^[A-Za-z0-9_-]{1,64}$/;
  const badId = (v: string) => !AGENT_ID_LIKE.test(v) || FORBIDDEN_TOML_KEYS.has(v.toLowerCase());
  if (c.mcp.agent != null && badId(c.mcp.agent)) errs.push('mcp.agent invalid agent id');
  for (const [name, cl] of Object.entries(c.mcp.clients ?? {})) {
    if (badId(name)) errs.push(`mcp.clients.${name} name invalid (lowercase [a-z0-9_-]{1,64}, no dots/prototype keys)`);
    if (cl.agent != null && badId(cl.agent)) errs.push(`mcp.clients.${name}.agent invalid agent id`);
  }
  // [cdp] — the login worker types vault secrets into this endpoint, so it
  // is held to the same loopback rule as the --cdp flag / unlock server.
  if (c.cdp?.endpoint != null && !isLoopbackCdpEndpoint(c.cdp.endpoint))
    errs.push('cdp.endpoint must be loopback (http(s) on 127.0.0.1/localhost/[::1])');
  return errs;
}

/** Atomic save — write tmp then rename; config never partially written. */
export function saveConfig(c: AppConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  const lines: string[] = [
    `schema_version = ${CONFIG_SCHEMA_VERSION}`,
    '',
    '[keepass]',
    `executable = ${tomlEscape(c.keepass.executable ?? '')}`,
    `kpscript = ${tomlEscape(c.keepass.kpscript ?? '')}`,
    `default_database = ${tomlEscape(c.keepass.default_database ?? '')}`,
    '',
  ];
  for (const [alias, db] of Object.entries(c.databases)) {
    lines.push(`[databases.${alias}]`);
    lines.push(`path = ${tomlEscape(db.path)}`);
    if (db.key_file) lines.push(`key_file = ${tomlEscape(db.key_file)}`);
    if (db.unlock_method) lines.push(`unlock_method = ${tomlEscape(db.unlock_method)}`);
    if (db.session_timeout != null) lines.push(`session_timeout = ${db.session_timeout}`);
    lines.push('');
  }
  lines.push('[unlock]');
  lines.push(`host = ${tomlEscape(c.unlock.host)}`);
  lines.push(`port = ${c.unlock.port}`);
  lines.push(`auto_open_browser = ${c.unlock.auto_open_browser}`);
  lines.push(`transport = ${tomlEscape(c.unlock.transport)}`, '');
  if (c.policy.audit_max_bytes != null) {
    lines.push('[policy]', `audit_max_bytes = ${c.policy.audit_max_bytes}`, '');
  }
  const h = c.hardened;
  if (h.enabled || h.endpoint || h.token_file || h.state_dir || h.service_uid != null ||
      h.peer_verify || h.allowed_uids?.length || h.allowed_sids?.length || h.connect_timeout_ms != null) {
    lines.push('[hardened]');
    lines.push(`enabled = ${h.enabled === true}`);
    if (h.endpoint) lines.push(`endpoint = ${tomlEscape(h.endpoint)}`);
    if (h.token_file) lines.push(`token_file = ${tomlEscape(h.token_file)}`);
    if (h.state_dir) lines.push(`state_dir = ${tomlEscape(h.state_dir)}`);
    if (h.service_uid != null) lines.push(`service_uid = ${h.service_uid}`);
    if (h.peer_verify) lines.push(`peer_verify = ${tomlEscape(h.peer_verify)}`);
    if (h.allowed_uids?.length) lines.push(`allowed_uids = ${JSON.stringify(h.allowed_uids)}`);
    if (h.allowed_sids?.length) lines.push(`allowed_sids = ${JSON.stringify(h.allowed_sids)}`);
    if (h.connect_timeout_ms != null) lines.push(`connect_timeout_ms = ${h.connect_timeout_ms}`);
    lines.push('');
  }
  const cd = c.cdp;
  if (cd?.endpoint || cd?.allow_default_context) {
    lines.push('[cdp]');
    if (cd.endpoint) lines.push(`endpoint = ${tomlEscape(cd.endpoint)}`);
    if (cd.allow_default_context) lines.push('allow_default_context = true');
    lines.push('');
  }
  const m = c.mcp;
  if (m.agent || Object.keys(m.clients).length) {
    lines.push('[mcp]');
    if (m.agent) lines.push(`agent = ${tomlEscape(m.agent)}`);
    lines.push('');
    for (const [name, cl] of Object.entries(m.clients)) {
      lines.push(`[mcp.clients.${name}]`);
      if (cl.agent) lines.push(`agent = ${tomlEscape(cl.agent)}`);
      lines.push('');
    }
  }
  for (const [name, a] of Object.entries(c.agents)) {
    lines.push(`[agents.${name}]`);
    for (const f of AGENT_LIST_FIELDS) {
      if (a[f]?.length) lines.push(`${f} = ${JSON.stringify(a[f])}`);
    }
    lines.push('');
  }
  const tmp = CONFIG_PATH + '.tmp';
  writeFileSync(tmp, lines.join('\n') + '\n', 'utf8');
  renameSync(tmp, CONFIG_PATH);
}

/** Path safety — resolve symlinks for file existence checks without following '..'. */
export function safeReal(p: string): string | null {
  try {
    if (!existsSync(p)) return null;
    return realpathSync(p);
  } catch { return null; }
}

export function fileExists(p: string): boolean {
  try { return statSync(p).isFile(); } catch { return false; }
}
