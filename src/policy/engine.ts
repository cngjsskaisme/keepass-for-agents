// Policy Engine — per-agent action/entry/host policy for the credential
// gateway.
//
// Identity model: the agent declares itself via `--agent <id>` or the
// `KEEPASS_AGENT_ID` env var. This is a *self-declared* identity — Standard
// Mode runs everything under one OS principal, so a same-UID process could
// claim any agent name. The identity exists to scope policy decisions and
// audit attribution, not to authenticate the caller (that needs Hardened
// Mode, out of scope). An unidentified caller resolves to the reserved
// agent name `default`.
//
// Decision model: deny-by-default. An action that is not listed in the
// resolved agent policy's `allowed` or `require_approval` is denied
// (POLICY_DENIED). `require_approval` means the action may only proceed
// through the existing one-time-token web approval flow — today that covers
// unlock/entry.add/entry.sync-cookies/entry.login-capture/db.create; for any
// other action the CLI reports POLICY_APPROVAL_REQUIRED (fail-closed — a
// generic approval channel is follow-up work).
//
// Policy lives in config.toml ([agents.<name>] / [policy]); editing rights
// are governed by OS file permissions on config.toml — the engine only reads.

import type { AppConfig, AgentPolicy } from '../config/config.ts';
import { FORBIDDEN_TOML_KEYS } from '../config/config.ts';

export const DEFAULT_AGENT = 'default';

// Agent ids double as TOML section names ([agents.<id>]) — no dots.
const AGENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Action names the existing web approval flow can satisfy. */
export const APPROVABLE_ACTIONS = new Set([
  'unlock', 'entry.add', 'entry.sync-cookies', 'entry.login-capture', 'db.create',
]);

export type PolicyDecision = 'allow' | 'deny' | 'require_approval';

export interface EvalResult {
  decision: PolicyDecision;
  /** Non-secret rationale, safe to surface in `detail` and the audit log. */
  reason: string;
  /** Which policy resolved the decision — the agent name, `default`, or none. */
  policy: string;
}

/** Non-secret target context for entry/host-scoped checks. */
export interface EvalTarget {
  entry?: { id?: string; title?: string; url?: string };
  /** Normalized URL host (worker credential destination). */
  host?: string;
}

/**
 * Resolve the calling agent's declared identity. `--agent` (flag) wins over
 * `KEEPASS_AGENT_ID` (env); neither → `default`. The value must match a
 * strict charset — it lands in audit logs and TOML section names.
 */
export function resolveAgentId(
  env: NodeJS.ProcessEnv = process.env, flagAgent?: string | boolean,
): { ok: true; agent: string } | { ok: false; reason: string } {
  const raw = (typeof flagAgent === 'string' && flagAgent) || env.KEEPASS_AGENT_ID || DEFAULT_AGENT;
  if (!AGENT_ID_RE.test(raw) || FORBIDDEN_TOML_KEYS.has(raw.toLowerCase()))
    return { ok: false, reason: `agent id must match [A-Za-z0-9_-]{1,64} and not be a reserved key` };
  return { ok: true, agent: raw };
}

/** Look up the effective policy: named agent, else `default`, else none.
 *  `hasOwn` guards inherited-property names (`constructor`, `toString`, …)
 *  from resolving to builtins instead of a policy object. */
export function agentPolicy(cfg: AppConfig, agent: string): AgentPolicy | null {
  const a = cfg.agents ?? {};
  if (Object.hasOwn(a, agent)) return a[agent];
  if (Object.hasOwn(a, DEFAULT_AGENT)) return a[DEFAULT_AGENT];
  return null;
}

/** Glob match: `*` → any run, `?` → one char; anchored, case-insensitive. */
export function globMatch(pattern: string, value: string): boolean {
  const esc = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${esc}$`, 'i').test(value);
}

export function matchAny(patterns: readonly string[] | undefined, value: string): boolean {
  return !!patterns?.some((p) => globMatch(p, value));
}

function normalizeUuid(u: string): string {
  return u.replace(/-/g, '').toLowerCase();
}

function hostOf(url?: string): string {
  if (!url) return '';
  try {
    const u = new URL(url.includes('://') ? url : 'https://' + url);
    // Trailing-root-dot (`evil.com.`) must collapse the same way hostAllowed
    // normalizes its input — otherwise an asymmetric form bypasses
    // denied_entries/allowed_hosts matching.
    return u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.+$/, '');
  } catch { return ''; }
}

/**
 * One allowed/denied entry pattern vs an entry: `uuid:<id>` is an exact
 * (dash-insensitive) uuid match; anything else is a glob tried against the
 * title and the URL's normalized host.
 */
export function entryMatches(pattern: string, e: { id?: string; title?: string; url?: string }): boolean {
  if (pattern.toLowerCase().startsWith('uuid:'))
    return normalizeUuid(pattern.slice(5)) === normalizeUuid(e.id ?? '');
  return globMatch(pattern, e.title ?? '') || globMatch(pattern, hostOf(e.url));
}

/**
 * Entry-level restriction for a resolved policy: `denied_entries` always
 * wins; a non-empty `allowed_entries` makes the set exclusive. A null policy
 * means "no policy resolved" — fail closed.
 */
export function entryPermitted(
  pol: AgentPolicy | null | undefined, e: { id?: string; title?: string; url?: string },
): boolean {
  if (!pol) return false;
  if (pol.denied_entries?.some((p) => entryMatches(p, e))) return false;
  if (pol.allowed_entries?.length && !pol.allowed_entries.some((p) => entryMatches(p, e))) return false;
  return true;
}

/**
 * Host allowlist check for `allowed_hosts` (worker login destination).
 * Plain hostnames use dot-boundary semantics (`github.com` covers
 * `*.github.com`, never `mygithub.com`); patterns containing `*`/`?` are
 * treated as globs. An absent list means "no extra host restriction".
 */
export function hostAllowed(pol: AgentPolicy | null | undefined, host: string): boolean {
  const list = pol?.allowed_hosts;
  if (!list?.length) return true;
  const h = host.toLowerCase().replace(/\.+$/, '');
  if (!h) return false;
  return list.some((p) => {
    const pat = p.toLowerCase();
    if (/[*?]/.test(pat)) return globMatch(pat, h);
    return h === pat || h.endsWith('.' + pat);
  });
}

/**
 * Policy evaluation — deny-by-default.
 *   1. resolve agent policy (agent → default → none=deny)
 *   2. action must appear in `allowed` or `require_approval` (glob)
 *   3. entry target must survive denied_entries/allowed_entries
 *   4. host target must satisfy allowed_hosts when the list exists
 * `require_approval` listed actions take the stricter decision even when
 * also present in `allowed`.
 */
export function evaluate(cfg: AppConfig, agent: string, action: string, target: EvalTarget = {}): EvalResult {
  const pol = agentPolicy(cfg, agent);
  if (!pol)
    return { decision: 'deny', policy: 'none', reason: `no policy for agent '${agent}' (deny-by-default)` };
  const policyName = Object.hasOwn(cfg.agents ?? {}, agent) ? agent : DEFAULT_AGENT;
  const allowed = matchAny(pol.allowed, action);
  const approval = matchAny(pol.require_approval, action);
  if (!allowed && !approval)
    return { decision: 'deny', policy: policyName, reason: `action '${action}' not allowed for agent '${agent}'` };
  if (target.entry && !entryPermitted(pol, target.entry))
    return { decision: 'deny', policy: policyName, reason: `entry not permitted by agents.${policyName} entry policy` };
  if (target.host && pol.allowed_hosts?.length && !hostAllowed(pol, target.host))
    return { decision: 'deny', policy: policyName, reason: `host '${target.host}' not in agents.${policyName}.allowed_hosts` };
  if (approval)
    return { decision: 'require_approval', policy: policyName, reason: `action '${action}' requires approval for agent '${agent}'` };
  return { decision: 'allow', policy: policyName, reason: `action '${action}' allowed for agent '${agent}'` };
}
