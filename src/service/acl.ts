// Isolation/ACL checks — the fail-closed environment gate for Hardened Mode.
//
// What "isolated" means here:
//   - Session files, the IPC socket, and the capability token live on the
//     service principal's side; any other-access permission ('other' bits on
//     POSIX, broad NTFS grants on Windows) means a non-service principal can
//     read them → the check fails.
//   - Every registered KDBX must be unreadable by the agent principal: on
//     POSIX, 'other' bits must be zero and (when hardened.service_uid is set)
//     the owner uid must match the service account. On Windows the NTFS ACL
//     must not grant broad principals (Everyone / BUILTIN\Users /
//     Authenticated Users).
//   - Windows named pipes cannot be ACL'd from Node (libuv passes NULL
//     security attributes) — the capability-token file ACL is the enforced
//     caller boundary there, verified with the same icacls scan.
//
// A check that cannot be executed (icacls missing, stat fails) is reported
// UNMET — Hardened Mode never assumes a permission it cannot see.

import { statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import type { AppConfig } from '../config/config.ts';

export interface AclCheck {
  /** Stable check name — surfaced in `kp status` and failure details. */
  check: 'kdbx_isolation' | 'token_file_perms' | 'socket_perms' | 'session_dir_perms';
  path: string;
  ok: boolean;
  detail?: string;
}

/**
 * icacls ACE parser — one entry per `PRINCIPAL:(perms)` line. Display form
 * (account name or unresolvable `S-1-…` sid) is kept verbatim-lowercased.
 * The FIRST ACE sits on the same line as the file path — when `path` is
 * given it is stripped before matching so no ACE escapes the allow-list.
 */
export function parseIcaclsPrincipals(output: string, path?: string): string[] {
  const principals: string[] = [];
  for (const raw of output.split('\n')) {
    let line = raw;
    if (path && line.toLowerCase().startsWith(path.toLowerCase()))
      line = line.slice(path.length);
    // `:(` distinguishes ACE entries from the `C:` drive prefix; the
    // `Successfully processed` summary carries no `:(` shape either.
    const m = line.match(/^\s*(.+?):\(/);
    if (m) principals.push(m[1].trim().toLowerCase());
  }
  return principals;
}

/**
 * Allow-list ACL check (F2): EVERY principal granted on the file must appear
 * in `allowed` — deny-listed-principal matching was replaced because new or
 * unusual principals (INTERACTIVE, NETWORK, app-container sids, …) silently
 * escaped it. `allowed` entries match either the icacls display form
 * (`builtin\administrators`, `machine\kpa-svc`) or a raw sid, lowercased.
 * Unconfigured allow-list → unmet (the gate cannot verify what it can't see);
 * a DENY-ACE principal also fails — a hand-edited ACE shape the gate cannot
 * model is treated as unsafe, fail-closed.
 */
export function winAclCheck(path: string, allowed: readonly string[] | undefined): { ok: boolean; detail?: string } {
  if (!allowed?.length) return { ok: false, detail: 'allowed_sids_unconfigured' };
  const allow = new Set(allowed.map((p) => p.toLowerCase()));
  const r = spawnSync('icacls', [path], { encoding: 'utf8', timeout: 10_000, windowsHide: true });
  if (r.error || r.status == null) return { ok: false, detail: 'icacls_unavailable' };
  if (r.status !== 0) return { ok: false, detail: `icacls_exit_${r.status}` };
  const principals = parseIcaclsPrincipals(`${r.stdout}\n${r.stderr}`, path);
  const foreign = principals.find((p) => !allow.has(p));
  if (foreign) return { ok: false, detail: `foreign_principal:${foreign}` };
  return { ok: true };
}

/** POSIX stat-based check: no 'other' permission bits; optional owner-uid pin. */
export function posixPermCheck(path: string, opts: { ownerUid?: number; what: string }): { ok: boolean; detail?: string } {
  let st;
  try { st = statSync(path); } catch { return { ok: false, detail: `${opts.what}_missing` }; }
  const mode = st.mode & 0o777;
  if (mode & 0o007) return { ok: false, detail: `other_access_bits:${mode.toString(8)}` };
  if (opts.ownerUid != null && st.uid !== opts.ownerUid)
    return { ok: false, detail: `owner_uid_${st.uid}_expected_${opts.ownerUid}` };
  return { ok: true };
}

function fileCheck(check: AclCheck['check'], path: string, ownerUid?: number, allowedSids?: readonly string[]): AclCheck {
  const r = process.platform === 'win32'
    ? winAclCheck(path, allowedSids)
    : posixPermCheck(path, { ownerUid, what: check });
  return { check, path, ok: r.ok, detail: r.detail };
}

/**
 * KDBX isolation: the vault file must not be world-accessible, and when
 * hardened.service_uid is configured the owner must be the service account —
 * a vault owned by the agent uid is definitionally not isolated.
 */
export function checkKdbxIsolation(cfg: AppConfig, kdbxPath: string): AclCheck {
  return fileCheck('kdbx_isolation', kdbxPath, cfg.hardened.service_uid, cfg.hardened.allowed_sids);
}

export function checkTokenFile(cfg: AppConfig, tokenPath: string): AclCheck {
  return fileCheck('token_file_perms', tokenPath, undefined, cfg.hardened.allowed_sids);
}

export function checkSessionDir(cfg: AppConfig, dirPath: string): AclCheck {
  return fileCheck('session_dir_perms', dirPath, cfg.hardened.service_uid, cfg.hardened.allowed_sids);
}

export function checkSocketFile(socketPath: string, allowedSids?: readonly string[]): AclCheck {
  return fileCheck('socket_perms', socketPath, undefined, allowedSids);
}

/**
 * Pre-dispatch gate (client side): run every check relevant to the command's
 * target. Returns the list of failed checks — empty means the environment
 * satisfies the isolation contract. Callers fail with HARDENED_ACL_UNMET on
 * a non-empty result.
 */
export function verifyHardenedEnvironment(cfg: AppConfig, opts: {
  tokenPath: string;
  kdbxPaths?: string[];
  socketPath?: string;
}): AclCheck[] {
  const checks: AclCheck[] = [checkTokenFile(cfg, opts.tokenPath)];
  for (const p of opts.kdbxPaths ?? []) checks.push(checkKdbxIsolation(cfg, p));
  if (opts.socketPath && process.platform !== 'win32') checks.push(checkSocketFile(opts.socketPath));
  return checks.filter((c) => !c.ok);
}

/**
 * Service self-check at startup — the service verifies its OWN side of the
 * boundary (socket dir, token file) right after binding. Skipped when
 * KEEPASS_AGENT_SERVICE_SELFTEST is set (same-principal dev/test runs); that
 * hook is for the test suite only and emits a stderr warning, matching the
 * repo's other injection-hook conventions.
 */
export function serviceSelfCheck(cfg: AppConfig, paths: { tokenPath: string; socketPath?: string; sessionDir: string }): AclCheck[] {
  if (process.env.KEEPASS_AGENT_SERVICE_SELFTEST) return [];
  const checks: AclCheck[] = [
    fileCheck('token_file_perms', paths.tokenPath, undefined, cfg.hardened.allowed_sids),
    fileCheck('session_dir_perms', paths.sessionDir, cfg.hardened.service_uid, cfg.hardened.allowed_sids),
  ];
  if (paths.socketPath && process.platform !== 'win32')
    checks.push(fileCheck('socket_perms', paths.socketPath, undefined, cfg.hardened.allowed_sids));
  return checks;
}
