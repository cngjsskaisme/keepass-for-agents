// Audit log — append-only JSONL at ~/.config/keepass-agent/audit.log.
//
// Every gated action (allow / deny / require_approval → success or failure)
// emits exactly one record:
//   {ts, agent, action, target, decision, result_code, db}
// `target` is non-secret metadata only (entry uuid / title / host). Secrets,
// passwords, cookie values, or master key material MUST NEVER be passed to
// audit() — the schema whitelist below drops any field outside the contract,
// and values are stripped of control chars and capped in length, but the
// caller contract is still "no secrets", by design and by review.
//
// POSIX mode 0600 (user-only read); single-generation rotation — when the
// file would exceed audit_max_bytes (default 1 MiB) it is renamed to
// audit.log.1 before the append. Audit failures never break the action path
// (a gateway that can't log still must not leak or hang), but they are
// reported on stderr.

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { CONFIG_DIR } from '../config/config.ts';

export const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');
export const AUDIT_MAX_BYTES_DEFAULT = 1_048_576; // 1 MiB

export interface AuditRecord {
  ts: string;                    // ISO-8601
  agent: string;                 // declared agent id ('default' when unidentified)
  action: string;                // e.g. 'search', 'login', 'entry.add', 'config.set'
  target?: string;               // non-secret: entry uuid/title, host, config key
  decision?: string;             // 'allow' | 'deny' | 'require_approval' (policy-gated events)
  result_code?: string;          // outcome code ('OK' on success)
  db?: string;                   // database alias
}

/** Cap and de-control any value bound for the log — display-safe, JSONL-safe. */
function clean(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined;
  return v.replace(/[\x00-\x1f\x7f-\x9f]/g, '').slice(0, 256) || undefined;
}

export function audit(e: Omit<AuditRecord, 'ts'>, maxBytes: number = AUDIT_MAX_BYTES_DEFAULT): void {
  try {
    const rec: AuditRecord = {
      ts: new Date().toISOString(),
      agent: clean(e.agent) ?? 'unknown',
      action: clean(e.action) ?? '?',
    };
    for (const k of ['target', 'decision', 'result_code', 'db'] as const) {
      const v = clean(e[k]);
      if (v) rec[k] = v;
    }
    const line = JSON.stringify(rec) + '\n';
    mkdirSync(CONFIG_DIR, { recursive: true });
    try {
      if (existsSync(AUDIT_LOG) && statSync(AUDIT_LOG).size + Buffer.byteLength(line) > maxBytes)
        renameSync(AUDIT_LOG, AUDIT_LOG + '.1');
    } catch { /* rotation failure must not lose the record */ }
    appendFileSync(AUDIT_LOG, line, { mode: 0o600 });
    try { chmodSync(AUDIT_LOG, 0o600); } catch {} // no-op on Windows ACLs
  } catch (err) {
    try {
      process.stderr.write(`kp: warning: audit log write failed: ${String((err as any)?.message || err)}\n`);
    } catch {}
  }
}

/** Read the tail of the audit log (oldest→newest), tolerating torn lines. */
export function readAudit(limit = 100): AuditRecord[] {
  try {
    const lines = readFileSync(AUDIT_LOG, 'utf8').split('\n').filter(Boolean);
    return lines
      .slice(-Math.max(1, Math.min(limit, 1000)))
      .map((l) => { try { return JSON.parse(l) as AuditRecord; } catch { return null; } })
      .filter((r): r is AuditRecord => !!r);
  } catch { return []; }
}
