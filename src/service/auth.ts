// IPC capability-token authentication.
//
// The service generates a 256-bit random token at startup and writes it to a
// token file. Whoever can READ that file may authenticate — the file's
// filesystem ACL is therefore the kernel-enforced caller-authorization
// boundary:
//   POSIX   — chown service:agent-group, mode 0640 (provisioning manages the
//             group; this module writes 0640 and the ACL checker verifies no
//             'other' access).
//   Windows — NTFS ACL restricted to the service + agent/operator SIDs by
//             provisioning; acl.ts verifies deny-listed principals are absent.
//
// The handshake itself is HMAC-SHA256(token, server-nonce) — the token never
// travels the wire, and a replayed response is bound to a fresh nonce.

import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, chmodSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function newNonce(): string {
  return randomBytes(24).toString('base64url');
}

export function hmacToken(token: string, nonce: string): string {
  return createHmac('sha256', token).update(nonce).digest('hex');
}

export function verifyHmac(token: string, nonce: string, presented: string): boolean {
  const expected = hmacToken(token, nonce);
  const a = Buffer.from(expected);
  const b = Buffer.from(typeof presented === 'string' ? presented : '');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Persist the token for callers. POSIX: mode 0640 (owner rw, group r, other
 * none) — the *group* grants the agent principal its read; provisioning owns
 * the group mapping. Windows: file perms are ACL-based; provisioning applies
 * the SID restriction and acl.ts verifies it.
 */
export function writeTokenFile(path: string, token: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, token, { encoding: 'utf8', mode: 0o640 });
  try { chmodSync(path, 0o640); } catch {}
}

/**
 * Load the token as a prospective caller. Returns null when the file is
 * missing/unreadable/empty — the caller maps that to
 * HARDENED_TOKEN_UNAVAILABLE (never a silent retry against the service).
 */
export function readTokenFile(path: string): string | null {
  try {
    const s = readFileSync(path, 'utf8').trim();
    return s.length >= 32 ? s : null;
  } catch { return null; }
}

/** Existence/type check without reading (pre-flight diagnostics). */
export function tokenFileStat(path: string): { exists: boolean; mode?: number } {
  try {
    const st = statSync(path);
    return { exists: st.isFile(), mode: st.mode & 0o777 };
  } catch { return { exists: false } };
}
