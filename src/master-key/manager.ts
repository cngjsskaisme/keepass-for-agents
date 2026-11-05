// Master Key Manager — per-DB unlock state, session lifecycle.
// Plaintext keys live only inside the broker process memory during a call;
// between invocations they persist as DPAPI-encrypted session files.
// Key verification goes through the CredentialProvider seam — this module
// owns sessions, never a KDBX backend directly.

import { readSession, saveSession, clearSession, sessionStatus } from '../security/dpapi.ts';
import { createProvider } from '../provider/provider.ts';
import type { DbConfig } from '../config/config.ts';

export type DbState = 'LOCKED' | 'UNLOCK_REQUIRED' | 'UNLOCKING' | 'UNLOCKED' | 'EXPIRED' | 'ERROR';

export function dbState(alias: string): DbState {
  const s = sessionStatus(alias);
  return s === 'UNLOCKED' ? 'UNLOCKED' : s === 'EXPIRED' ? 'EXPIRED' : 'LOCKED';
}

/** Verify a master key — returns null on success or a provider error code. */
export async function verifyKey(kpscript: string | string[], db: DbConfig, masterKey: string): Promise<string | null> {
  const r = await createProvider(kpscript).verifyKey(db, masterKey);
  return r.ok ? null : r.code;
}

/** Unlock a DB: verify key then persist as DPAPI session. */
export async function unlock(kpscript: string | string[], alias: string, db: DbConfig, masterKey: string): Promise<{ ok: boolean; code?: string }> {
  const err = await verifyKey(kpscript, db, masterKey);
  if (err) return { ok: false, code: err };
  await saveSession(alias, masterKey, db.session_timeout ?? 900);
  return { ok: true };
}

export function lock(alias: string): void {
  clearSession(alias);
}

export { readSession };
