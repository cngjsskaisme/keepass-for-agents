// Credential Provider — the single seam between kp's flows and a KDBX backend.
//
// Two backends implement this contract:
//   KpscriptProvider  — Windows: KeePass 2 KPScript.exe (verify/list/getSecret)
//   PyKeePassProvider — POSIX:   src/keepass/*.py helpers (all operations)
// Write operations (createDb/addEntry/updateEntryFields) are PyKeePass-based on
// every platform — KpscriptProvider inherits them from PyKeePassProvider.
// Backend selection is platform-based via createProvider() — callers hold the
// interface, never a process.platform branch.
//
// Error codes are part of the external contract: the CLI prints them verbatim
// in the stdout JSON `code` field and maps some to non-zero exit codes, and the
// unlock server returns them to the browser. Values are frozen — renaming is a
// breaking change.

import type { DbConfig } from '../config/config.ts';
import { PyKeePassProvider } from './pykeepass.ts';
import { KpscriptProvider } from './kpscript.ts';

/** Entry metadata as surfaced by list operations (never the secret fields). */
export interface Entry {
  id: string;
  title: string;
  username: string;
  url: string;
}

/** Payload for a new KDBX entry — password travels provider-ward only. */
export interface NewEntry {
  title: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
}

/**
 * Discriminated result every provider operation returns. `code` is a frozen
 * contract value (see PROVIDER_ERROR_CODES); `detail` carries sanitized
 * non-secret context (e.g. why SECRET_OUTPUT_INVALID fired).
 */
export type ProviderResult<T extends object = object> =
  | ({ ok: true } & T)
  | { ok: false; code: string; detail?: string };

/**
 * Provider error-code namespace — the union of codes the provider boundary
 * may surface. Two origins, one flat namespace (upstream consumers switch on
 * the bare string):
 *   - backend-owned codes emitted by this layer (spawn/timeout/validation)
 *   - helper-owned codes forwarded verbatim from kdbx_helper.py /
 *     create_kdbx.py / add_entry.py / update_entry.py (`result.code`)
 */
export const PROVIDER_ERROR_CODES = [
  // provider-owned: helper availability / process lifecycle
  'PYTHON_HELPER_NOT_READY', 'PYTHON_HELPER_SPAWN_FAILED', 'HELPER_TIMEOUT', 'HELPER_FAILED',
  // provider-owned: kdbx lifecycle
  'INVALID_CONFIG', 'DATABASE_ALREADY_EXISTS',
  'KDBX_CREATE_TIMEOUT', 'KDBX_CREATE_FAILED',
  'ENTRY_ADD_TIMEOUT', 'ENTRY_ADD_FAILED',
  'ENTRY_UPDATE_TIMEOUT', 'ENTRY_UPDATE_FAILED',
  // provider-owned: KPScript backend
  'KPSCRIPT_SPAWN_FAILED', 'KPSCRIPT_TIMEOUT', 'KPSCRIPT_FAILED',
  'UNSUPPORTED_SECRET_ENCODING', 'INVALID_SECRET_CHARS', 'SECRET_OUTPUT_INVALID',
  'AUTHENTICATION_FAILED', 'INVALID_MASTER_KEY',
  // helper-owned codes forwarded as-is from the Python helpers' JSON results
  'DATABASE_NOT_FOUND', 'KEYFILE_NOT_FOUND', 'ENTRY_NOT_FOUND', 'FIELD_NOT_FOUND',
  'EMPTY_MASTER_KEY', 'DB_OPEN_FAILED', 'UNKNOWN_CMD',
  // catch-all for unexpected backend errors
  'INTERNAL_ERROR',
] as const;
export type ProviderErrorCode = typeof PROVIDER_ERROR_CODES[number];

export interface CredentialProvider {
  /** Which backend this provider drives — for diagnostics/tests, not output. */
  readonly kind: 'kpscript' | 'pykeepass';
  /** Verify a master key against the DB. ok → verified; otherwise an error code. */
  verifyKey(db: DbConfig, masterKey: string): Promise<ProviderResult>;
  /** List entry metadata — id/title/username/url only, never secret fields. */
  listEntries(db: DbConfig, masterKey: string): Promise<ProviderResult<{ entries: Entry[] }>>;
  /** Fetch one field (default password) from an entry — for worker stdin piping. */
  getSecret(db: DbConfig, masterKey: string, uuid: string, field?: string): Promise<ProviderResult<{ secret: string }>>;
  /** Create a new KDBX file on disk. */
  createDb(path: string, masterKey: string, keyFile?: string): Promise<ProviderResult>;
  /** Add an entry; returns the new uuid (KPScript form, dashes stripped) when known. */
  addEntry(db: DbConfig, masterKey: string, entry: NewEntry): Promise<ProviderResult<{ uuid?: string }>>;
  /** Set custom string fields on an existing entry (uuid without dashes). */
  updateEntryFields(db: DbConfig, masterKey: string, uuid: string, fields: Record<string, string>): Promise<ProviderResult>;
}

/**
 * Split a kpscript reference into exe + prefix args. Callers pass either a
 * plain path or [exe, ...prefixArgs] — the prefix convention lets tests inject
 * a script arg (e.g. [node, mock.mjs]) without changing call sites.
 */
export function kpscriptParts(kp: string | string[]): { exe: string; prefix: string[] } {
  const a = Array.isArray(kp) ? kp : [kp];
  return { exe: a[0] ?? '', prefix: a.slice(1) };
}

/** Backend selection: KPScript on Windows, the PyKeePass helpers elsewhere. */
export function createProvider(kpscript: string | string[]): CredentialProvider {
  return process.platform === 'win32' ? new KpscriptProvider(kpscript) : new PyKeePassProvider(kpscript);
}
