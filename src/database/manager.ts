// Database Manager — KDBX registry lifecycle (config bookkeeping only).
// Registration ≠ creation: `add` registers an existing file, `create` makes one.
// All KDBX file/credential operations live behind src/provider/ — this module
// never touches master keys or the KDBX backends.

import type { AppConfig, DbConfig } from '../config/config.ts';
import { fileExists } from '../config/config.ts';
import { clearSession } from '../security/dpapi.ts';

export function listDbs(cfg: AppConfig): { alias: string; db: DbConfig; exists: boolean; default: boolean }[] {
  return Object.entries(cfg.databases).map(([alias, db]) => ({
    alias, db, exists: fileExists(db.path), default: cfg.keepass.default_database === alias,
  }));
}

export function getDb(cfg: AppConfig, alias?: string): { ok: boolean; alias?: string; db?: DbConfig; code?: string } {
  const a = alias || cfg.keepass.default_database;
  if (!a) return { ok: false, code: 'DATABASE_NOT_FOUND' };
  const db = cfg.databases[a];
  if (!db) return { ok: false, code: 'DATABASE_NOT_FOUND' };
  if (!fileExists(db.path)) return { ok: false, code: 'DATABASE_NOT_FOUND', alias: a };
  if (db.key_file && !fileExists(db.key_file)) return { ok: false, code: 'KEYFILE_NOT_FOUND', alias: a };
  return { ok: true, alias: a, db };
}

export function addDb(cfg: AppConfig, alias: string, db: DbConfig): { ok: boolean; code?: string } {
  if (!/^[a-z0-9_-]+$/i.test(alias)) return { ok: false, code: 'INVALID_CONFIG' };
  if (!db.path) return { ok: false, code: 'INVALID_CONFIG' };
  // Register may reference a file that doesn't exist yet (create comes separately),
  // but warn-level: allow it for `db create` workflows.
  cfg.databases[alias] = db;
  if (!cfg.keepass.default_database) cfg.keepass.default_database = alias;
  return { ok: true };
}

export function removeDb(cfg: AppConfig, alias: string): { ok: boolean; code?: string } {
  if (!cfg.databases[alias]) return { ok: false, code: 'DATABASE_NOT_FOUND' };
  delete cfg.databases[alias];
  if (cfg.keepass.default_database === alias) cfg.keepass.default_database = Object.keys(cfg.databases)[0] ?? '';
  clearSession(alias); // drop any credential session for a deregistered DB
  return { ok: true };
}

export function setDefault(cfg: AppConfig, alias: string): { ok: boolean; code?: string } {
  if (!cfg.databases[alias]) return { ok: false, code: 'DATABASE_NOT_FOUND' };
  cfg.keepass.default_database = alias;
  return { ok: true };
}
