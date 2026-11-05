// PyKeePass provider — POSIX backend for every CredentialProvider operation,
// and the write backend (createDb/addEntry/updateEntryFields) on all platforms
// (KpscriptProvider inherits those). Drives the src/keepass/*.py helpers:
// secrets go over stdin only, status/metadata comes back as stdout JSON, and
// helper stderr is discarded entirely — it must never become a secret channel.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileExists } from '../config/config.ts';
import type { DbConfig } from '../config/config.ts';
import type { CredentialProvider, Entry, NewEntry, ProviderResult } from './provider.ts';
import { kpscriptParts } from './provider.ts';

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const VENV_PY = process.platform === 'win32'
  ? join(APP_DIR, '.venv', 'Scripts', 'python.exe')
  : join(APP_DIR, '.venv', 'bin', 'python');
const PYTHON = existsSync(VENV_PY) ? VENV_PY : 'python3';
const KDBX_CREATOR = join(APP_DIR, 'src', 'keepass', 'create_kdbx.py');
const ENTRY_ADDER = join(APP_DIR, 'src', 'keepass', 'add_entry.py');
const ENTRY_UPDATER = join(APP_DIR, 'src', 'keepass', 'update_entry.py');
const KDBX_HELPER = join(APP_DIR, 'src', 'keepass', 'kdbx_helper.py');

/**
 * Helper command resolution — default is the bundled Python helper. Tests/CI
 * may set KEEPASS_AGENT_HELPER_CMD to a JSON argv array (e.g.
 * ["node","tests/fixtures/mock-helper.mjs"]) or a bare executable path that
 * speaks the same stdin-JSON → stdout-JSON protocol. Production callers never
 * set it; behavior is identical when unset.
 */
let helperOverrideWarned = false;
function helperCmd(): { exe: string; args: string[] } | null {
  const raw = process.env.KEEPASS_AGENT_HELPER_CMD;
  if (raw) {
    // Warn once (no env value, no secrets) — this hook hands the master key to
    // an arbitrary process via stdin and must never fire silently in real use.
    if (!helperOverrideWarned) {
      helperOverrideWarned = true;
      process.stderr.write('kp: warning: KEEPASS_AGENT_HELPER_CMD override active — helper receives master key via stdin\n');
    }
    try {
      const a = JSON.parse(raw);
      if (Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === 'string'))
        return { exe: a[0], args: a.slice(1) };
    } catch { /* not JSON — treat as a bare executable path */ }
    return { exe: raw, args: [] };
  }
  if (!existsSync(KDBX_HELPER)) return null;
  return { exe: PYTHON, args: [KDBX_HELPER] };
}

/** Shared stdin/stdout runner for kdbx_helper.py — secrets via stdin only. */
function runKdbxHelper(db: DbConfig, masterKey: string, extra: Record<string, unknown>): Promise<any> {
  return new Promise((resolve) => {
    const cmd = helperCmd();
    if (!cmd) return resolve({ ok: false, code: 'PYTHON_HELPER_NOT_READY' });
    const child = spawn(cmd.exe, cmd.args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let out = Buffer.alloc(0), done = false;
    const timer = setTimeout(() => {
      child.kill();
      if (!done) { done = true; resolve({ ok: false, code: 'HELPER_TIMEOUT' }); }
    }, 60_000);
    child.stdout.on('data', (d: Buffer) => { if (out.length < 4 * 1024 * 1024) out = Buffer.concat([out, d]); });
    child.stderr.on('data', () => {});
    child.on('error', () => { clearTimeout(timer); if (!done) { done = true; resolve({ ok: false, code: 'PYTHON_HELPER_SPAWN_FAILED' }); } });
    child.on('close', () => {
      clearTimeout(timer);
      if (done) return;
      done = true;
      try { resolve(JSON.parse(out.toString('utf8'))); } catch { resolve({ ok: false, code: 'HELPER_FAILED' }); }
    });
    child.stdin.write(JSON.stringify({ path: db.path, keyFile: db.key_file || null, master: masterKey, ...extra }));
    child.stdin.end();
  });
}

export class PyKeePassProvider implements CredentialProvider {
  readonly kind: 'kpscript' | 'pykeepass' = 'pykeepass';
  /**
   * The configured KPScript path — unused by the read/write helpers, but
   * createDb keeps the historical contract that a valid keepass.kpscript is
   * required before a KDBX may be created (INVALID_CONFIG otherwise).
   */
  protected readonly kpscriptExe: string;

  constructor(kpscript: string | string[] = '') {
    this.kpscriptExe = kpscriptParts(kpscript).exe;
  }

  /** Linux/macOS equivalent of KPScript verify — open the KDBX with the key. */
  async verifyKey(db: DbConfig, masterKey: string): Promise<ProviderResult> {
    const r = await runKdbxHelper(db, masterKey, { cmd: 'verify' });
    return r.ok === true ? { ok: true } : { ok: false, code: 'INVALID_MASTER_KEY' };
  }

  /** Linux/macOS equivalent of KPScript ListEntries. */
  async listEntries(db: DbConfig, masterKey: string): Promise<ProviderResult<{ entries: Entry[] }>> {
    const r = await runKdbxHelper(db, masterKey, { cmd: 'list' });
    if (r.ok === true) return { ok: true, entries: r.entries || [] };
    return { ok: false, code: r.code || 'HELPER_FAILED' };
  }

  /** Fetch one field (default password) from an entry — for worker stdin piping. */
  async getSecret(db: DbConfig, masterKey: string, uuid: string, field = 'password'): Promise<ProviderResult<{ secret: string }>> {
    const r = await runKdbxHelper(db, masterKey, { cmd: 'get', uuid, field });
    if (r.ok === true) return { ok: true, secret: r.secret };
    return { ok: false, code: r.code || 'HELPER_FAILED' };
  }

  /** Create a KDBX using the local PyKeePass helper; the key payload goes over stdin only. */
  createDb(path: string, masterKey: string, keyFile?: string): Promise<ProviderResult> {
    const kpscript = this.kpscriptExe;
    return new Promise((resolve) => {
      if (!kpscript || !fileExists(kpscript)) return resolve({ ok: false, code: 'INVALID_CONFIG' });
      if (!existsSync(PYTHON) || !existsSync(KDBX_CREATOR)) return resolve({ ok: false, code: 'PYTHON_HELPER_NOT_READY' });
      if (existsSync(path)) return resolve({ ok: false, code: 'DATABASE_ALREADY_EXISTS' });
      const child = spawn(PYTHON, [KDBX_CREATOR], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let out = Buffer.alloc(0), done = false;
      const timer = setTimeout(() => {
        child.kill();
        if (!done) { done = true; resolve({ ok: false, code: 'KDBX_CREATE_TIMEOUT' }); }
      }, 60_000);
      child.stdout.on('data', (d: Buffer) => { if (out.length < 8192) out = Buffer.concat([out, d]); });
      // Never capture or forward helper stderr; it must not become a secret log channel.
      child.stderr.on('data', () => {});
      child.on('error', () => {
        clearTimeout(timer);
        if (!done) { done = true; resolve({ ok: false, code: 'PYTHON_HELPER_SPAWN_FAILED' }); }
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (done) return;
        done = true;
        try {
          const result = JSON.parse(out.toString('utf8'));
          if (code === 0 && result.success === true && existsSync(path)) return resolve({ ok: true });
          return resolve({ ok: false, code: result.code || 'KDBX_CREATE_FAILED' });
        } catch {
          return resolve({ ok: false, code: 'KDBX_CREATE_FAILED' });
        }
      });
      child.stdin.write(JSON.stringify({ path, keyFile: keyFile || null, kpscript, password: masterKey }));
      child.stdin.end();
    });
  }

  /** Add an entry via the local PyKeePass helper; master key and fields go over stdin only. */
  addEntry(db: DbConfig, masterKey: string, entry: NewEntry): Promise<ProviderResult<{ uuid?: string }>> {
    return new Promise((resolve) => {
      if (!existsSync(PYTHON) || !existsSync(ENTRY_ADDER)) return resolve({ ok: false, code: 'PYTHON_HELPER_NOT_READY' });
      const child = spawn(PYTHON, [ENTRY_ADDER], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let out = Buffer.alloc(0), done = false;
      const timer = setTimeout(() => {
        child.kill();
        if (!done) { done = true; resolve({ ok: false, code: 'ENTRY_ADD_TIMEOUT' }); }
      }, 60_000);
      child.stdout.on('data', (d: Buffer) => { if (out.length < 8192) out = Buffer.concat([out, d]); });
      // Never capture or forward helper stderr; it must not become a secret log channel.
      child.stderr.on('data', () => {});
      child.on('error', () => {
        clearTimeout(timer);
        if (!done) { done = true; resolve({ ok: false, code: 'PYTHON_HELPER_SPAWN_FAILED' }); }
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (done) return;
        done = true;
        try {
          const result = JSON.parse(out.toString('utf8'));
          if (code === 0 && result.success === true) return resolve({ ok: true, uuid: result.uuid });
          return resolve({ ok: false, code: result.code || 'ENTRY_ADD_FAILED' });
        } catch {
          return resolve({ ok: false, code: 'ENTRY_ADD_FAILED' });
        }
      });
      child.stdin.write(JSON.stringify({
        path: db.path, keyFile: db.key_file || null, master: masterKey,
        title: entry.title, username: entry.username || '', password: entry.password,
        url: entry.url || '', notes: entry.notes || '',
      }));
      child.stdin.end();
    });
  }

  /** Set custom string fields on an existing entry (uuid without dashes, KPScript form). */
  updateEntryFields(db: DbConfig, masterKey: string, uuid: string, fields: Record<string, string>): Promise<ProviderResult> {
    return new Promise((resolve) => {
      if (!existsSync(PYTHON) || !existsSync(ENTRY_UPDATER)) return resolve({ ok: false, code: 'PYTHON_HELPER_NOT_READY' });
      const child = spawn(PYTHON, [ENTRY_UPDATER], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let out = Buffer.alloc(0), done = false;
      const timer = setTimeout(() => {
        child.kill();
        if (!done) { done = true; resolve({ ok: false, code: 'ENTRY_UPDATE_TIMEOUT' }); }
      }, 60_000);
      child.stdout.on('data', (d: Buffer) => { if (out.length < 8192) out = Buffer.concat([out, d]); });
      // Never capture or forward helper stderr; it must not become a secret log channel.
      child.stderr.on('data', () => {});
      child.on('error', () => {
        clearTimeout(timer);
        if (!done) { done = true; resolve({ ok: false, code: 'PYTHON_HELPER_SPAWN_FAILED' }); }
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (done) return;
        done = true;
        try {
          const result = JSON.parse(out.toString('utf8'));
          if (code === 0 && result.success === true) return resolve({ ok: true });
          return resolve({ ok: false, code: result.code || 'ENTRY_UPDATE_FAILED' });
        } catch {
          return resolve({ ok: false, code: 'ENTRY_UPDATE_FAILED' });
        }
      });
      child.stdin.write(JSON.stringify({
        path: db.path, keyFile: db.key_file || null, master: masterKey, uuid, fields,
      }));
      child.stdin.end();
    });
  }
}
