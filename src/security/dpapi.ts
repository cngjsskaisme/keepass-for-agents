// DPAPI session store — Windows ProtectedData (CurrentUser scope) encrypts the
// master key between CLI invocations. Plaintext never touches disk.
// Each session file: { db, expiresAt, payload(base64 dpapi) } — user-scoped crypto.

import { spawn } from 'node:child_process';
import { SESSION_DIR } from '../config/config.ts';
import { mkdirSync, readFileSync, writeFileSync, unlinkSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const PS_SCRIPT = (mode: 'enc' | 'dec') => `
$mode='${mode}'
Add-Type -AssemblyName System.Security
$data=[Console]::In.ReadToEnd()
if ($mode -eq 'enc') {
  $b=[Convert]::FromBase64String($data)
  $p=[Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser')
  [Console]::Out.Write([Convert]::ToBase64String($p))
} else {
  $b=[Convert]::FromBase64String($data)
  $p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser')
  [Console]::Out.Write([Convert]::ToBase64String($p))
}`;

function ps(mode: 'enc' | 'dec', data: string): Promise<string> {
  return new Promise((res, rej) => {
    // data travels via stdin — never argv (argv is visible to process lists)
    const c = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', PS_SCRIPT(mode)], { windowsHide: true });
    const input = mode === 'enc' ? Buffer.from(data, 'utf8').toString('base64') : data;
    let out = '', err = '';
    c.stdout.on('data', (d) => out += d);
    c.stderr.on('data', (d) => err += d);
    const timer = setTimeout(() => { c.kill(); rej(new Error('dpapi timeout')); }, 15000);
    c.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return rej(new Error(`dpapi ${mode} failed`));
      const output = out.trim();
      res(mode === 'enc' ? output : Buffer.from(output, 'base64').toString('utf8'));
    });
    c.stdin.write(input);
    c.stdin.end();
  });
}

// Non-Windows: no DPAPI — protect session payloads with AES-256-GCM under a
// random key stored user-only (chmod 600) next to the sessions. Not as strong
// as DPAPI (any process running as the user can read the key) but keeps
// plaintext off disk with equivalent access semantics.
const KEY_FILE = () => join(SESSION_DIR, '.session-key');
function localKey(): Buffer {
  mkdirSync(SESSION_DIR, { recursive: true });
  const f = KEY_FILE();
  if (existsSync(f)) return readFileSync(f);
  const k = randomBytes(32);
  writeFileSync(f, k, { mode: 0o600 });
  try { chmodSync(f, 0o600); } catch {}
  return k;
}

function localCrypt(mode: 'enc' | 'dec', data: string): Promise<string> {
  const k = localKey();
  if (mode === 'enc') {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', k, iv);
    const out = Buffer.concat([c.update(data, 'utf8'), c.final()]);
    return Promise.resolve(Buffer.concat([iv, c.getAuthTag(), out]).toString('base64'));
  }
  const raw = Buffer.from(data, 'base64');
  const d = createDecipheriv('aes-256-gcm', k, raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Promise.resolve(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'));
}

const protect = (mode: 'enc' | 'dec', data: string) =>
  process.platform === 'win32' ? ps(mode, data) : Promise.resolve().then(() => localCrypt(mode, data));

export interface Session {
  db: string;
  expiresAt: number;
  payload: string;
}

export function sessionFile(alias: string): string {
  return join(SESSION_DIR, `${alias}.session.json`);
}

export async function saveSession(alias: string, masterKey: string, timeoutSec: number): Promise<void> {
  mkdirSync(SESSION_DIR, { recursive: true });
  const payload = await protect('enc', masterKey);
  const s: Session = { db: alias, expiresAt: Date.now() + timeoutSec * 1000, payload };
  // mode 0600 on POSIX — the file holds an encrypted payload, but user-only
  // read is the documented expectation (same as .session-key).
  writeFileSync(sessionFile(alias), JSON.stringify(s), { encoding: 'utf8', mode: 0o600 });
}

export async function readSession(alias: string): Promise<string | null> {
  const f = sessionFile(alias);
  if (!existsSync(f)) return null;
  let s: Session;
  try { s = JSON.parse(readFileSync(f, 'utf8')); } catch { return null; }
  if (s.expiresAt < Date.now()) { try { unlinkSync(f); } catch {} return null; }
  try { return await protect('dec', s.payload); } catch { return null; }
}

export function sessionStatus(alias: string): 'UNLOCKED' | 'EXPIRED' | 'LOCKED' {
  const f = sessionFile(alias);
  if (!existsSync(f)) return 'LOCKED';
  try {
    const s: Session = JSON.parse(readFileSync(f, 'utf8'));
    // Same cleanup as readSession — an expired file never lingers on disk.
    if (s.expiresAt < Date.now()) { try { unlinkSync(f); } catch {} return 'EXPIRED'; }
    return 'UNLOCKED';
  } catch { return 'LOCKED'; }
}

export function clearSession(alias: string): void {
  try { unlinkSync(sessionFile(alias)); } catch {}
}

/** Generate a short-lived one-time token (unlock-request correlation). */
export function newToken(): string {
  return randomBytes(24).toString('base64url');
}
