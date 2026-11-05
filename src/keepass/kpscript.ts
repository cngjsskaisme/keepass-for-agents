// KPScript runner — safe argv-array spawn, stdin key delivery, output validation.
// Never uses shell:true; master keys go only through stdin, never argv/env.

import { spawn } from 'node:child_process';
import { basename } from 'node:path';
import { createRequire } from 'node:module';
// iconv-lite is only needed for CP949 on the Windows KPScript path — load
// lazily so non-Windows deployments don't require the package.
const _req = createRequire(import.meta.url);
let _iconv: any;
const iconv = () => (_iconv ??= _req('iconv-lite'));
import { fileExists } from '../config/config.ts';

export class KpsError extends Error {
  code: string;
  constructor(code: string, msg: string) { super(msg); this.code = code; }
}

export interface KpsResult {
  code: number;
  stdout: string;
  timedOut: boolean;
}

const MAX_OUT = 1 << 20; // 1MB cap — oversized output is anomalous

export function runKpscript(
  exe: string,
  args: string[],
  opts: { stdin?: string; timeoutMs?: number } = {},
): Promise<KpsResult> {
  return new Promise((resolve, reject) => {
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const isWindowsKpscript = process.platform === 'win32' && /^KPScript(?:\.exe)?$/i.test(basename(exe));
    let stdinPayload: string | Buffer | undefined = opts.stdin;
    if (opts.stdin != null && isWindowsKpscript) {
      const encoded = iconv().encode(opts.stdin, 'cp949');
      if (iconv().decode(encoded, 'cp949') !== opts.stdin) {
        throw new KpsError('UNSUPPORTED_SECRET_ENCODING', 'KPScript Windows key prompt cannot represent this password in CP949.');
      }
      stdinPayload = encoded;
    }
    const child = spawn(exe, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let out = Buffer.alloc(0), err = Buffer.alloc(0), done = false, timedOut = false;
    const decode = (buffer: Buffer) => isWindowsKpscript ? iconv().decode(buffer, 'cp949') : buffer.toString('utf8');
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.stdout.on('data', (d: Buffer) => { if (out.length + d.length < MAX_OUT) out = Buffer.concat([out, d]); });
    child.stderr.on('data', (d: Buffer) => { if (err.length + d.length < MAX_OUT) err = Buffer.concat([err, d]); });
    child.on('error', (e) => { clearTimeout(timer); if (!done) { done = true; reject(new KpsError('KPSCRIPT_SPAWN_FAILED', String(e))); } });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (done) return; done = true;
      const stderr = decode(err);
      // KPScript prints real errors on stderr as "E: <msg>" and exits 1
      if (timedOut) return reject(new KpsError('KPSCRIPT_TIMEOUT', `timeout after ${timeoutMs}ms`));
      if (code !== 0) {
        const msg = stderr.replace(/^E:\s*/m, '').trim() || `exit ${code}`;
        return reject(classifyError(code ?? 1, msg));
      }
      if (stderr.trim()) {
        // Warnings on stderr with exit 0 — keep stderr private, never log it
      }
      resolve({ code: code ?? 0, stdout: decode(out), timedOut: false });
    });
    if (stdinPayload != null) { child.stdin.write(stdinPayload); }
    child.stdin.end();
  });
}

function classifyError(code: number, msg: string): KpsError {
  const m = msg.toLowerCase();
  if (/composite key|invalid.*key|password.*incorrect/i.test(msg)) return new KpsError('AUTHENTICATION_FAILED', msg);
  if (/not found|does not exist|no entries/i.test(msg)) return new KpsError('ENTRY_NOT_FOUND', msg);
  return new KpsError('KPSCRIPT_FAILED', msg);
}

/**
 * Validate a password field output — KPScript GetEntryString prints just the value,
 * but diagnostics can leak into stdout. Reject anything looking like an error line
 * or exceeding sane password bounds. Never logs raw content.
 */
export function validateSecretOutput(raw: string): { ok: boolean; value?: string; reason?: string } {
  if (raw.length > 4096) return { ok: false, reason: 'output_too_large' };
  const firstNl = raw.indexOf('\n');
  // A password may itself contain anything, but KPScript prints exactly one line.
  // Multi-line output beyond a single trailing newline is anomalous.
  const trimmed = raw.replace(/\r?\n$/, '');
  if (/\r?\n/.test(trimmed)) return { ok: false, reason: 'multiline_output' };
  if (/^(E:|W:|OK:|error|warning)/i.test(trimmed)) return { ok: false, reason: 'diagnostic_in_stdout' };
  return { ok: true, value: trimmed };
}

/** Build DB-open args for a kdbx; key material comes via stdin, keyfile via argv (non-secret path). */
export function dbArgs(dbPath: string, keyFile?: string, guiKeyPrompt = false): string[] {
  const args = [dbPath];
  if (guiKeyPrompt) args.push('-guikeyprompt');
  else args.push('-keyprompt');
  if (keyFile) args.push(`-keyfile:${keyFile}`);
  return args;
}

/**
 * -keyprompt stdin format (verified against KPScript 2.61):
 *   line1: master password
 *   line2: key file path (empty if none / already given via -keyfile:)
 *   line3: 'y'/'n' — use Windows user account
 * When -keyfile: is passed as an arg, the keyfile line is skipped by the prompt.
 */
export function keyStdin(masterKey: string, hasKeyfileArg: boolean): string {
  // Defense in depth (T12): CR/LF would corrupt the -keyprompt line sequence.
  // Inputs are already rejected upstream (INVALID_SECRET_CHARS); a key that
  // still reaches here must fail closed rather than feed a broken prompt.
  if (/[\r\n]/.test(masterKey))
    throw new KpsError('INVALID_SECRET_CHARS', 'master key must not contain CR/LF');
  return masterKey + '\n' + (hasKeyfileArg ? '' : '\n') + 'n\n';
}

/**
 * True if `s` survives a CP949 encode→decode round-trip. On Windows the
 * KPScript stdout path decodes as CP949 — an entry password with
 * non-CP949 characters would come back corrupted (T12). Callers warn at
 * entry-add time.
 */
export function cp949RoundTrips(s: string): boolean {
  return iconv().decode(iconv().encode(s, 'cp949'), 'cp949') === s;
}

/** Ensure the KPScript exe is usable (exists; caller decides policy when missing). */
export function kpscriptAvailable(exe: string): boolean {
  return !!exe && fileExists(exe);
}
