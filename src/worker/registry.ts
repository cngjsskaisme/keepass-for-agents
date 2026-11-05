// Worker registry — allowlist of approved login workers.
// Agents cannot point at arbitrary executables; workers resolve to fixed
// scripts inside this package's worker/ directory only.

import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

const __dir = dirname(fileURLToPath(import.meta.url));
const WORKER_DIR = __dir; // src/worker — worker scripts live here

interface WorkerDef {
  file: string;
  /** Per-worker run cap; broker defaults to 60s when omitted. */
  timeoutMs?: number;
}

const ALLOWED: Record<string, WorkerDef> = {
  'local-test': { file: join(WORKER_DIR, 'local-test.mjs'), timeoutMs: 30_000 },
  'playwright': { file: join(WORKER_DIR, 'playwright', 'browser-login.mjs'), timeoutMs: 120_000 },
};

export function resolveWorker(name: string): { ok: boolean; cmd?: string[]; timeoutMs?: number; code?: string } {
  const def = ALLOWED[name];
  if (!def || !existsSync(def.file)) return { ok: false, code: 'UNSUPPORTED_WORKER' };
  return { ok: true, cmd: [process.execPath, def.file], timeoutMs: def.timeoutMs };
}

export function workerNames(): string[] {
  return Object.keys(ALLOWED).filter((n) => existsSync(ALLOWED[n].file));
}
