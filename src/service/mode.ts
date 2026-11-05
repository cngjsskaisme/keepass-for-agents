// Hardened Mode — mode resolution and endpoint/token path derivation.
//
// Hardened Mode runs all credential-touching work (master-key verification,
// session custody, KDBX access, worker spawn) inside a separate OS principal
// — the Credential Service. The kp CLI becomes a thin IPC client for those
// operations. This module is pure resolution logic shared by the client side
// (kp.ts) and the service daemon (service.ts); nothing here grants or denies
// anything by itself.

import { join, dirname, isAbsolute } from 'node:path';
import { CONFIG_DIR, type AppConfig } from '../config/config.ts';

/** Default named pipe name on Windows (the `\\.\pipe\` prefix is implied). */
export const DEFAULT_PIPE_NAME = 'keepass-agent-svc';
/** Default unix-socket path component (resolved under the service state dir). */
export const DEFAULT_SOCK_NAME = 'svc.sock';
export const DEFAULT_TOKEN_NAME = 'ipc-token';

/** Service state dir — sessions/socket/token live under it on the service account. */
export function serviceStateDir(cfg?: AppConfig): string {
  return cfg?.hardened.state_dir || join(CONFIG_DIR, 'service');
}

/**
 * IPC endpoint the client dials / the service binds.
 *   win32 → `\\.\pipe\<name>` (name from cfg.hardened.endpoint or default)
 *   posix → absolute socket path (cfg.hardened.endpoint or <state_dir>/svc.sock)
 */
export function resolveEndpoint(cfg: AppConfig): string {
  const ep = cfg.hardened.endpoint;
  if (process.platform === 'win32') return `\\\\.\\pipe\\${ep || DEFAULT_PIPE_NAME}`;
  if (ep) return ep;
  return join(serviceStateDir(cfg), DEFAULT_SOCK_NAME);
}

/**
 * Capability token file — the IPC authentication anchor. Any principal that
 * can read this file can authenticate to the service, so its filesystem ACL
 * IS the caller authorization boundary (see docs/security.md).
 */
export function resolveTokenFile(cfg: AppConfig): string {
  if (cfg.hardened.token_file) return cfg.hardened.token_file;
  if (process.platform === 'win32') return join(serviceStateDir(cfg), DEFAULT_TOKEN_NAME);
  return join(dirname(resolveEndpoint(cfg)), DEFAULT_TOKEN_NAME);
}

export function hardenedEnabled(cfg: AppConfig): boolean {
  return cfg.hardened.enabled === true;
}

export const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;

export function connectTimeoutMs(cfg: AppConfig): number {
  return cfg.hardened.connect_timeout_ms ?? DEFAULT_CONNECT_TIMEOUT_MS;
}
