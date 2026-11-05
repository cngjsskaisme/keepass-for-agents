// Hardened IPC client — the kp CLI's only path into the Credential Service.
//
// Every call: load capability token → connect → HMAC handshake → request →
// interim frames (approval URLs) → final response. Failures are mapped to
// explicit HARDENED_* codes; callers must surface them, never fall back.

import { connect, type Socket } from 'node:net';
import { encode, isRequest, LineDecoder, LONG_RUNNING_OPS, HARDENED_CODES } from './protocol.ts';
import { readTokenFile } from './auth.ts';
import { hmacToken } from './auth.ts';
import { resolveEndpoint, resolveTokenFile, connectTimeoutMs } from './mode.ts';
import type { AppConfig } from '../config/config.ts';

export interface IpcResponse {
  ok: boolean;
  code?: string;
  detail?: string;
  [k: string]: any;
}

export interface CallOpts {
  /** Long-poll ops (approvals) get no response cap by default. */
  timeoutMs?: number;
  /** Interim frames (e.g. {url} while an approval is pending). */
  onInterim?: (m: Record<string, any>) => void;
}

let nextId = 1;

/**
 * One request against the service. Resolves with the service's own result
 * object ({ok:true,...} or {ok:false,code,...}); transport/auth failures are
 * returned as {ok:false, code:HARDENED_*} — callers handle them identically
 * to service-level denials, fail-closed by construction.
 */
export function callService(cfg: AppConfig, op: string, params: Record<string, any> = {}, opts: CallOpts = {}): Promise<IpcResponse> {
  const endpoint = resolveEndpoint(cfg);
  const tokenPath = resolveTokenFile(cfg);
  return new Promise((resolve) => {
    const token = readTokenFile(tokenPath);
    if (token == null) return resolve({ ok: false, code: HARDENED_CODES.TOKEN_UNAVAILABLE, detail: 'ipc token file missing/unreadable' });

    const timeoutMs = opts.timeoutMs ?? (LONG_RUNNING_OPS.has(op) ? 0 : connectTimeoutMs(cfg));
    const socket: Socket = connect(endpoint);
    const decoder = new LineDecoder();
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (r: IpcResponse) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      try { socket.destroy(); } catch {}
      resolve(r);
    };
    if (timeoutMs > 0)
      timer = setTimeout(() => finish({ ok: false, code: HARDENED_CODES.TIMEOUT }), timeoutMs);

    let authed = false;
    let id = -1;

    socket.on('connect', () => {});
    socket.on('error', () => finish({ ok: false, code: authed ? HARDENED_CODES.IPC_ERROR : HARDENED_CODES.SERVICE_UNAVAILABLE }));
    socket.on('close', () => finish({ ok: false, code: authed ? HARDENED_CODES.IPC_ERROR : HARDENED_CODES.SERVICE_UNAVAILABLE }));
    socket.on('data', (chunk) => {
      // Check BEFORE iterating — an oversized buffer yields zero messages,
      // so an in-loop check would never fire (same fix as the server, F4).
      const msgs = decoder.feed(chunk);
      if (decoder.overflow()) return finish({ ok: false, code: HARDENED_CODES.IPC_ERROR, detail: 'overflow' });
      for (const m of msgs) {
        if (!authed) {
          if (m?.t === 'challenge' && typeof m.nonce === 'string') {
            try { socket.write(encode({ t: 'auth', hmac: hmacToken(token, m.nonce) })); } catch {}
          } else if (m?.t === 'ready') {
            authed = true;
            id = nextId++;
            try { socket.write(encode({ t: 'req', id, op, ...params })); } catch {}
          } else if (m?.t === 'denied') {
            return finish({ ok: false, code: m.code || HARDENED_CODES.AUTH_FAILED, detail: m.detail });
          }
          continue;
        }
        if (m?.t === 'interim' && m.id === id) { opts.onInterim?.(m); continue; }
        if (m?.t === 'res' && m.id === id) {
          const { t, id: _id, ...rest } = m;
          return finish(rest as IpcResponse);
        }
      }
    });
  });
}

/**
 * Cheap liveness probe for `kp status` — performs a full handshake + hello.
 * Returns service info on success or {down:true, code} on any failure.
 */
export async function probeService(cfg: AppConfig): Promise<{ down: boolean; code?: string; info?: Record<string, any> }> {
  const r = await callService(cfg, 'hello', {}, { timeoutMs: connectTimeoutMs(cfg) });
  if (!r.ok) return { down: true, code: r.code };
  const { ok, ...info } = r;
  return { down: false, info };
}
