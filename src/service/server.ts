// Credential Service — IPC listener: unix socket (POSIX) or named pipe
// (Windows), capability-token HMAC handshake, request dispatch.
//
// Connection lifecycle:
//   accept → challenge(nonce) → client hmac(token,nonce) → ready/denied
//   → req/interim/res frames until close.
// Handshake timeout (10s), one request per connection at a time is NOT
// required — requests carry ids and may interleave; handlers are async.

import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, unlinkSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';
import { encode, isRequest, LineDecoder, PROTOCOL_VERSION } from './protocol.ts';
import { newNonce, verifyHmac } from './auth.ts';
import { peerIdentity, peerVerifyDecision } from './peer.ts';
import { handleRequest, type ServiceContext } from './handlers.ts';
import type { AppConfig } from '../config/config.ts';

const HANDSHAKE_TIMEOUT_MS = 10_000;

export interface ServiceServer {
  server: Server;
  endpoint: string;
  close(): Promise<void>;
}

/**
 * Bind the IPC endpoint and serve requests.
 *   endpoint: POSIX → absolute unix-socket path; win32 → `\\.\pipe\<name>`.
 *   token:    capability token the HMAC handshake verifies against.
 */
export function startServiceServer(opts: {
  endpoint: string;
  token: string;
  cfg: AppConfig;
  ctx: Omit<ServiceContext, 'cfg'>;
  onError?: (e: Error) => void;
}): Promise<ServiceServer> {
  const { endpoint, token, cfg } = opts;
  const ctx: ServiceContext = { cfg, ...opts.ctx };
  const isPipe = process.platform === 'win32';

  if (!isPipe) {
    mkdirSync(dirname(endpoint), { recursive: true });
    // Stale socket files block bind — remove only a leftover (we own this dir).
    try { if (existsSync(endpoint)) unlinkSync(endpoint); } catch {}
  }

  const server = createServer((socket: Socket) => {
    socket.setNoDelay?.(true);
    let authed = false;
    let nonce = '';
    const decoder = new LineDecoder();
    const write = (m: Record<string, any>) => { try { socket.write(encode(m)); } catch {} };
    const kill = () => { try { socket.destroy(); } catch {} };
    // Deny + graceful close: socket.end flushes the frame before FIN — a bare
    // write() followed by destroy() can drop the denial on the floor.
    const deny = (code: string, detail?: string) => {
      try { socket.end(encode(detail ? { t: 'denied', code, detail } : { t: 'denied', code })); }
      catch { kill(); }
    };

    const handshakeTimer = setTimeout(kill, HANDSHAKE_TIMEOUT_MS);

    // Challenge first — the nonce binds the HMAC to this connection.
    nonce = newNonce();
    write({ t: 'challenge', nonce, v: PROTOCOL_VERSION });

    socket.on('data', async (chunk) => {
      // Overflow check BEFORE iterating: an oversized buffer yields no
      // messages at all, so checking inside the loop would never fire (F4).
      // The cap applies pre- and post-auth alike.
      const msgs = decoder.feed(chunk);
      if (decoder.overflow()) return deny('HARDENED_IPC_ERROR', 'message_cap_exceeded');
      for (const m of msgs) {
        if (!authed) {
          if (m?.t !== 'auth' || !verifyHmac(token, nonce, m.hmac)) {
            return deny('HARDENED_AUTH_FAILED');
          }
          // Optional POSIX peer-credential layer (strict tier can reject here).
          const id = peerIdentity(socket);
          const pv = peerVerifyDecision(cfg.hardened.peer_verify, id, cfg.hardened.allowed_uids);
          if (pv.reject) {
            return deny('HARDENED_AUTH_FAILED', pv.reason);
          }
          authed = true;
          clearTimeout(handshakeTimer);
          write({
            t: 'ready', v: PROTOCOL_VERSION, service: 'kp-credential-service',
            pid: process.pid,
            peer: id.ok ? { uid: id.uid, pid: id.pid, mechanism: id.mechanism } : { mechanism: id.mechanism },
          });
          continue;
        }
        if (!isRequest(m)) {
          // Echo the request id when present so the caller can correlate the
          // rejection; unknown ops never reach dispatch.
          const rid = Number.isInteger(m?.id) && m.id >= 0 ? m.id : -1;
          write({ t: 'res', id: rid, ok: false, code: 'HARDENED_IPC_ERROR' });
          continue;
        }
        const id = m.id;
        const sendInterim = (im: Record<string, any>) => write({ t: 'interim', id, ...im });
        try {
          const res = await handleRequest(m, ctx, sendInterim);
          write({ t: 'res', id, ...res });
        } catch {
          write({ t: 'res', id, ok: false, code: 'INTERNAL_ERROR' });
        }
      }
    });
    socket.on('error', () => {});
  });

  return new Promise((resolve, reject) => {
    server.on('error', (e) => { opts.onError?.(e); reject(e); });
    server.listen(endpoint, () => {
      if (!isPipe) {
        // Connect permission on Linux is governed by the socket file's
        // write bit — 0660 keeps 'other' out; the group (provisioning's
        // agent group) retains access. This is the kernel-enforced caller
        // restriction; the token handshake is the second layer.
        try { chmodSync(endpoint, 0o660); } catch {}
      }
      resolve({
        server,
        endpoint,
        close: () => new Promise<void>((r) => {
          try { server.close(() => r()); } catch { r(); }
        }),
      });
    });
  });
}
