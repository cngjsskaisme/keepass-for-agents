// Generic CDP client — minimal Chrome DevTools Protocol plumbing over a
// loopback endpoint using Node's built-in WebSocket. Flat protocol mode:
// every command/event carries an optional `sessionId` so one browser-level
// socket multiplexes all attached targets. No npm dependencies.
//
// Used by the playwright login worker (src/worker/playwright/) — kept in
// src/cdp so other consumers (cookie reader, future workers) share one
// implementation.

import { isLoopbackCdpEndpoint } from './cookies.ts';

/** Reply/event frames above this size are dropped, never parsed. */
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

export interface CdpConnection {
  /** Send a command; resolves with `result` or rejects on `error.message`. */
  call(method: string, params?: Record<string, unknown>, sessionId?: string): Promise<any>;
  /** Register an event listener: (method, params, sessionId?). */
  onEvent(listener: (method: string, params: any, sessionId?: string) => void): void;
  /** Resolve on the next event matching method (+sessionId when given). */
  waitEvent(method: string, sessionId: string | undefined, timeoutMs: number): Promise<any>;
  /** Close the socket and reject every in-flight call. */
  close(): void;
}

export interface CdpPage {
  conn: CdpConnection;
  sessionId: string;
  targetId: string;
  /** Isolated browser context owning the target (undefined if unsupported). */
  browserContextId?: string;
}

/**
 * Resolve the browser-level WebSocket URL for a CDP endpoint. The endpoint
 * must be loopback (same rule as the cookie path — a remote debug socket
 * would own both the browser and anything entered into it). The returned
 * ws:// URL itself is also checked: a hostile endpoint could otherwise
 * redirect the debug session off-host.
 */
export async function browserWebSocketUrl(endpoint: string, timeoutMs = 10_000): Promise<string> {
  if (!isLoopbackCdpEndpoint(endpoint)) throw new Error('CDP_ENDPOINT_REJECTED');
  const ep = endpoint.replace(/\/+$/, '');
  const r = await fetch(`${ep}/json/version`, { signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error('CDP_CONNECT_FAILED');
  const v = (await r.json()) as { webSocketDebuggerUrl?: string };
  const wsUrl = v.webSocketDebuggerUrl;
  if (!wsUrl || !/^wss?:\/\//i.test(wsUrl)) throw new Error('CDP_NO_WS');
  const host = new URL(wsUrl.replace(/^ws/i, 'http')).hostname
    .replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1')
    throw new Error('CDP_ENDPOINT_REJECTED');
  return wsUrl;
}

/**
 * Open the CDP WebSocket and return a connection handle. `opts.timeoutMs`
 * caps the handshake; `opts.callTimeoutMs` (default 30s) caps every command
 * — a browser that accepts a socket but never replies must not park a
 * worker holding vault credentials until the broker's tree-kill.
 */
export function connectCdp(
  wsUrl: string,
  opts: { timeoutMs?: number; callTimeoutMs?: number } = {},
): Promise<CdpConnection> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const callTimeoutMs = opts.callTimeoutMs ?? 30_000;
  return new Promise((resolve, reject) => {
    let ws: WebSocket;
    try { ws = new WebSocket(wsUrl); } catch { reject(new Error('CDP_CONNECT_FAILED')); return; }
    let id = 0;
    let settled = false;
    const pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
    const listeners: ((method: string, params: any, sessionId?: string) => void)[] = [];
    const failAll = (e: Error) => {
      for (const p of pending.values()) p.reject(e);
      pending.clear();
    };
    const timer = setTimeout(() => {
      if (settled) return;
      try { ws.close(); } catch {}
      reject(new Error('CDP_CONNECT_FAILED'));
    }, timeoutMs);
    ws.onerror = () => {
      if (!settled) { clearTimeout(timer); reject(new Error('CDP_CONNECT_FAILED')); }
      else failAll(new Error('CDP_CLOSED'));
    };
    ws.onclose = () => {
      if (!settled) { clearTimeout(timer); reject(new Error('CDP_CONNECT_FAILED')); }
      else failAll(new Error('CDP_CLOSED'));
    };
    ws.onmessage = (ev) => {
      const raw = typeof ev.data === 'string' ? ev.data : '';
      if (!raw || raw.length > MAX_MESSAGE_BYTES) return;
      let m: any;
      try { m = JSON.parse(raw); } catch { return; }
      if (m.id != null && pending.has(m.id)) {
        const p = pending.get(m.id)!;
        pending.delete(m.id);
        if (m.error) p.reject(new Error(String(m.error.message || 'CDP_ERROR').slice(0, 200)));
        else p.resolve(m.result);
      } else if (m.method) {
        for (const l of listeners) { try { l(m.method, m.params, m.sessionId); } catch {} }
      }
    };
    ws.onopen = () => {
      clearTimeout(timer);
      settled = true;
      resolve({
        call(method, params = {}, sessionId) {
          return new Promise((res, rej) => {
            const mid = ++id;
            const t = setTimeout(() => {
              if (pending.delete(mid)) rej(new Error('CDP_CALL_TIMEOUT'));
            }, callTimeoutMs);
            pending.set(mid, {
              resolve: (v) => { clearTimeout(t); res(v); },
              reject: (e) => { clearTimeout(t); rej(e); },
            });
            try {
              ws.send(JSON.stringify({ id: mid, method, params, ...(sessionId ? { sessionId } : {}) }));
            } catch (e) { clearTimeout(t); pending.delete(mid); rej(new Error('CDP_CLOSED')); }
          });
        },
        onEvent(l) { listeners.push(l); },
        waitEvent(method, sessionId, ms) {
          return new Promise((res, rej) => {
            const l = (m: string, p: any, s?: string) => {
              if (m !== method) return;
              if (sessionId && s !== sessionId) return;
              clearTimeout(t);
              const i = listeners.indexOf(l);
              if (i >= 0) listeners.splice(i, 1);
              res(p);
            };
            const t = setTimeout(() => {
              const i = listeners.indexOf(l);
              if (i >= 0) listeners.splice(i, 1);
              rej(new Error('CDP_EVENT_TIMEOUT'));
            }, ms);
            listeners.push(l);
          });
        },
        close() {
          failAll(new Error('CDP_CLOSED'));
          try { ws.close(); } catch {}
        },
      });
    };
  });
}

/**
 * Open a page in an ISOLATED browser context (the CDP equivalent of an
 * incognito window): a fresh cookie jar and storage partition, so the login
 * never mixes with the user's existing sessions. If `isolated` is false the
 * default context is used — only for CDP instances that are already a
 * dedicated profile (their default context is the isolated store, and its
 * cookies remain harvestable via `entry sync-cookies`).
 *
 * Fail-closed: when the browser cannot create an isolated context the call
 * throws rather than silently falling back to the user's default profile.
 */
export async function openCdpPage(
  endpoint: string,
  opts: { timeoutMs?: number; isolated?: boolean } = {},
): Promise<CdpPage> {
  const isolated = opts.isolated !== false;
  const conn = await connectCdp(await browserWebSocketUrl(endpoint, opts.timeoutMs), opts);
  let browserContextId: string | undefined;
  try {
    if (isolated) {
      try {
        const r = await conn.call('Target.createBrowserContext', { disposeOnDetach: false });
        browserContextId = r?.browserContextId;
      } catch { /* older Chromium — no param/unknown method */ }
      if (!browserContextId) {
        try {
          const r = await conn.call('Target.createBrowserContext', {});
          browserContextId = r?.browserContextId;
        } catch { /* fall through to fail-closed */ }
      }
      if (!browserContextId) throw new Error('CDP_NO_ISOLATED_CONTEXT');
    }
    const t = await conn.call('Target.createTarget', {
      url: 'about:blank', ...(browserContextId ? { browserContextId } : {}),
    });
    const a = await conn.call('Target.attachToTarget', { targetId: t.targetId, flatten: true });
    if (!a?.sessionId) throw new Error('CDP_ATTACH_FAILED');
    return { conn, sessionId: a.sessionId, targetId: t.targetId, browserContextId };
  } catch (e) {
    // Partial open — never leak a live isolated context behind a dead socket.
    if (browserContextId) {
      try { await conn.call('Target.disposeBrowserContext', { browserContextId }); } catch {}
    }
    conn.close();
    throw e;
  }
}

/** Best-effort teardown: close the tab, dispose the isolated context, drop the socket. */
export async function closeCdpPage(page: CdpPage): Promise<void> {
  try { await page.conn.call('Target.closeTarget', { targetId: page.targetId }); } catch {}
  if (page.browserContextId) {
    try { await page.conn.call('Target.disposeBrowserContext', { browserContextId: page.browserContextId }); } catch {}
  }
  page.conn.close();
}
