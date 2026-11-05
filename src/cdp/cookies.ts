// Minimal CDP cookie reader — connects to a Chrome remote-debugging endpoint
// and returns the browser's cookie jar. No dependencies beyond Node's WebSocket.

export interface CdpCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  expires?: number;
  sameSite?: string;
}

/** Only loopback CDP endpoints are ever trusted — anything else can mint cookies (T11). */
export const DEFAULT_CDP_ENDPOINT = 'http://127.0.0.1:9222';

/**
 * CDP endpoint policy: http(s) on 127.0.0.1 / localhost / [::1] only, any
 * port. A browser-debug socket has total authority over the cookie jar — a
 * remote or attacker-controlled endpoint could both harvest and inject
 * cookies, so non-loopback values are rejected outright.
 */
export function isLoopbackCdpEndpoint(endpoint: string): boolean {
  try {
    const u = new URL(endpoint);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const h = u.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
    return h === '127.0.0.1' || h === 'localhost' || h === '::1';
  } catch { return false; }
}

export async function getBrowserCookies(
  endpoint = DEFAULT_CDP_ENDPOINT, timeoutMs = 10_000,
): Promise<CdpCookie[]> {
  const v = (await fetch(`${endpoint}/json/version`).then((r) => r.json())) as { webSocketDebuggerUrl?: string };
  const wsUrl = v.webSocketDebuggerUrl;
  if (!wsUrl) throw new Error('CDP_NO_WS');
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timer = setTimeout(() => { try { ws.close(); } catch {} reject(new Error('CDP_TIMEOUT')); }, timeoutMs);
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Storage.getCookies', params: {} }));
    ws.onmessage = (ev) => {
      const m = JSON.parse(String(ev.data));
      if (m.id === 1) { clearTimeout(timer); ws.close(); resolve(m.result?.cookies || []); }
    };
    ws.onerror = () => { clearTimeout(timer); reject(new Error('CDP_CONNECT_FAILED')); };
  });
}

/** Open a URL in a new CDP tab (Chrome requires PUT for /json/new). */
export async function openPage(endpoint: string, url: string): Promise<boolean> {
  try {
    const r = await fetch(`${endpoint}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
    return r.ok;
  } catch { return false; }
}

/**
 * cookie.domain matches host when the two are identical or one is a
 * dot-boundary parent/sub domain of the other — `github.com` ↔
 * `www.github.com`/`sub.github.com`. Suffix lookalikes never match:
 * `mygithub.com` ≠ `github.com`, `github.com.evil.net` ≠ `github.com`.
 */
export function domainMatch(cookieDomain: string, host: string): boolean {
  const d = cookieDomain.replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase();
  const h = host.replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase();
  if (!d || !h) return false;
  return d === h || h.endsWith('.' + d) || d.endsWith('.' + h);
}
