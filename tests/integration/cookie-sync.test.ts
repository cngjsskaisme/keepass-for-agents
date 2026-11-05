// Cookie-sync approval-flow tests (T7/T11) — cookies-mode requests to the
// unlock server must collect browser cookies ONLY after explicit web
// approval, against a loopback-only CDP endpoint. A fake CDP server (raw
// WebSocket) counts every Storage.getCookies call.
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest, createServer as createHttpServer, type Server } from 'node:http';
import { createHash, createCipheriv, createPublicKey, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requestCookieSync, waitForUnlock, type UnlockRequest, type UnlockResult } from '../../src/unlock-server/server.ts';
import { normalize, saveConfig, SESSION_DIR, type DbConfig } from '../../src/config/config.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

// POSIX verify path goes through the PyKeePass helper protocol.
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

const DB: DbConfig = { path: 'C:/fake/test.kdbx', session_timeout: 900 };
const DBS: Record<string, DbConfig> = { testdb: DB };
const KS: string[] = [process.execPath, join(TEST_HOME, 'noop-kpscript.mjs')];

{
  const c = normalize({});
  c.databases = { ...DBS };
  c.keepass.default_database = 'testdb';
  saveConfig(c);
}

// --- fake CDP server: /json/version + minimal WebSocket (Storage.getCookies) ---
const CDP_COOKIES = [
  { name: 'sess', value: 'abc', domain: '.github.com', path: '/', secure: true, httpOnly: true },
  { name: 'tracker', value: 'zzz', domain: 'evil.net', path: '/', secure: false, httpOnly: false },
];
let cdpCookieCalls = 0;
const cdp: Server = createHttpServer((req, res) => {
  if (req.url === '/json/version') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ webSocketDebuggerUrl: `ws://127.0.0.1:${cdpPort}/ws` }));
    return;
  }
  res.writeHead(404); res.end();
});
let cdpPort = 0;

function parseWsFrame(buf: Buffer): { opcode: number; payload: Buffer; consumed: number } | null {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f, off = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buf.length < 10) return null; len = Number(buf.readBigUInt64BE(2)); off = 10; }
  const maskOff = off;
  if (masked) off += 4;
  if (buf.length < off + len) return null;
  let payload = buf.subarray(off, off + len);
  if (masked) {
    const m = buf.subarray(maskOff, maskOff + 4);
    payload = Buffer.from(payload.map((b, i) => b ^ m[i % 4]));
  }
  return { opcode, payload, consumed: off + len };
}

function sendWsText(sock: any, text: string) {
  const p = Buffer.from(text);
  let header: Buffer;
  if (p.length < 126) { header = Buffer.from([0x81, p.length]); }
  else if (p.length < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(p.length, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(p.length), 2); }
  sock.write(Buffer.concat([header, p]));
}

cdp.on('upgrade', (req, sock) => {
  const key = String(req.headers['sec-websocket-key'] || '');
  const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
    + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
  let buf = Buffer.alloc(0);
  sock.on('data', (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    const f = parseWsFrame(buf);
    if (!f) return;
    buf = buf.subarray(f.consumed);
    if (f.opcode === 8) { sock.end(); return; }
    let msg: any = null;
    try { msg = JSON.parse(f.payload.toString()); } catch {}
    if (msg?.method === 'Storage.getCookies') {
      cdpCookieCalls++;
      sendWsText(sock, JSON.stringify({ id: msg.id, result: { cookies: CDP_COOKIES } }));
    }
  });
});

after(() => { try { cdp.close(); } catch {} });

// --- helpers (same shape as unlock-server.test.ts) ---
let nextPort = 26100 + Math.floor(Math.random() * 2000);

function serve(req: UnlockRequest, dbs = DBS): Promise<{ port: number; url: string; result: Promise<UnlockResult> }> {
  const cfg = normalize({});
  cfg.unlock.port = nextPort++;
  cfg.unlock.auto_open_browser = false;
  return new Promise((resolve) => {
    const result = waitForUnlock(cfg, KS, req, dbs, (url) => resolve({ port: cfg.unlock.port, url, result }));
  });
}

function req(port: number, opts: { method?: string; path: string; headers?: Record<string, string>; body?: string }): Promise<{ status: number; body: string; json: any }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ hostname: '127.0.0.1', port, path: opts.path, method: opts.method || 'GET', headers: opts.headers }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => {
        let j: any = null;
        try { j = JSON.parse(b); } catch {}
        resolve({ status: res.statusCode!, body: b, json: j });
      });
    });
    r.on('error', reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}
const get = (port: number, path: string) => req(port, { path });
const post = (port: number, path: string, body: string) =>
  req(port, { path, body, method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } });

function pubkeyOf(htmlBody: string): any {
  const m = htmlBody.match(/const PUB = (\{[^;]+\});/);
  assert.ok(m, 'page did not contain a rendered PUBKEY');
  return JSON.parse(m![1]);
}
function encPayload(jwk: any, obj: Record<string, string>): string {
  const aes = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', aes, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  const ek = publicEncrypt(
    { key: createPublicKey({ key: jwk, format: 'jwk' }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aes);
  return `${ek.toString('base64url')}.${iv.toString('base64url')}.${ct.toString('base64url')}`;
}

test('setup — fake CDP server', async () => {
  cdpPort = await new Promise<number>((resolve) => cdp.listen(0, '127.0.0.1', () => resolve((cdp.address() as any).port)));
  assert.ok(cdpPort > 0);
});

test('cookies mode — cookies are harvested only after explicit web approval (T7)', async () => {
  await saveSession('testdb', 'rightkey', 300); // session unlocked — approval page can skip master entry
  const r = requestCookieSync('testdb', 'UUID-1', 'github.com', `http://127.0.0.1:${cdpPort}`);
  const s = await serve(r);
  try {
    assert.equal(cdpCookieCalls, 0, 'CDP must not be touched before the request is served');
    const page = await get(s.port, `/unlock?t=${r.token}`);
    assert.equal(page.status, 200);
    assert.match(page.body, /쿠키 동기화|cookie/i, 'approval page renders the cookie-sync form');
    assert.equal(cdpCookieCalls, 0, 'serving the approval page must not harvest cookies');

    const jwk = pubkeyOf(page.body);
    const resp = await post(s.port, '/unlock', `t=${r.token}&p=${encPayload(jwk, {})}`);
    // Storage proceeds past harvest; the fake KDBX/python helper then fails —
    // what matters is the cookie read happened exactly once, post-approval.
    assert.equal(cdpCookieCalls, 1, 'cookie harvest must happen exactly once, after approval');
    assert.equal(resp.status, 400);
    assert.ok(
      ['PYTHON_HELPER_NOT_READY', 'PYTHON_HELPER_SPAWN_FAILED', 'ENTRY_UPDATE_FAILED', 'ENTRY_UPDATE_TIMEOUT', 'HELPER_FAILED'].includes(resp.json?.code),
      `expected storage-layer failure after harvest, got ${resp.status} ${resp.body}`,
    );
  } finally {
    clearSession('testdb');
    await post(s.port, `/cancel?t=${r.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});

test('cookies mode — a non-loopback CDP endpoint is rejected server-side (T11)', async () => {
  await saveSession('testdb', 'rightkey', 300);
  const r = requestCookieSync('testdb', 'UUID-1', 'github.com', 'http://169.254.169.254:9222');
  const s = await serve(r);
  try {
    const page = await get(s.port, `/unlock?t=${r.token}`);
    const jwk = pubkeyOf(page.body);
    const before = cdpCookieCalls;
    const resp = await post(s.port, '/unlock', `t=${r.token}&p=${encPayload(jwk, {})}`);
    assert.equal(resp.status, 400);
    assert.equal(resp.json?.code, 'CDP_ENDPOINT_REJECTED');
    assert.equal(cdpCookieCalls, before, 'rejected endpoints never reach the CDP layer');
  } finally {
    clearSession('testdb');
    await post(s.port, `/cancel?t=${r.token}`, '').catch(() => {});
    await s.result.catch(() => {});
  }
});
