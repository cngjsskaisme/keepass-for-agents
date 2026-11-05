// relay-unlock proxy tests (T3) — the relay must behave as a pure proxy:
// remote page served verbatim, bodies forwarded byte-for-byte to the remote
// /unlock, no plaintext password ever synthesized. Host/Origin loopback
// checks, relay-owned token enforcement, body cap, and fail-closed upstream
// handling are exercised over real HTTP. The sprite channel is mocked by
// tests/fixtures/mock-sprite.mjs (its `curl` mode does a real local request).
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SESSION_DIR } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const RELAY = join(__dir, '..', '..', 'tools', 'relay-unlock.mjs');
const MOCK_SPRITE = join(__dir, '..', 'fixtures', 'mock-sprite.mjs');

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const TOKEN = 'a'.repeat(32); // valid charset: [A-Za-z0-9_-]{16,128}
const remotePosts: { path: string; body: string; ct: string }[] = [];

// --- fake "remote" unlock server (stands in for the sprite-side server) ---
const remote: Server = createServer((req, res) => {
  const u = new URL(req.url || '/', 'http://x');
  if (req.method === 'GET' && u.pathname === '/unlock') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(`<!doctype html><title>remote unlock</title><script>const PUB = {"kty":"RSA","n":"AA","e":"AQAB"};</script>REMOTE-UNLOCK-PAGE t=${u.searchParams.get('t')}`);
  }
  if (req.method === 'POST' && (u.pathname === '/unlock' || u.pathname === '/cancel')) {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      remotePosts.push({ path: u.pathname + u.search, body: b, ct: String(req.headers['content-type']) });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, remote: true, path: u.pathname }));
    });
    return;
  }
  res.writeHead(404); res.end();
});

const children: ChildProcess[] = [];
after(() => { for (const c of children) { try { c.kill(); } catch {} } try { remote.close(); } catch {} });

let nextPort = 25100 + Math.floor(Math.random() * 2000);
let remotePort = 0;

function listen(s: Server): Promise<number> {
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve((s.address() as any).port)));
}

/** Start the relay against the fake remote; resolves once it prints its URL. */
function startRelay(opts: { spriteCmd?: string; remote?: string } = {}): Promise<{ port: number; child: ChildProcess }> {
  const port = nextPort++;
  const env = {
    ...process.env,
    KEEPASS_AGENT_SPRITE_CMD: opts.spriteCmd ?? JSON.stringify([process.execPath, MOCK_SPRITE]),
  };
  const child = spawn(process.execPath, [RELAY, TOKEN, String(port), 'hub-test', opts.remote ?? `http://127.0.0.1:${remotePort}`], { env });
  children.push(child);
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('relay did not start')), 10_000);
    child.stdout!.on('data', (d) => {
      if (String(d).includes('relay:')) { clearTimeout(to); resolve({ port, child }); }
    });
    child.on('exit', (c) => { clearTimeout(to); reject(new Error(`relay exited ${c}`)); });
  });
}

interface Resp { status: number; body: string; headers: any; json: any; }
function req(port: number, opts: { method?: string; path: string; headers?: Record<string, string>; body?: string }): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ hostname: '127.0.0.1', port, path: opts.path, method: opts.method || 'GET', headers: opts.headers }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => {
        let j: any = null;
        try { j = JSON.parse(b); } catch {}
        resolve({ status: res.statusCode!, body: b, headers: res.headers, json: j });
      });
    });
    r.on('error', reject);
    if (opts.body != null) r.write(opts.body);
    r.end();
  });
}

test('setup — fake remote unlock server', async () => {
  remotePort = await listen(remote);
  assert.ok(remotePort > 0);
});

test('relay — GET proxies the remote unlock page verbatim (token embedded upstream)', async () => {
  const { port } = await startRelay();
  const r = await req(port, { path: '/' });
  assert.equal(r.status, 200);
  assert.match(r.body, /REMOTE-UNLOCK-PAGE/);
  assert.match(r.body, new RegExp(`t=${TOKEN}`), 'remote page fetched with the relay-owned token');
  assert.equal(r.headers['cache-control'], 'no-store');
});

test('relay — non-loopback Host and Origin are refused (PR-02 parity)', async () => {
  const { port } = await startRelay();
  assert.equal((await req(port, { path: '/', headers: { host: '10.0.0.9' } })).status, 403);
  assert.equal((await req(port, { path: '/', headers: { host: '127.0.0.1.evil.com' } })).status, 403);
  assert.equal((await req(port, { path: '/', headers: { origin: 'http://evil.example' } })).status, 403);
  assert.equal((await req(port, { path: '/unlock', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://10.1.2.3' }, body: `t=${TOKEN}&p=x` })).status, 403);
});

test('relay — a token the relay does not own is never forwarded (T3)', async () => {
  const { port } = await startRelay();
  remotePosts.length = 0;
  const bogus = 'b'.repeat(32);
  // wrong token in query for GET
  assert.equal((await req(port, { path: `/unlock?t=${bogus}` })).status, 403);
  // wrong token in POST body
  const bad = await req(port, { path: '/unlock', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `t=${bogus}&p=AAAA` });
  assert.equal(bad.status, 403);
  assert.equal(bad.json?.code, 'TOKEN_MISMATCH');
  assert.equal(remotePosts.length, 0, 'nothing may reach the remote server for a foreign token');
});

test('relay — POST body is forwarded byte-for-byte; plaintext never synthesized', async () => {
  const { port } = await startRelay();
  remotePosts.length = 0;
  const body = `t=${TOKEN}&p=ek.iv.ct-encrypted-payload`;
  const r = await req(port, { path: '/unlock', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(r.status, 200);
  assert.equal(r.json?.ok, true);
  assert.equal(remotePosts.length, 1);
  assert.equal(remotePosts[0].body, body, 'the encrypted payload must pass through verbatim');
  assert.equal(remotePosts[0].path, '/unlock');
  assert.equal(remotePosts[0].ct, 'application/x-www-form-urlencoded');
  assert.ok(!remotePosts[0].body.includes('password='), 'relay must not synthesize plaintext password fields');
});

test('relay — cancel is proxied too (form action in the remote page)', async () => {
  const { port } = await startRelay();
  remotePosts.length = 0;
  const r = await req(port, { path: `/cancel?t=${TOKEN}`, method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '' });
  assert.equal(r.status, 200);
  assert.equal(remotePosts[0]?.path, `/cancel?t=${TOKEN}`);
});

test('relay — oversized bodies are refused before upstream', async () => {
  const { port } = await startRelay();
  remotePosts.length = 0;
  const big = `t=${TOKEN}&p=${'x'.repeat(70 * 1024)}`;
  const r = await req(port, { path: '/unlock', method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: big });
  assert.equal(r.status, 413);
  assert.equal(remotePosts.length, 0);
});

test('relay — fails closed when the remote channel is unavailable', async () => {
  // Sprite command that does not exist → every remote fetch fails → 502 page,
  // never a locally-served plaintext form.
  const { port } = await startRelay({ spriteCmd: JSON.stringify([process.execPath, join(TEST_HOME, 'no-such-file.mjs')]) });
  const r = await req(port, { path: '/' });
  assert.equal(r.status, 502);
  assert.doesNotMatch(r.body, /type="password"/, 'fail-closed must not fall back to a local password form');
});
