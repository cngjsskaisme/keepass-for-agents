// Local unlock relay — a PURE PROXY between the user's browser (loopback)
// and the remote unlock server running inside a Sprite.
//
//   GET  /            → remote GET  <remote>/unlock?t=<relay-owned token>
//   POST /unlock      → remote POST <remote>/unlock   (body verbatim)
//   POST /cancel      → remote POST <remote>/cancel   (body verbatim)
//
// The remote page already contains the remote RSA public key, so the page's
// JS encrypts the master password under that key and posts {t, p}. The relay
// forwards the ciphertext byte-for-byte and NEVER sees the plaintext
// password — that is the whole point of this design (T3). A plaintext
// password field is never accepted, generated, or forwarded.
//
// Remote access goes through `sprite exec ... curl` argv arrays — no shell
// string is ever built. If the remote channel is unavailable the relay
// fails closed (502), it never degrades to a local plaintext form.
//
// Usage: node tools/relay-unlock.mjs <token> [localPort] [sprite] [remoteBase]
//   token       one-time token issued by the remote `kp unlock` (relay-owned;
//               only submissions carrying exactly this token are forwarded)
//   localPort   loopback port to serve on          (default 8767)
//   sprite      sprite name                        (default hub-test)
//   remoteBase  remote unlock base URL             (default http://127.0.0.1:8765)
//
// Test hook: KEEPASS_AGENT_SPRITE_CMD (JSON argv array) replaces the sprite
// executable — same convention as src/cli/kp.ts. Never set it outside tests.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const TOKEN = process.argv[2];
const PORT = Number(process.argv[3] || 8767);
const SPRITE = process.argv[4] || 'hub-test';
const REMOTE = (process.argv[5] || 'http://127.0.0.1:8765').replace(/\/+$/, '');

if (!TOKEN || !/^[A-Za-z0-9_-]{16,128}$/.test(TOKEN)) {
  console.error('usage: node tools/relay-unlock.mjs <token> [localPort] [sprite] [remoteBase]');
  console.error('  token: the one-time token from the remote unlock URL (16-128 url-safe chars)');
  process.exit(1);
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('relay: invalid local port');
  process.exit(1);
}
if (!/^[A-Za-z0-9._-]{1,64}$/.test(SPRITE)) {
  console.error('relay: invalid sprite name');
  process.exit(1);
}
try {
  const u = new URL(REMOTE);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error();
} catch {
  console.error('relay: remoteBase must be an http(s) URL');
  process.exit(1);
}

const MAX_BODY = 64 * 1024; // encrypted payloads are ~1KB; anything larger is anomalous

let spriteOverrideWarned = false;

/** Sprite executable — KEEPASS_AGENT_SPRITE_CMD (JSON argv array) test hook.
 *  Same one-time stderr warning as kp.ts when the override is active. */
function spriteCmd() {
  const raw = process.env.KEEPASS_AGENT_SPRITE_CMD;
  if (raw) {
    if (!spriteOverrideWarned) {
      spriteOverrideWarned = true;
      process.stderr.write('relay: warning: KEEPASS_AGENT_SPRITE_CMD override active — sprite exec routes to a test double\n');
    }
    try {
      const a = JSON.parse(raw);
      if (Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === 'string'))
        return { exe: a[0], prefix: a.slice(1) };
    } catch { /* bare executable path */ }
    return { exe: raw, prefix: [] };
  }
  return { exe: (process.env.LOCALAPPDATA || '') + '/Programs/Sprite/sprite.exe', prefix: [] };
}

/**
 * Run curl inside the sprite: `sprite exec -s <sprite> --stdin|--no-stdin --
 * curl <args...>` — pure argv, never a shell string. `stdinBody` is piped to
 * the remote curl's stdin (used with --data-binary @-).
 * Resolves { status, body } parsed from curl's -w status trailer.
 */
function remoteCurl(curlArgs, stdinBody) {
  return new Promise((resolve) => {
    const { exe, prefix } = spriteCmd();
    const args = [...prefix, 'exec', '-s', SPRITE,
      stdinBody == null ? '--no-stdin' : '--stdin',
      '--', 'curl', '-sS', '--max-time', '15', '-w', '\n%{http_code}', ...curlArgs];
    const c = spawn(exe, args, {
      windowsHide: true,
      env: { ...process.env, MSYS2_ARG_CONV_EXCL: '*', MSYS_NO_PATHCONV: '1' },
    });
    let out = '', err = '';
    c.stdout.on('data', (d) => (out += d));
    c.stderr.on('data', (d) => (err += d));
    const finish = (ok) => {
      if (!ok) return resolve({ status: 0, body: '', err: err || 'spawn failed' });
      const nl = out.lastIndexOf('\n');
      const status = nl >= 0 ? Number(out.slice(nl + 1).trim()) : 0;
      resolve({ status, body: nl >= 0 ? out.slice(0, nl) : out, err });
    };
    c.on('close', (code) => finish(code === 0));
    c.on('error', (e) => { err = String(e); finish(false); });
    if (stdinBody != null) c.stdin.write(stdinBody);
    c.stdin.end();
  });
}

const remoteGet = (path) =>
  remoteCurl(['-X', 'GET', `${REMOTE}${path}`], null);
const remotePost = (path, body, contentType) =>
  remoteCurl(['-X', 'POST', '-H', `content-type: ${contentType}`, '--data-binary', '@-', `${REMOTE}${path}`], body);

// --- loopback request hygiene (same policy as src/unlock-server/server.ts) ---
function hostOk(req) {
  const h = (req.headers.host || '').split(':')[0].toLowerCase().replace(/^\[|\]$/g, '');
  return ['127.0.0.1', 'localhost', '::1'].includes(h);
}
function originOk(req) {
  const o = req.headers.origin;
  if (!o) return true; // form POST may omit origin
  try {
    const h = new URL(o).hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return ['127.0.0.1', 'localhost', '::1'].includes(h);
  } catch { return false; }
}
function secHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
}
function html(res, status, s) {
  secHeaders(res);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(s);
}
function json(res, status, o) {
  secHeaders(res);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(o));
}
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const page = (title, msg) =>
  `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title><body style="font-family:sans-serif;max-width:400px;margin:60px auto;text-align:center"><h2>${esc(title)}</h2><p>${esc(msg)}</p></body>`;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = '', tooBig = false;
    // Over-cap bodies are drained (not socket-killed) so the client always
    // gets a clean 413 rather than a connection reset.
    req.on('data', (c) => {
      if (tooBig) return;
      d += c;
      if (d.length > MAX_BODY) { tooBig = true; d = ''; }
    });
    req.on('end', () => tooBig ? reject(new Error('too large')) : resolve(d));
    req.on('error', reject);
  });
}

/** Extract the submitted token `t` from urlencoded or JSON bodies (opaque `p` is never touched). */
function submittedToken(raw, ct) {
  try {
    if (ct.includes('json')) return String(JSON.parse(raw).t || '');
    return new URLSearchParams(raw).get('t') || '';
  } catch { return ''; }
}

const server = createServer(async (req, res) => {
  try {
    if (!hostOk(req) || !originOk(req)) return json(res, 403, { ok: false, code: 'FORBIDDEN' });
    const u = new URL(req.url || '/', 'http://x');

    // The token belongs to the relay (argv), never to the requester. Any
    // query/body token that isn't ours is rejected before touching upstream.
    const qt = u.searchParams.get('t');

    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/unlock')) {
      if (qt && qt !== TOKEN) return html(res, 403, page('forbidden', '이 릴레이가 발급한 토큰이 아닙니다.'));
      const r = await remoteGet(`/unlock?t=${encodeURIComponent(TOKEN)}`);
      // Fail closed: without the remote channel there is no encrypted-submit
      // path, and a plaintext credential form is never served.
      if (!r.status || r.status >= 400 || !r.body)
        return html(res, 502, page('relay unreachable', '원격 잠금 해제 서버에 연결할 수 없습니다. (sprite exec/curl 실패 또는 원격 오류)'));
      secHeaders(res);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(r.body);
    }

    if (req.method === 'POST' && (u.pathname === '/unlock' || u.pathname === '/cancel')) {
      const ct = String(req.headers['content-type'] || '');
      if (!ct.includes('application/x-www-form-urlencoded') && !ct.includes('application/json'))
        return json(res, 415, { ok: false, code: 'BAD_CONTENT_TYPE' });
      let raw;
      try { raw = await readBody(req); }
      catch { return json(res, 413, { ok: false, code: 'BODY_TOO_LARGE' }); }
      // Relay-owned token check — bodies naming any other token are dropped
      // before they reach the remote server (token is never requester-chosen).
      const t = submittedToken(raw, ct) || qt || '';
      if (t !== TOKEN) return json(res, 403, { ok: false, code: 'TOKEN_MISMATCH' });
      const r = await remotePost(u.pathname + (qt ? `?t=${encodeURIComponent(qt)}` : ''), raw, ct);
      if (!r.status) return json(res, 502, { ok: false, code: 'RELAY_UPSTREAM_FAILED' });
      secHeaders(res);
      res.writeHead(r.status, { 'content-type': 'application/json' });
      return res.end(r.body || JSON.stringify({ ok: false, code: 'RELAY_EMPTY_RESPONSE' }));
    }

    return json(res, 404, { ok: false, code: 'NOT_FOUND' });
  } catch {
    return json(res, 500, { ok: false, code: 'RELAY_INTERNAL' });
  }
});

server.listen(PORT, '127.0.0.1', () =>
  console.log(`relay: http://127.0.0.1:${PORT}/ -> ${REMOTE} via sprite '${SPRITE}' (proxy mode — plaintext never transits this process)`));
