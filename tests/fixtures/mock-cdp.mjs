// Fake Chrome for tests — HTTP /json/version plus a hand-rolled RFC 6455
// WebSocket endpoint speaking just enough CDP (flat protocol) for the
// browser-login worker: Target.*, Page.enable/navigate/loadEventFired,
// Runtime.evaluate, Network.getCookies. Runtime.evaluate responses are
// scenario-driven and routed by the /*marker*/ comment the driver's
// in-page sources carry (/*inspect*/, /*fill*/, /*submit*/).
//
//   const { endpoint, state, close } = await startMockCdp({
//     inspect: (state) => ({ url, hasPassword, mfa, error, marker, ... }),
//     cookies: (state) => [{ name, httpOnly, ... }],
//     navError: 'net::ERR_...',          // optional — Page.navigate errorText
//   });
//
// state tracks submitted/fillArgs/lastInspectUrl so scenarios can switch
// inspect() output between the pre- and post-submit phases.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function wsAccept(key) {
  return createHash('sha1').update(key + WS_GUID).digest('base64');
}

/** Encode a server→client frame (FIN set, unmasked). */
function encodeFrame(payload, opcode = 0x1) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const len = body.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode; head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode; head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, body]);
}

/** Incremental client→server frame parser (masked text/binary/ping/pong/close). */
function makeFrameParser({ onText, onPong, socket }) {
  let buf = Buffer.alloc(0);
  let frags = null;
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const op = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2); off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        len = Number(buf.readBigUInt64BE(2)); off = 10;
      }
      const maskOff = off;
      if (masked) off += 4;
      if (len > 16 * 1024 * 1024) { socket.destroy(); return; }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked) {
        const m = buf.subarray(maskOff, maskOff + 4);
        const p = Buffer.alloc(len);
        for (let i = 0; i < len; i++) p[i] = payload[i] ^ m[i & 3];
        payload = p;
      }
      buf = buf.subarray(off + len);
      if (op === 0x8) { socket.end(encodeFrame(Buffer.alloc(0), 0x8)); return; }
      if (op === 0x9) { socket.write(encodeFrame(payload, 0xA)); continue; }
      if (op === 0xA) { onPong?.(payload); continue; }
      if (op === 0x1 || op === 0x2) { frags = [payload]; }
      else if (op === 0x0 && frags) { frags.push(payload); }
      else continue;
      if (fin && frags) {
        const text = Buffer.concat(frags).toString('utf8');
        frags = null;
        onText(text);
      }
    }
  };
}

/** Extract the trailing args array from `(<fnSrc>)(<jsonArgs>)` expressions. */
function evalArgs(expr) {
  const i = expr.lastIndexOf(')([');
  if (i < 0 || !expr.endsWith('])')) return [];
  try { return JSON.parse(expr.slice(i + 2, -1)); } catch { return []; }
}

function originOf(url) {
  try { return new URL(url).origin; } catch { return null; }
}

function handleMessage(msg, send, state, scenario) {
  state.calls.push(msg);
  const { id, method, params = {}, sessionId } = msg;
  const reply = (result) => send({ id, result });
  switch (method) {
    case 'Target.createBrowserContext': return reply({ browserContextId: 'ctx-1' });
    case 'Target.createTarget': return reply({ targetId: 't-1' });
    case 'Target.attachToTarget': return reply({ sessionId: 'sess-1' });
    case 'Page.enable':
    case 'Runtime.enable':
    case 'Network.enable':
    case 'Target.closeTarget':
    case 'Target.disposeBrowserContext':
      return reply({});
    case 'Page.navigate': {
      const navErr = typeof scenario.navError === 'function' ? scenario.navError(state) : scenario.navError;
      reply(navErr ? { frameId: 'f-1', errorText: navErr } : { frameId: 'f-1', loaderId: 'l-1' });
      if (!navErr)
        send({ method: 'Page.loadEventFired', params: { timestamp: Date.now() / 1000 }, sessionId });
      return;
    }
    case 'Network.getCookies':
      return reply({ cookies: scenario.cookies?.(state, params) ?? [] });
    case 'Runtime.evaluate': {
      const expr = String(params.expression || '');
      let value = null;
      if (expr.includes('/*inspect*/')) {
        value = scenario.inspect(state);
        if (value?.url) state.lastInspectUrl = value.url;
      } else if (expr.includes('/*clear*/')) {
        state.clearedPw = true;
        value = true;
      } else if (expr.includes('/*fill*/')) {
        const args = evalArgs(expr);
        state.fillArgs = args; // [username, password, expectedOrigin]
        const pageOrigin = originOf(state.lastInspectUrl);
        value = (args[2] && pageOrigin && args[2] !== pageOrigin)
          ? { originMismatch: pageOrigin }
          : (scenario.fillResult?.(state, args) ?? { user: true, pass: true });
      } else if (expr.includes('/*submit*/')) {
        const args = evalArgs(expr);
        const pageOrigin = originOf(state.lastInspectUrl);
        if (args[0] && pageOrigin && args[0] !== pageOrigin) {
          value = { originMismatch: pageOrigin };
        } else {
          state.submitted = true;
          value = scenario.submitResult?.(state) ?? { how: 'clicked' };
        }
      } else if (scenario.otherEval) {
        value = scenario.otherEval(expr, state);
      }
      return reply({ result: { type: value === null ? 'undefined' : typeof value === 'object' ? 'object' : typeof value, ...(value !== undefined ? { value } : {}) } });
    }
    default:
      return reply({});
  }
}

/**
 * Start the fake Chrome. Returns { endpoint, state, close } — `endpoint` is
 * a loopback http:// URL suitable for the worker's `cdp` field.
 */
export async function startMockCdp(scenario = {}) {
  if (typeof scenario.inspect !== 'function')
    scenario.inspect = () => ({ url: 'about:blank', hasPassword: false });
  const state = { submitted: false, fillArgs: null, lastInspectUrl: 'about:blank', calls: [] };
  const sockets = new Set();
  const server = createServer((req, res) => {
    if (req.url === '/json/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/browser/mock`,
      }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n\r\n`,
    );
    socket.setNoDelay(true);
    sockets.add(socket);
    const send = (o) => { try { socket.write(encodeFrame(JSON.stringify(o))); } catch {} };
    socket.on('data', makeFrameParser({
      socket,
      onText: (text) => { try { handleMessage(JSON.parse(text), send, state, scenario); } catch {} },
    }));
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  return {
    endpoint,
    state,
    async close() {
      for (const s of sockets) { try { s.destroy(); } catch {} }
      await new Promise((r) => server.close(r));
    },
  };
}
