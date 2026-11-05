// MCP Adapter protocol tests — in-process serveMcp over PassThrough
// streams. Covers the JSON-RPC handshake surface: initialize negotiation,
// pre-initialize rejection, notifications, tools/list, tools/call dispatch,
// parse/invalid/method-not-found errors, declared-identity resolution, and
// stdout protocol purity. Tool semantics themselves live in
// mcp-tools.test.ts. Import order: tmp-home first.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { normalize, saveConfig, SESSION_DIR, CONFIG_DIR, type AppConfig } from '../../src/config/config.ts';
import { serveMcp, SUPPORTED_PROTOCOL_VERSIONS, LATEST_PROTOCOL_VERSION } from '../../src/mcp/server.ts';

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const DB_PATH = join(TEST_HOME, 'mcp.kdbx');
writeFileSync(DB_PATH, Buffer.alloc(64, 9));
const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');

function setCfg(mutate: (c: AppConfig) => void = () => {}): void {
  const c = normalize({});
  c.databases = { testdb: { path: DB_PATH } };
  c.keepass.default_database = 'testdb';
  c.agents = { default: { allowed: ['*'] } };
  c.unlock.auto_open_browser = false;
  mutate(c);
  saveConfig(c);
}

interface Harness {
  send: (o: any) => void;
  sendRaw: (s: string) => void;
  next: () => Promise<any>;
  end: () => Promise<void>;
  errs: () => string;
}

function harness(cliAgent?: string): Harness {
  const input = new PassThrough();
  const output = new PassThrough();
  const errput = new PassThrough();
  const pending: any[] = [];
  const waiters: ((m: any) => void)[] = [];
  let buf = '', errBuf = '';
  output.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const l = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (!l.trim()) continue;
      const m = JSON.parse(l); // stdout must stay protocol-pure — every line parses
      if (waiters.length) waiters.shift()!(m); else pending.push(m);
    }
  });
  errput.on('data', (d) => { errBuf += d; });
  const done = serveMcp({ input, output, errput, cliAgent });
  return {
    send: (o) => input.write(JSON.stringify(o) + '\n'),
    sendRaw: (s) => input.write(s),
    next: () => new Promise((resolve) => {
      if (pending.length) return resolve(pending.shift());
      waiters.push(resolve);
    }),
    end: async () => { input.end(); await done; },
    errs: () => errBuf,
  };
}

const INIT = (id: any, protocolVersion = '2025-11-25', extra: any = {}) => ({
  jsonrpc: '2.0', id, method: 'initialize',
  params: { protocolVersion, capabilities: {}, clientInfo: { name: 'test-client', version: '1.0' }, ...extra },
});

before(() => { setCfg(); });

test('mcp — initialize negotiates version and reports capabilities/serverInfo', async () => {
  const h = harness();
  h.send(INIT(1));
  const r = await h.next();
  assert.equal(r.jsonrpc, '2.0');
  assert.equal(r.id, 1);
  assert.equal(r.result.protocolVersion, '2025-11-25');
  assert.equal(r.result.serverInfo.name, 'keepass-agent');
  assert.ok(r.result.capabilities?.tools, JSON.stringify(r.result));
  await h.end();
});

test('mcp — version negotiation honors supported requests, falls back for unknown', async () => {
  const h = harness();
  h.send(INIT(1, '2024-11-05'));
  assert.equal((await h.next()).result.protocolVersion, '2024-11-05');
  await h.end();
  const h2 = harness();
  h2.send(INIT(1, '9-9-9'));
  assert.equal((await h2.next()).result.protocolVersion, LATEST_PROTOCOL_VERSION);
  assert.ok(SUPPORTED_PROTOCOL_VERSIONS.includes('2025-11-25'));
  await h2.end();
});

test('mcp — requests before initialize are rejected (-32002), ping is exempt', async () => {
  const h = harness();
  h.send({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  let r = await h.next();
  assert.equal(r.error?.code, -32002);
  h.send({ jsonrpc: '2.0', id: 2, method: 'ping' });
  r = await h.next();
  assert.deepEqual(r.result, {});
  await h.end();
});

test('mcp — notifications produce no response; initialized completes the handshake', async () => {
  const h = harness();
  h.send(INIT(1));
  await h.next();
  // A notification (no id) must get NO response — the next response we read
  // must belong to the subsequent ping, proving the notification was silent.
  h.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  h.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 99 } });
  h.send({ jsonrpc: '2.0', id: 7, method: 'ping' });
  const r = await h.next();
  assert.equal(r.id, 7);
  assert.deepEqual(r.result, {});
  await h.end();
});

test('mcp — tools/list exposes the secret-free tool surface', async () => {
  const h = harness();
  h.send(INIT(1));
  await h.next();
  h.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const r = await h.next();
  const names = r.result.tools.map((t: any) => t.name).sort();
  assert.deepEqual(names, [
    'audit_tail', 'logout', 'request_login', 'request_unlock',
    'revoke_session', 'search_entries', 'session_status',
  ]);
  for (const t of r.result.tools) {
    assert.equal(t.inputSchema?.type, 'object', t.name);
    assert.ok(typeof t.description === 'string' && t.description.length > 10, t.name);
  }
  await h.end();
});

test('mcp — malformed JSON, non-object, and array messages get JSON-RPC errors', async () => {
  const h = harness();
  h.sendRaw('this is not json\n');
  let r = await h.next();
  assert.equal(r.error?.code, -32700);
  assert.equal(r.id, null);
  h.sendRaw('42\n');
  r = await h.next();
  assert.equal(r.error?.code, -32600);
  h.sendRaw('[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n');
  r = await h.next();
  assert.equal(r.error?.code, -32600, 'JSON-RPC batching is not supported');
  h.sendRaw(JSON.stringify({ jsonrpc: '2.0', id: 5 }) + '\n');
  r = await h.next();
  assert.equal(r.error?.code, -32600, 'missing method must be invalid request');
  // The session survives malformed input — normal operation continues.
  h.send(INIT(9));
  r = await h.next();
  assert.equal(r.result?.protocolVersion, '2025-11-25');
  await h.end();
});

test('mcp — unknown method → -32601; unknown tool → -32602; bad arguments → -32602', async () => {
  const h = harness();
  h.send(INIT(1));
  await h.next();
  h.send({ jsonrpc: '2.0', id: 2, method: 'resources/list', params: {} });
  assert.equal((await h.next()).error?.code, -32601);
  h.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_secret', arguments: {} } });
  assert.equal((await h.next()).error?.code, -32602);
  h.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'session_status', arguments: ['x'] } });
  assert.equal((await h.next()).error?.code, -32602);
  await h.end();
});

test('mcp — tools/call returns MCP content blocks wrapping the CLI JSON family', async () => {
  const h = harness();
  h.send(INIT(1));
  await h.next();
  h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'session_status', arguments: { db: 'testdb' } } });
  const r = await h.next();
  assert.equal(r.id, 2);
  assert.equal(r.result.isError, false);
  const payload = JSON.parse(r.result.content[0].text);
  assert.equal(payload.success, true);
  assert.equal(payload.mode, 'standard');
  assert.equal(payload.status, 'LOCKED');
  assert.deepEqual(r.result.structuredContent, payload);
  await h.end();
});

test('mcp — policy deny surfaces as isError + POLICY_DENIED payload', async () => {
  setCfg((c) => { c.agents = { reader: { allowed: ['status'] } }; });
  try {
    const h = harness();
    h.send(INIT(1, '2025-11-25', { agent: 'reader' }));
    await h.next();
    h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'search_entries', arguments: { query: 'x' } } });
    const r = await h.next();
    assert.equal(r.result.isError, true);
    const payload = JSON.parse(r.result.content[0].text);
    assert.equal(payload.code, 'POLICY_DENIED');
    await h.end();
  } finally { setCfg(); }
});

test('mcp — declared agent identity: params.agent wins, then client mapping, cliAgent, env', async () => {
  // params.agent is written into the audit record — read it back.
  const auditAgentFor = async (extra: any, cliAgent?: string) => {
    try { unlinkSync(AUDIT_LOG); } catch {}
    const h = harness(cliAgent);
    h.send(INIT(1, '2025-11-25', extra));
    const init = await h.next();
    assert.ok(init.result, JSON.stringify(init));
    h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'session_status', arguments: {} } });
    await h.next();
    await h.end();
    const lines = readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    return lines.find((e) => e.action === 'mcp.session_status')?.agent;
  };
  assert.equal(await auditAgentFor({ agent: 'explicit' }), 'explicit');
  // clientInfo.name → [mcp.clients.<normalized>] mapping.
  setCfg((c) => { c.mcp.clients = { 'test-client': { agent: 'mapped' } }; });
  try {
    assert.equal(await auditAgentFor({}), 'mapped');
    assert.equal(await auditAgentFor({ agent: 'explicit2' }), 'explicit2', 'params.agent beats client mapping');
    // cliAgent fallback beats client mapping? No — mapping is more specific:
    // the chain is params > mapping > cliAgent > env > mcp.agent > default.
    assert.equal(await auditAgentFor({}), 'mapped');
  } finally { setCfg(); }
  // cliAgent fallback when no params/mapping.
  assert.equal(await auditAgentFor({}, 'cliid'), 'cliid');
  // mcp.agent config fallback.
  setCfg((c) => { c.mcp.agent = 'cfgagent'; });
  try { assert.equal(await auditAgentFor({}), 'cfgagent'); }
  finally { setCfg(); }
  // nothing declared → default.
  assert.equal(await auditAgentFor({}), 'default');
});

test('mcp — invalid declared agent id fails initialize closed', async () => {
  const h = harness();
  h.send(INIT(1, '2025-11-25', { agent: 'bad agent!' }));
  const r = await h.next();
  assert.equal(r.error?.code, -32602);
  assert.match(r.error?.message, /INVALID_AGENT_ID/);
  // A rejected initialize must not silently create a working session.
  h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'session_status', arguments: {} } });
  const r2 = await h.next();
  assert.equal(r2.error?.code, -32002);
  await h.end();
});

test('mcp — stdout carries only protocol frames (all lines are JSON-RPC)', async () => {
  // Implicitly proven by the harness JSON.parse on every stdout line — this
  // test additionally asserts the shape of frames across a whole session.
  const h = harness();
  h.send(INIT(1));
  h.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  h.sendRaw('garbage\n');
  h.send({ jsonrpc: '2.0', id: 3, method: 'ping' });
  for (let i = 0; i < 4; i++) {
    const r = await h.next();
    assert.equal(r.jsonrpc, '2.0');
    assert.ok('id' in r);
    assert.ok('result' in r || 'error' in r);
  }
  await h.end();
});
