// Worker egress + output security tests (T4 URL policy, redirect contract,
// T8 redaction/schema whitelist, timeout tree-kill, T12 encoding guards).
//
// Import order matters: tmp-home must evaluate before any src module so that
// config.ts binds SESSION_DIR under the throwaway home.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { existsSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkWorkerUrl, pipeSecretToWorker } from '../../src/broker/broker.ts';
import { resolveWorker } from '../../src/worker/registry.ts';
import { keyStdin, cp949RoundTrips } from '../../src/keepass/kpscript.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { SESSION_DIR } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));

// Tripwire — if tmp-home ever loses the import-order race, SESSION_DIR points
// at the real profile and this fails loudly instead of polluting it.
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const WORKER = join(__dir, '..', '..', 'src', 'worker', 'local-test.mjs');
const DB = { path: 'C:/fake/test.kdbx' };

// Mock KPScript — node script that reads stdin key then emits canned output.
// Lives inside TEST_HOME: unique per test file/process, cleaned up on exit.
const MOCK = join(TEST_HOME, 'mock-kpscript-wsec.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
if(args.includes('-Field:Password'))process.stdout.write('s3cr3t\\n');
process.exit(0)})`);

// POSIX path uses the PyKeePass helper instead of KPScript — inject the shared
// mock helper (master must be 'rightkey', secret 's3cr3t').
const HELPER_DEFAULT = JSON.stringify([
  process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
]);
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = HELPER_DEFAULT;
}
const useHelper = (argv: string[]) => {
  if (process.platform !== 'win32')
    process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify(argv);
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- T4: worker URL egress policy ---

test('url policy — https any host allowed; http only loopback', () => {
  for (const ok of [
    'https://evil.example/login', 'https://anything.com:8443/x?y=1',
    'HTTPS://EXAMPLE.COM/', // scheme is case-insensitive
    'http://127.0.0.1/login', 'http://127.0.0.1:8080/x',
    'http://localhost/', 'http://localhost:3000/',
    'http://localhost./', // trailing-dot loopback still resolves local
    'http://[::1]:8080/login',
  ]) assert.equal(checkWorkerUrl(ok).ok, true, ok);

  for (const bad of [
    'http://evil.example', 'http://10.0.0.1:8080', 'http://example.com',
    'ftp://example.com', 'file:///c:/x', 'javascript:alert(1)', 'ws://x',
    'not a url', 'http://user:pw@127.0.0.1/', // embedded credentials
  ]) assert.equal(checkWorkerUrl(bad).ok, false, bad);
});

test('url policy — pipeSecretToWorker rejects http non-loopback before spawn', async () => {
  await saveSession('wsec', 'rightkey', 300);
  // This worker would create a sentinel if it ever ran — rejection must
  // happen before the secret is fetched and the process spawned.
  const sentinel = join(TEST_HOME, 'should-never-exist');
  const worker = join(TEST_HOME, 'w-write-sentinel.mjs');
  writeFileSync(worker, `import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(sentinel)},'x')`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec', DB, 'UUID-1',
    [process.execPath, worker], [],
    { db: 'wsec', entry: 'UUID-1', username: 'agent1', url: 'http://evil.example/login' },
  );
  clearSession('wsec');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WORKER_URL_REJECTED');
  assert.ok(!existsSync(sentinel), 'worker must not run on a rejected URL');
});

// --- Redirect contract: credentialed requests never follow redirects ---

test('redirect — local-test refuses a 302 and never reaches the target', async () => {
  let hits = 0;
  const server = createServer((req, res) => {
    hits++;
    if (req.url === '/login') {
      res.writeHead(302, { location: '/next' });
      return res.end();
    }
    res.writeHead(200); res.end('welcome');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  try {
    await saveSession('wsec-r', 'rightkey', 300);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK], 'wsec-r', DB, 'UUID-1',
      [process.execPath, WORKER], [],
      { db: 'wsec-r', entry: 'UUID-1', username: 'agent1', url: `http://127.0.0.1:${port}/login` },
    );
    clearSession('wsec-r');
    assert.equal(r.ok, false);
    assert.equal(r.code, 'REDIRECT_REJECTED');
    assert.equal(hits, 1, 'the redirect target must never be requested');
  } finally {
    server.close();
  }
});

// --- T8: secret redaction on worker output ---

test('redaction — worker echoing secret/username to stderr and detail is masked', async () => {
  await saveSession('wsec-l', 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-leak.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
console.error('dbg pw='+j.password+' u='+j.username);
process.stdout.write(JSON.stringify({success:false,code:'WORKER_LEAK',detail:'pw='+j.password+' u='+j.username}));
process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec-l', DB, 'UUID-1',
    [process.execPath, worker], [],
    { db: 'wsec-l', entry: 'UUID-1', username: 'agent1' },
  );
  clearSession('wsec-l');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WORKER_LEAK');
  assert.match(r.detail!, /\[redacted\]/);
  const s = JSON.stringify(r);
  assert.ok(!s.includes('s3cr3t'), `password leaked: ${s}`);
  assert.ok(!s.includes('agent1'), `username leaked: ${s}`);
});

test('redaction — secret smuggled inside the status field is masked too', async () => {
  await saveSession('wsec-l2', 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-leak2.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
process.stdout.write(JSON.stringify({success:true,status:'token='+j.password}));
process.exit(0)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec-l2', DB, 'UUID-1',
    [process.execPath, worker], [], { db: 'wsec-l2', entry: 'UUID-1' },
  );
  clearSession('wsec-l2');
  assert.equal(r.ok, true);
  assert.match(r.detail!, /\[redacted\]/);
  assert.ok(!JSON.stringify(r).includes('s3cr3t'));
});

// --- Variant matching: casing and interleaved whitespace ---

test('redaction — C1-control and ZWSP insertions cannot reassemble the secret', async () => {
  const alias = 'wsec-v2';
  await saveSession(alias, 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-variants2.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
process.stdout.write(JSON.stringify({success:false,code:'WORKER_V2',
detail:'c1='+j.password.split('').join('\\x85')+' zw='+j.password.split('').join('\\u200b')}));
process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], alias, DB, 'UUID-1',
    [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
  );
  clearSession(alias);
  const s = JSON.stringify(r);
  assert.ok(!s.includes('s3cr3t'), `C1-reassembled secret leaked: ${s}`);
  assert.ok(!s.includes('s​3​c​r​3​t'), `ZWSP variant leaked: ${s}`);
  assert.ok(!/s(?:\u0085|\u200b| )*3(?:\u0085|\u200b| )*c/.test(r.detail!), `fragmented secret leaked: ${JSON.stringify(r.detail)}`);
  assert.match(r.detail!, /\[redacted\]/);
});

test('redaction — case and whitespace variants of the secret are masked', async () => {
  const alias = 'wsec-v';
  await saveSession(alias, 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-variants.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
const spaced=j.password.split('').join(' ');
process.stdout.write(JSON.stringify({success:false,code:'WORKER_V',
detail:'up='+j.password.toUpperCase()+' spaced='+spaced}));
process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], alias, DB, 'UUID-1',
    [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
  );
  clearSession(alias);
  const s = JSON.stringify(r);
  assert.ok(!s.includes('S3CR3T'), `uppercase variant leaked: ${s}`);
  assert.ok(!s.includes('s 3 c r 3 t'), `spaced variant leaked: ${s}`);
  assert.match(r.detail!, /\[redacted\]/);
});

// --- Output schema whitelist ---

test('schema — unknown fields are dropped from the worker result', async () => {
  await saveSession('wsec-s', 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-extra.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
process.stdout.write(JSON.stringify({success:true,status:'ok',secret:j.password,token:'abc',extra:{deep:1}}));
process.exit(0)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec-s', DB, 'UUID-1',
    [process.execPath, worker], [], { db: 'wsec-s', entry: 'UUID-1' },
  );
  clearSession('wsec-s');
  assert.equal(r.ok, true);
  assert.equal(r.detail, 'ok');
  const s = JSON.stringify(r);
  assert.ok(!s.includes('s3cr3t') && !s.includes('abc'), `extra fields leaked: ${s}`);
});

test('schema — a malformed worker code is rejected as WORKER_OUTPUT_INVALID', async () => {
  await saveSession('wsec-c', 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-badcode.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
process.stdout.write(JSON.stringify({success:false,code:'not a code!',detail:'x'}));
process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec-c', DB, 'UUID-1',
    [process.execPath, worker], [], { db: 'wsec-c', entry: 'UUID-1' },
  );
  clearSession('wsec-c');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WORKER_OUTPUT_INVALID');
});

test('schema — workers cannot spoof system/broker codes; WORKER_* customs pass', async () => {
  for (const [i, [emitted, want]] of [
    ['UNLOCK_REQUIRED', 'WORKER_OUTPUT_INVALID'],
    ['AUTHENTICATION_FAILED', 'WORKER_OUTPUT_INVALID'],
    ['WORKER_TIMEOUT', 'WORKER_OUTPUT_INVALID'],
    ['WORKER_URL_REJECTED', 'WORKER_OUTPUT_INVALID'],
    ['WORKER_CUSTOM_SITE', 'WORKER_CUSTOM_SITE'],
    ['CREDENTIALS_REJECTED', 'CREDENTIALS_REJECTED'],
  ].entries()) {
    const alias = `wsec-sp${i}`;
    await saveSession(alias, 'rightkey', 300);
    const worker = join(TEST_HOME, `w-spoof${i}.mjs`);
    writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
process.stdout.write(JSON.stringify({success:false,code:${JSON.stringify(emitted)},detail:'x'}));
process.exit(1)})`);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK], alias, DB, 'UUID-1',
      [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
    );
    clearSession(alias);
    assert.equal(r.code, want, `${emitted} → ${want}`);
  }
});

// --- Timeout kills the whole worker process tree ---

test('timeout — worker and its spawned children are killed on expiry', async () => {
  await saveSession('wsec-t', 'rightkey', 300);
  const sentinel = join(TEST_HOME, 'grandchild-survived');
  const worker = join(TEST_HOME, 'w-sleep.mjs');
  writeFileSync(worker, `
import { spawn } from 'node:child_process';
// Grandchild: same process group on POSIX, child of the worker on Windows —
// writes a sentinel ~1.6s in unless the tree kill reaches it. Path goes via
// env to avoid quoting issues inside the generated script.
spawn(process.execPath,['-e','setTimeout(()=>require("node:fs").writeFileSync(process.env.KP_SENTINEL,"x"),1600)'],{stdio:'ignore',env:{...process.env,KP_SENTINEL:${JSON.stringify(sentinel)}}});
process.stdin.on('data',()=>{});
setInterval(()=>{},60000);`);
  const t0 = Date.now();
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], 'wsec-t', DB, 'UUID-1',
    [process.execPath, worker], [], { db: 'wsec-t', entry: 'UUID-1' },
    { timeoutMs: 900 },
  );
  clearSession('wsec-t');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WORKER_TIMEOUT');
  assert.ok(Date.now() - t0 < 10_000, 'timeout must fire near the configured cap');
  // Give the grandchild's own timer a chance to (not) fire.
  await sleep(2200);
  assert.ok(!existsSync(sentinel), 'grandchild survived the tree kill');
});

// --- Registry timeout field ---

test('registry — resolveWorker exposes per-worker timeoutMs', () => {
  const w = resolveWorker('local-test');
  assert.equal(w.ok, true);
  assert.equal(typeof w.timeoutMs, 'number');
  assert.ok(w.timeoutMs! > 0);
});

// --- T12: encoding guards ---

test('keyStdin — CR/LF in the master key is rejected', () => {
  for (const bad of ['a\nb', 'a\rb', 'x\r\ny'])
    assert.throws(() => keyStdin(bad, false), (e: any) => e?.code === 'INVALID_SECRET_CHARS');
  assert.equal(keyStdin('pw', false), 'pw\n\nn\n');
  assert.equal(keyStdin('pw', true), 'pw\nn\n');
});

test('cp949RoundTrips — ASCII/Hangul round-trip, emoji does not', () => {
  assert.equal(cp949RoundTrips('abc123!@#'), true);
  assert.equal(cp949RoundTrips('한글비밀'), true); // Hangul is in CP949
  assert.equal(cp949RoundTrips('pässwörd🙂'), false);
});

// --- P1: JSON-escaped echo must not bypass post-parse redaction ---

// A secret containing '"' and '\' — JSON.stringify on the worker side escapes
// them (pw\"sec\\ret!), so a raw-substring scan on stdout cannot match; only
// post-parse redaction on the decoded fields keeps it out of the result.
const TRICKY_SECRET = 'pw"sec\\ret!';

const MOCK_TRICKY = join(TEST_HOME, 'mock-kpscript-wsec-tricky.mjs');
writeFileSync(MOCK_TRICKY, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: bad key');process.exit(1)}
if(args.includes('-Field:Password'))process.stdout.write(${JSON.stringify(TRICKY_SECRET + '\n')});
process.exit(0)})`);

// POSIX equivalent — a one-off helper mock emitting the tricky secret.
const HELPER_TRICKY = join(TEST_HOME, 'mock-helper-tricky.mjs');
writeFileSync(HELPER_TRICKY, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
process.stdout.write(JSON.stringify({ok:true,secret:${JSON.stringify(TRICKY_SECRET)}}))})`);

test('redaction — JSON-escaped secret echo is redacted post-parse (P1)', async () => {
  useHelper([process.execPath, HELPER_TRICKY]);
  try {
    const alias = 'wsec-p1';
    await saveSession(alias, 'rightkey', 300);
    const worker = join(TEST_HOME, 'w-echo.mjs');
    writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
process.stdout.write(JSON.stringify({success:false,code:'WORKER_ECHO',detail:'got '+j.password}));
process.exit(1)})`);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK_TRICKY], alias, DB, 'UUID-1',
      [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
    );
    clearSession(alias);
    assert.equal(r.code, 'WORKER_ECHO');
    const s = JSON.stringify(r);
    assert.ok(!s.includes('pw"sec'), `secret leaked through detail: ${s}`);
    assert.ok(!s.includes('sec\\ret'), `partial secret leaked: ${s}`);
    assert.match(r.detail!, /\[redacted\]/);
  } finally {
    useHelper([process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs')]);
  }
});

test('redaction — success status field carrying the escaped secret is masked', async () => {
  useHelper([process.execPath, HELPER_TRICKY]);
  try {
    const alias = 'wsec-p1b';
    await saveSession(alias, 'rightkey', 300);
    const worker = join(TEST_HOME, 'w-echo-status.mjs');
    writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
process.stdout.write(JSON.stringify({success:true,status:j.password}));
process.exit(0)})`);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK_TRICKY], alias, DB, 'UUID-1',
      [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
    );
    clearSession(alias);
    assert.equal(r.ok, true);
    assert.ok(!JSON.stringify(r).includes('pw"sec'));
    assert.equal(r.detail, '[redacted]');
  } finally {
    useHelper([process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs')]);
  }
});

// --- Control chars + absolute paths in worker detail/status ---

test('output — control chars stripped, absolute paths collapsed in detail', async () => {
  const alias = 'wsec-ctl';
  await saveSession(alias, 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-ctl.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
process.stdout.write(JSON.stringify({success:false,code:'WORKER_CTL',
detail:'\\x1b[31mred\\x1b[0m\\x07 home='+${JSON.stringify(TEST_HOME)}+' cfg='+${JSON.stringify(SESSION_DIR)}}));
process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], alias, DB, 'UUID-1',
    [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
  );
  clearSession(alias);
  assert.equal(r.code, 'WORKER_CTL');
  assert.ok(!/[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(r.detail!), `control chars leaked: ${JSON.stringify(r.detail)}`);
  assert.ok(!r.detail!.includes(TEST_HOME), `absolute home path leaked: ${r.detail}`);
  assert.ok(!r.detail!.includes(SESSION_DIR), `absolute session path leaked: ${r.detail}`);
  assert.ok(r.detail!.includes('~'), `home not collapsed: ${r.detail}`);
});

// --- EPIPE: a worker exiting before reading stdin must not crash the broker ---

test('spawn — worker exiting immediately resolves cleanly (stdin EPIPE guard)', async () => {
  const alias = 'wsec-e';
  await saveSession(alias, 'rightkey', 300);
  const worker = join(TEST_HOME, 'w-exit-early.mjs');
  writeFileSync(worker, `process.exit(0)`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], alias, DB, 'UUID-1',
    [process.execPath, worker], [], { db: alias, entry: 'UUID-1' },
  );
  clearSession(alias);
  assert.equal(r.ok, false);
  assert.ok(r.code === 'LOGIN_FAILED' || r.code === 'WORKER_SPAWN_FAILED');
});
