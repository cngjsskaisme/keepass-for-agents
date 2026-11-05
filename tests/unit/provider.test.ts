// CredentialProvider contract tests — both backends behind the seam, the
// platform factory, and the frozen error-code namespace. No real KDBX or
// KPScript/pykeepass needed: the KPScript backend is exercised through a mock
// node script (same [exe, ...prefix] convention as pipeline.test.ts) and the
// PyKeePass backend through KEEPASS_AGENT_HELPER_CMD → mock-helper.mjs.
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createProvider, PROVIDER_ERROR_CODES } from '../../src/provider/provider.ts';
import { KpscriptProvider } from '../../src/provider/kpscript.ts';
import { PyKeePassProvider } from '../../src/provider/pykeepass.ts';
import { SESSION_DIR } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));

// Tripwire — if tmp-home ever loses the import-order race, SESSION_DIR points
// at the real profile and this fails loudly instead of polluting it.
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

const DB = { path: 'C:/fake/test.kdbx' };

// Mock KPScript — reads the -keyprompt stdin, accepts only 'rightkey'.
// 'BADOUT' uuid emits diagnostic text on stdout (must fail validation).
const MOCK = join(TEST_HOME, 'mock-kpscript-provider.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
if(args.includes('-c:ListEntries')){process.stdout.write('UUID-1\\tGitHub Work\\tu@x.com\\thttps://github.com/login\\n')}
else if(args.includes('-c:GetEntryString')){
if(args.join(' ').includes('BADOUT'))process.stdout.write('E: diagnostic\\n');
else process.stdout.write('s3cr3t\\n')}
process.exit(0)})`);
const KS: string[] = [process.execPath, MOCK];

// The PyKeePass backend speaks the helper protocol — inject the shared mock
// (master 'rightkey', secret 's3cr3t'). This works on every platform: only
// PyKeePassProvider consults KEEPASS_AGENT_HELPER_CMD.
process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
  process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
]);

const KNOWN = new Set<string>(PROVIDER_ERROR_CODES);
const assertKnownCode = (r: { ok: boolean; code?: string }) =>
  assert.ok(r.ok || (r.code && KNOWN.has(r.code)), `provider code outside the frozen namespace: ${r.code}`);

test('factory — platform selects the backend', () => {
  const p = createProvider(KS);
  assert.equal(p.kind, process.platform === 'win32' ? 'kpscript' : 'pykeepass');
});

test('kpscript backend — verifyKey ok / wrong key → AUTHENTICATION_FAILED', async () => {
  const p = new KpscriptProvider(KS);
  assert.deepEqual(await p.verifyKey(DB, 'rightkey'), { ok: true });
  const bad = await p.verifyKey(DB, 'wrongkey');
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'AUTHENTICATION_FAILED');
  assertKnownCode(bad);
});

test('kpscript backend — listEntries parses TSV output', async () => {
  const p = new KpscriptProvider(KS);
  const l = await p.listEntries(DB, 'rightkey');
  assert.equal(l.ok, true);
  assert.deepEqual(l.entries, [{ id: 'UUID-1', title: 'GitHub Work', username: 'u@x.com', url: 'https://github.com/login' }]);
});

test('kpscript backend — getSecret validates output; diagnostics → SECRET_OUTPUT_INVALID', async () => {
  const p = new KpscriptProvider(KS);
  const g = await p.getSecret(DB, 'rightkey', 'UUID-1');
  assert.equal(g.ok, true);
  assert.equal(g.secret, 's3cr3t');
  const bad = await p.getSecret(DB, 'rightkey', 'BADOUT');
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'SECRET_OUTPUT_INVALID');
  assertKnownCode(bad);
});

test('kpscript backend — write ops are PyKeePass-delegated (createDb keeps the kpscript-path contract)', async () => {
  // No python/venv needed to reach the contract check: a missing kpscript
  // path is rejected before any helper is spawned.
  const p = new KpscriptProvider('');
  const r = await p.createDb(join(TEST_HOME, 'nope.kdbx'), 'pw');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_CONFIG');
  assertKnownCode(r);
});

test('pykeepass backend — verifyKey ok / wrong key → INVALID_MASTER_KEY', async () => {
  const p = new PyKeePassProvider(KS);
  assert.deepEqual(await p.verifyKey(DB, 'rightkey'), { ok: true });
  const bad = await p.verifyKey(DB, 'wrongkey');
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'INVALID_MASTER_KEY');
  assertKnownCode(bad);
});

test('pykeepass backend — listEntries + getSecret through the helper protocol', async () => {
  const p = new PyKeePassProvider(KS);
  const l = await p.listEntries(DB, 'rightkey');
  assert.equal(l.ok, true);
  assert.deepEqual(l.entries, [{ id: 'UUID-1', title: 'GitHub Work', username: 'u@x.com', url: 'https://github.com/login' }]);
  const g = await p.getSecret(DB, 'rightkey', 'UUID-1');
  assert.equal(g.ok, true);
  assert.equal(g.secret, 's3cr3t');
  // Helper codes pass through verbatim — wrong key surfaces its code, not a rewrite.
  const gb = await p.getSecret(DB, 'wrongkey', 'UUID-1');
  assert.equal(gb.ok, false);
  assert.equal(gb.code, 'INVALID_MASTER_KEY');
  assertKnownCode(gb);
});
