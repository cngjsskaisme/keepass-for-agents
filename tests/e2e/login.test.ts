// Import order matters: tmp-home must evaluate before any src module so that
// config.ts binds SESSION_DIR under the throwaway home, not the real profile.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { SESSION_DIR } from '../../src/config/config.ts';
import { pipeSecretToWorker } from '../../src/broker/broker.ts';
import { writeFileSync } from 'node:fs';

const __dir = dirname(fileURLToPath(import.meta.url));

// Tripwire — if tmp-home ever loses the import-order race, SESSION_DIR points
// at the real profile and this fails loudly instead of polluting it.
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);
const WORKER = join(__dir, '..', '..', 'src', 'worker', 'local-test.mjs');

// Unique mock name per test file (TEST_HOME is also per-process) — no
// collision with pipeline.test.ts even under parallel test runners.
const MOCK = join(TEST_HOME, 'mock-kpscript-e2e.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: bad key');process.exit(1)}
if(args.includes('-Field:Password'))process.stdout.write('s3cr3t\\n');
process.exit(0)})`);

// POSIX path uses the PyKeePass helper instead of KPScript — inject a mock
// that speaks the same stdin-JSON → stdout-JSON protocol.
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

test('e2e — pipeline secret → worker → local login site', async () => {
  // local login site: accepts user/s3cr3t
  const server = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => b += c);
    req.on('end', () => {
      const p = new URLSearchParams(b);
      res.writeHead(p.get('password') === 's3cr3t' && p.get('username') === 'agent1' ? 200 : 403, { 'content-type': 'text/plain' });
      res.end(p.get('password') === 's3cr3t' ? 'welcome' : 'invalid credentials');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  try {
    await saveSession('e2e', 'rightkey', 300);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK], 'e2e', { path: 'C:/fake/db.kdbx' }, 'UUID-1',
      [process.execPath, WORKER], [],
      { db: 'e2e', entry: 'UUID-1', username: 'agent1', url: `http://127.0.0.1:${port}/login` },
    );
    clearSession('e2e');
    assert.equal(r.ok, true);
    assert.equal(r.detail, 'authenticated');
  } finally {
    server.close();
  }
});

test('e2e — wrong credentials rejected by site', async () => {
  const server = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => b += c);
    req.on('end', () => { res.writeHead(403); res.end('invalid'); });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  try {
    await saveSession('e2e2', 'rightkey', 300);
    const r = await pipeSecretToWorker(
      [process.execPath, MOCK], 'e2e2', { path: 'C:/fake/db.kdbx' }, 'UUID-1',
      [process.execPath, WORKER], [],
      { db: 'e2e2', entry: 'UUID-1', username: 'agent1', url: `http://127.0.0.1:${port}/login` },
    );
    clearSession('e2e2');
    assert.equal(r.ok, false);
    assert.equal(r.code, 'CREDENTIALS_REJECTED');
  } finally {
    server.close();
  }
});
