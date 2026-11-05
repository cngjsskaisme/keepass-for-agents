// Import order matters: tmp-home must evaluate before any src module so that
// config.ts binds SESSION_DIR under the throwaway home, not the real profile.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pipeSecretToWorker, searchEntries } from '../../src/broker/broker.ts';
import { runKpscript } from '../../src/keepass/kpscript.ts';
import { saveSession, clearSession } from '../../src/security/dpapi.ts';
import { SESSION_DIR } from '../../src/config/config.ts';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));

// Tripwire — if tmp-home ever loses the import-order race, SESSION_DIR points
// at the real profile and this fails loudly instead of polluting it.
assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

// Mock KPScript — node script that reads stdin key then emits canned output.
// Lives inside TEST_HOME: unique per test file/process, cleaned up on exit.
const MOCK = join(TEST_HOME, 'mock-kpscript-pipeline.mjs');
writeFileSync(MOCK, `
let k='';process.stdin.on('data',d=>k+=d).on('end',()=>{
const args=process.argv.slice(2);
if(!k.startsWith('rightkey')){console.error('E: invalid composite key');process.exit(1)}
if(args.includes('-c:ListEntries')){process.stdout.write('UUID-1\\tGitHub Work\\tu@x.com\\thttps://github.com/login\\n')}
else if(args.includes('-c:GetEntryString')){process.stdout.write(args.includes('-Field:Password')?'s3cr3t\\n':'')}
else if(args.includes('-c:GetEntryCount')){process.stdout.write('1')}
process.exit(0)})`);

// POSIX path uses the PyKeePass helper instead of KPScript — inject a mock
// that speaks the same stdin-JSON → stdout-JSON protocol (see
// KEEPASS_AGENT_HELPER_CMD in src/provider/pykeepass.ts).
if (process.platform !== 'win32') {
  process.env.KEEPASS_AGENT_HELPER_CMD = JSON.stringify([
    process.execPath, join(__dir, '..', 'fixtures', 'mock-helper.mjs'),
  ]);
}

const DB = { path: 'C:/fake/test.kdbx' };
const ALIAS = 'pipetest';

test('kpscript stdin key — wrong key fails, right key lists entries', async () => {
  await assert.rejects(
    runKpscript(process.execPath, [MOCK, '-c:GetEntryCount', 'db'], { stdin: 'wrongkey\n' }),
    /composite|key/i,
  );
  const r = await runKpscript(process.execPath, [MOCK, '-c:ListEntries', 'db'], { stdin: 'rightkey\n' });
  assert.match(r.stdout, /UUID-1/);
});

test('pipeline — secret goes to worker stdin, never to caller', async () => {
  await saveSession(ALIAS, 'rightkey', 300);
  const worker = join(TEST_HOME, 'mock-worker-pipeline.mjs');
  writeFileSync(worker, `
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const j=JSON.parse(d);
if(j.password==='s3cr3t'){process.stdout.write(JSON.stringify({success:true,status:'authenticated'}));process.exit(0)}
process.stdout.write(JSON.stringify({success:false,code:'BAD_SECRET'}));process.exit(1)})`);
  const r = await pipeSecretToWorker(
    [process.execPath, MOCK], ALIAS, DB, 'UUID-1',
    [process.execPath, worker], [],
    { db: ALIAS, entry: 'UUID-1' },
  );
  clearSession(ALIAS);
  assert.equal(r.ok, true);
  assert.equal(r.detail, 'authenticated');
  // nothing in the return value carries the secret
  assert.ok(!JSON.stringify(r).includes('s3cr3t'));
});

test('pipeline — wrong key => UNLOCK/session fail not secret leak', async () => {
  await saveSession(ALIAS, 'wrongkey', 300);
  const r = await pipeSecretToWorker([process.execPath, MOCK], ALIAS, DB, 'UUID-1', [process.execPath, '-e', 'process.exit(1)'], [], {});
  clearSession(ALIAS);
  assert.equal(r.ok, false);
  assert.notEqual(r.code, undefined);
});
