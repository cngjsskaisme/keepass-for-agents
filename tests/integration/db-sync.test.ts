// db sync security tests — run the real CLI as a subprocess with the sprite
// exec channel replaced by tests/fixtures/mock-sprite.mjs (argv recorded to
// MOCK_SPRITE_LOG). Covers T2 injection rejection, argv-only remote command
// construction, and the staged/atomic local KDBX replace.
//
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, utimesSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { normalize, saveConfig, SESSION_DIR } from '../../src/config/config.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KP = join(__dir, '..', '..', 'src', 'cli', 'kp.ts');
const MOCK_SPRITE = join(__dir, '..', 'fixtures', 'mock-sprite.mjs');
const REMOTE_ROOT = join(TEST_HOME, 'remote-fs');
const SPRITE_LOG = join(TEST_HOME, 'sprite-calls.jsonl');
const DB_PATH = join(TEST_HOME, 'test.kdbx');
const REMOTE = '/root/.config/keepass-agent/test.kdbx';
const remoteFile = join(REMOTE_ROOT, ...REMOTE.split('/').filter(Boolean));

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

writeFileSync(DB_PATH, randomBytes(128));
mkdirSync(dirname(remoteFile), { recursive: true });

{
  const c = normalize({});
  c.databases = { testdb: { path: DB_PATH } };
  c.keepass.default_database = 'testdb';
  // PR-06: the CLI is policy-gated (deny-by-default) — these tests exercise
  // the sync/cdp channels, not policy, so the default agent is granted all.
  c.agents = { default: { allowed: ['*'] } };
  saveConfig(c);
}

interface KpRun { status: number | null; stdout: string; stderr: string; json: any; }

function kp(args: string[], env: Record<string, string> = {}): KpRun {
  const r = spawnSync(process.execPath, [KP, ...args], {
    env: {
      ...process.env,
      USERPROFILE: TEST_HOME,
      HOME: TEST_HOME,
      KEEPASS_AGENT_SPRITE_CMD: JSON.stringify([process.execPath, MOCK_SPRITE]),
      MOCK_REMOTE_ROOT: REMOTE_ROOT,
      MOCK_SPRITE_LOG: SPRITE_LOG,
      ...env,
    },
    encoding: 'utf8',
    timeout: 60_000,
  });
  let json: any = null;
  try { json = JSON.parse(r.stdout.trim().split('\n').pop() || ''); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

function spriteCalls(): string[][] {
  if (!existsSync(SPRITE_LOG)) return [];
  return readFileSync(SPRITE_LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}
const clearLog = () => rmSync(SPRITE_LOG, { force: true });

/** Every recorded sprite invocation must be pure argv — no remote shell. */
function assertNoShell(calls: string[][]) {
  for (const argv of calls) {
    const dd = argv.indexOf('--');
    const remoteArgv = dd >= 0 ? argv.slice(dd + 1) : [];
    assert.ok(!['sh', 'bash', 'dash', 'zsh', 'cmd', 'powershell'].includes(remoteArgv[0] || ''),
      `sprite remote command must not be a shell: ${JSON.stringify(argv)}`);
    assert.ok(!remoteArgv.some((a) => /[;&|`$<>'"\\]/.test(a)),
      `remote argv entry carries shell metacharacters: ${JSON.stringify(argv)}`);
  }
}

test('db sync — injection-shaped --remote is refused before any sprite call (T2)', () => {
  clearLog();
  for (const bad of ["x'; id; #", 'x"; id; #', 'x`id`', 'x; rm -rf /', 'x | tee /etc/passwd', 'x y.kdbx']) {
    const r = kp(['db', 'sync', '--remote', bad]);
    assert.equal(r.status, 1, `--remote ${JSON.stringify(bad)} should fail`);
    assert.equal(r.json?.code, 'INVALID_REMOTE_PATH', `--remote ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(spriteCalls(), [], 'sprite must never be invoked for a rejected remote path');
});

test('db sync — traversal/relative/bogus remote paths and bad sprite names refused', () => {
  clearLog();
  for (const bad of ['../etc/passwd', '/root/../etc/passwd', 'root/x.kdbx', '/root//x.kdbx', '/root/x k.kdbx', '-rf']) {
    const r = kp(['db', 'sync', '--remote', bad]);
    assert.equal(r.json?.code, 'INVALID_REMOTE_PATH', JSON.stringify(bad));
  }
  const r = kp(['db', 'sync', '--sprite', 'hub-test;id']);
  assert.equal(r.json?.code, 'INVALID_SPRITE');
  assert.deepEqual(spriteCalls(), []);
});

test('db sync push — argv-only calls upload and verify the remote copy', () => {
  rmSync(remoteFile, { force: true });
  clearLog();
  const r = kp(['db', 'sync', '--remote', REMOTE]);
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(r.json?.direction, 'push');
  assert.deepEqual(readFileSync(remoteFile), readFileSync(DB_PATH));
  const calls = spriteCalls();
  assert.ok(calls.length >= 3, 'expected md5sum/stat probe + upload + verify calls');
  assertNoShell(calls);
  assert.ok(calls.some((argv) => argv.includes('--file')), 'upload must go through sprite --file');
});

test('db sync — identical remote reports direction none', () => {
  writeFileSync(remoteFile, readFileSync(DB_PATH));
  const r = kp(['db', 'sync', '--remote', REMOTE]);
  assert.equal(r.json?.direction, 'none');
  assert.equal(r.json?.success, true);
});

test('db sync — remote-newer blocks push unless --force', () => {
  writeFileSync(remoteFile, randomBytes(64));
  utimesSync(remoteFile, new Date(), new Date(Date.now() + 60_000));
  const r = kp(['db', 'sync', '--remote', REMOTE]);
  assert.equal(r.json?.code, 'REMOTE_NEWER');
  assert.equal(readFileSync(remoteFile).length, 64, 'remote must be untouched');
});

test('db sync pull — staged replace: tmp → md5 verify → .bak → rename', () => {
  const remoteContent = randomBytes(200);
  writeFileSync(remoteFile, remoteContent);
  utimesSync(remoteFile, new Date(), new Date(Date.now() + 60_000));
  const oldLocal = readFileSync(DB_PATH);
  clearLog();
  const r = kp(['db', 'sync', '--remote', REMOTE, '--pull']);
  assert.equal(r.json?.success, true, r.stdout + r.stderr);
  assert.equal(r.json?.direction, 'pull');
  assert.equal(r.json?.backup, 'test.kdbx.bak');
  assert.deepEqual(readFileSync(DB_PATH), remoteContent, 'local kdbx replaced by remote bytes');
  assert.deepEqual(readFileSync(DB_PATH + '.bak'), oldLocal, 'previous kdbx preserved as .bak');
  assert.ok(!readdirSync(TEST_HOME).some((f) => f.includes('.pull-')), 'staged tmp file must not linger');
  assertNoShell(spriteCalls());
});

test('db sync pull — corrupted download fails integrity check and preserves the original', () => {
  const remoteContent = randomBytes(96);
  writeFileSync(remoteFile, remoteContent);
  utimesSync(remoteFile, new Date(), new Date(Date.now() + 60_000));
  const before = readFileSync(DB_PATH);
  const r = kp(['db', 'sync', '--remote', REMOTE, '--pull', '--force'], { MOCK_B64_CORRUPT: '1' });
  assert.equal(r.json?.success, false);
  assert.equal(r.json?.code, 'MD5_MISMATCH');
  assert.deepEqual(readFileSync(DB_PATH), before, 'original kdbx must survive a bad download');
  assert.ok(!readdirSync(TEST_HOME).some((f) => f.includes('.pull-')), 'tmp file cleaned up on failure');
});

test('entry sync-cookies / login-capture — --cdp must be loopback (T11)', () => {
  for (const bad of ['http://evil.com:9222', 'http://192.168.1.5:9222', 'http://127.0.0.1.evil.com', 'not-a-url']) {
    const r1 = kp(['entry', 'sync-cookies', '--db', 'testdb', '--cdp', bad]);
    assert.equal(r1.json?.code, 'CDP_ENDPOINT_REJECTED', `sync-cookies ${bad}`);
    const r2 = kp(['entry', 'login-capture', '--db', 'testdb', '--cdp', bad]);
    assert.equal(r2.json?.code, 'CDP_ENDPOINT_REJECTED', `login-capture ${bad}`);
  }
  const ok = kp(['entry', 'sync-cookies', '--db', 'testdb', '--cdp', 'http://127.0.0.1:9333']);
  assert.notEqual(ok.json?.code, 'CDP_ENDPOINT_REJECTED', 'loopback endpoint must pass validation');
});

test('entry sync-cookies — locked DB is refused before any approval is requested', () => {
  const r = kp(['entry', 'sync-cookies', '--db', 'testdb']);
  assert.equal(r.json?.code, 'UNLOCK_REQUIRED');
});

test('entry sync-cookies — no direct collection path exists in the handler', () => {
  // Structural guard for T7: the sync-cookies block must route through the
  // unlock-server approval flow (requestCookieSync + waitForUnlock) and must
  // not contain a direct CDP harvest / field-update call.
  const src = readFileSync(KP, 'utf8');
  const block = src.slice(src.indexOf("sub === 'sync-cookies'"), src.indexOf("sub === 'login-capture'"));
  assert.ok(block.length > 0, 'sync-cookies block not found');
  assert.match(block, /requestCookieSync/);
  assert.match(block, /waitForUnlock/);
  assert.doesNotMatch(block, /getBrowserCookies|updateEntryFields/);
});
