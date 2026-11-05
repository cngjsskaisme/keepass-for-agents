// verify-artifact — package contract checks + real npm pack coverage.
// Pure-function unit tests for checkFileList, plus an end-to-end npm pack
// against this repo to prove the `files` whitelist satisfies the contract.
import '../fixtures/tmp-home.ts';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
// @ts-expect-error — .mjs ships no declarations; the contract is exercised
// through the exported functions below with literal argument types.
import { checkFileList, listTarEntries, listTarball } from '../../tools/verify-artifact.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dir, '..', '..');
const TMP: string[] = [];
const tmpd = (prefix: string) => { const d = mkdtempSync(join(tmpdir(), prefix)); TMP.push(d); return d; };
after(() => { for (const d of TMP) { try { rmSync(d, { recursive: true, force: true }); } catch {} } });
const VERIFY = join(REPO, 'tools', 'verify-artifact.mjs');
const npm = (args: string[]) =>
  spawnSync('npm', args, { encoding: 'utf8', cwd: REPO, shell: process.platform === 'win32', timeout: 120_000 });

const CLEAN = [
  'package/LICENSE', 'package/README.md', 'package/package.json',
  'package/src/cli/kp.ts', 'package/bin/kp', 'package/bin/kp.cmd',
  'package/tools/keepass/README.md', 'package/docs/installation.md',
  'package/web/unlock-ui/index.html', 'package/requirements.txt',
];

test('checkFileList — clean list passes', () => {
  const r = checkFileList(CLEAN);
  assert.equal(r.ok, true, r.errors.join('\n'));
});

test('checkFileList — required files must be present', () => {
  for (const drop of ['package/LICENSE', 'package/README.md', 'package/src/cli/kp.ts']) {
    const r = checkFileList(CLEAN.filter((f) => f !== drop));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e: string) => e.includes('missing required')), `expected missing-required for ${drop}`);
  }
});

test('checkFileList — dev/local-only content is rejected', () => {
  for (const bad of [
    'package/node_modules/iconv-lite/index.js',
    'package/tests/unit/config.test.ts',
    'package/tmp/capture.png',
    'package/.venv/Scripts/python.exe',
    'package/.git/HEAD',
    'package/.github/workflows/ci.yml',
    'package/.env',
    'package/.env.production',
    // dotenv at ANY depth, not just the package root
    'package/docs/.env',
    'package/tools/.env.production',
    'package/src/deep/nested/.env.local',
    'package/secrets.kdbx',
    'package/vault.keyx',
    // key material — extension-based and extensionless ssh names
    'package/tls/cert.pem',
    'package/creds/client.pfx',
    'package/creds/bundle.p12',
    'package/creds/app.key',
    'package/sigs/release.asc',
    'package/java/store.jks',
    'package/java/app.keystore',
    'package/.ssh/id_rsa',
    'package/keys/id_ed25519',
    'package/id_dsa',
    'package/id_ecdsa',
    'package/audit.log',
    'package/src/keepass/__pycache__/x.cpython-312.pyc',
  ]) {
    const r = checkFileList([...CLEAN, bad]);
    assert.equal(r.ok, false, `expected rejection for ${bad}`);
  }
});

test('checkFileList — GPL/binary honeypot: ANY native binary fails, renamed or not', () => {
  for (const bin of [
    'package/tools/keepass/KeePass.exe',
    'package/tools/keepass/KPScript.exe',
    'package/tools/keepass/KeePassLibN.x64.dll',
    'package/tools/keepass/KeePassLibN.a64.dll',
    'package/elsewhere/KeePass2.exe',
    // renamed payloads — extension, not name, is the tripwire
    'package/tools/keepass/notkeepass.exe',
    'package/tools/keepass/helper.dll',
    'package/bin/runner.exe',
    'package/lib/native.so',
    'package/lib/native.dylib',
    'package/drivers/x.sys',
  ]) {
    const r = checkFileList([...CLEAN, bin]);
    assert.equal(r.ok, false, `honeypot must catch ${bin}`);
    assert.ok(r.errors.some((e: string) => e.includes('GPL')), `expected GPL error for ${bin}`);
  }
  // text payloads under tools/keepass are NOT binaries — they must ship
  const ok = checkFileList([...CLEAN,
    'package/tools/keepass/KeePass.exe.config',
    'package/tools/keepass/KPScript.exe.config',
    'package/tools/keepass/README.md',
  ]);
  assert.equal(ok.ok, true, ok.errors.join('\n'));
});

test('listTarEntries — parses a real ustar stream', () => {
  // build a tiny tar in memory: one entry = 512-header + data + pad + EOT
  const data = Buffer.from('hello');
  const header = Buffer.alloc(512);
  header.write('package/short.txt', 0);
  header.write('0000644', 100);
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  header[156] = '0'.charCodeAt(0);
  let sum = 0; for (const b of header) sum += b;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  const tar = Buffer.concat([header, data, pad, Buffer.alloc(1024)]);
  const names = listTarEntries(tar);
  assert.deepEqual(names, ['package/short.txt']);
});

test('npm pack --dry-run file list satisfies the artifact contract', () => {
  const r = npm(['pack', '--dry-run', '--json']);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  const files = (Array.isArray(out) ? out[0] : out).files.map((f: any) => `package/${f.path}`);
  assert.ok(files.length > 30);
  const res = checkFileList(files);
  assert.equal(res.ok, true, res.errors.join('\n'));
});

test('npm pack tarball — listTarball reads it and the contract holds', () => {
  const outDir = tmpd('kp-pack-test-');
  const r = npm(['pack', '--pack-destination', outDir]);
  assert.equal(r.status, 0, r.stderr);
  const tgz = readdirSync(outDir).find((f) => f.endsWith('.tgz'))!;
  const names = listTarball(join(outDir, tgz));
  assert.ok(names.length > 30);
  assert.ok(names.every((n: string) => n.startsWith('package/')));
  const res = checkFileList(names);
  assert.equal(res.ok, true, res.errors.join('\n'));
});

test('verify-artifact CLI — --list mode: honeypot file → exit 1, clean → 0', () => {
  const dir = tmpd('kp-vlist-');
  const good = join(dir, 'good.txt');
  const bad = join(dir, 'bad.txt');
  writeFileSync(good, CLEAN.join('\n'));
  writeFileSync(bad, [...CLEAN, 'package/tools/keepass/KeePass.exe'].join('\n'));
  const g = spawnSync(process.execPath, [VERIFY, '--list', good], { encoding: 'utf8' });
  assert.equal(g.status, 0);
  assert.equal(JSON.parse(g.stdout.trim()).success, true);
  const b = spawnSync(process.execPath, [VERIFY, '--list', bad], { encoding: 'utf8' });
  assert.equal(b.status, 1);
  const bj = JSON.parse(b.stdout.trim());
  assert.equal(bj.success, false);
  assert.ok(bj.errors.some((e: string) => e.includes('GPL')));
});
