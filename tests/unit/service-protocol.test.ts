// Credential Service unit tests — wire protocol, capability-token handshake,
// ACL checkers, peer-uid parser. Import order: tmp-home first so config.ts
// binds its paths under the throwaway home.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { writeFileSync, chmodSync, statSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { encode, LineDecoder, isRequest, MAX_MSG_BYTES } from '../../src/service/protocol.ts';
import { newToken, newNonce, hmacToken, verifyHmac, writeTokenFile, readTokenFile, tokenFileStat } from '../../src/service/auth.ts';
import { posixPermCheck, winAclCheck, parseIcaclsPrincipals, verifyHardenedEnvironment, serviceSelfCheck } from '../../src/service/acl.ts';
import { parseSsPeerPid, peerVerifyDecision } from '../../src/service/peer.ts';
import { normalize, type AppConfig } from '../../src/config/config.ts';

const cfgBase = (): AppConfig => normalize({});

test('protocol — encode/decode round trip + parse-error isolation', () => {
  const d = new LineDecoder();
  const msgs = d.feed(encode({ t: 'req', id: 1, op: 'hello' }) + encode({ t: 'res', id: 1, ok: true }));
  assert.equal(msgs.length, 2);
  assert.equal(msgs[0].op, 'hello');
  // Split chunks reassemble; a broken line becomes __parse_error__, not a throw.
  const d2 = new LineDecoder();
  assert.equal(d2.feed('{"t":"req"').length, 0);
  const m2 = d2.feed(',"id":2,"op":"status"}\nnot-json\n');
  assert.equal(m2[0].op, 'status');
  assert.equal(m2[1].t, '__parse_error__');
});

test('protocol — oversized message trips the overflow guard', () => {
  const d = new LineDecoder();
  d.feed('x'.repeat(MAX_MSG_BYTES + 1));
  assert.equal(d.overflow(), true);
  assert.equal(d.feed('more').length, 0);
});

test('protocol — newline-terminated line over the cap also overflows (G5)', () => {
  const d = new LineDecoder();
  // A completed line > MAX_MSG_BYTES is a full message — without a per-line
  // cap the whole-buffer check would accept it.
  const msgs = d.feed('x'.repeat(MAX_MSG_BYTES + 1) + '\n');
  assert.deepEqual(msgs, []);
  assert.equal(d.overflow(), true);
});

test('protocol — request shape whitelist (op set, id, agent)', () => {
  assert.equal(isRequest({ t: 'req', id: 0, op: 'login', agent: 'a' }), true);
  assert.equal(isRequest({ t: 'req', id: 0, op: 'getSecret' }), false); // no secret op exists
  assert.equal(isRequest({ t: 'req', id: -1, op: 'hello' }), false);
  assert.equal(isRequest({ t: 'req', id: 'x', op: 'hello' }), false);
  assert.equal(isRequest({ t: 'res', id: 0, op: 'hello' }), false);
});

test('auth — HMAC handshake: right token verifies, wrong/replayed fails', () => {
  const token = newToken();
  const n1 = newNonce();
  assert.equal(verifyHmac(token, n1, hmacToken(token, n1)), true);
  assert.equal(verifyHmac(token, n1, hmacToken('wrongtoken', n1)), false);
  // A response computed for a different nonce must not verify (no replay).
  const n2 = newNonce();
  assert.equal(verifyHmac(token, n2, hmacToken(token, n1)), false);
  assert.equal(verifyHmac(token, n1, ''), false);
  assert.equal(verifyHmac(token, n1, undefined as any), false);
});

test('auth — token file: write → stat → read; POSIX mode 0640', () => {
  const p = join(TEST_HOME, 'tok', 'ipc-token');
  const t = newToken();
  writeTokenFile(p, t);
  assert.equal(readTokenFile(p), t);
  const st = tokenFileStat(p);
  assert.equal(st.exists, true);
  if (process.platform !== 'win32') assert.equal(st.mode! & 0o777, 0o640);
  // Missing/short files read as unavailable — callers map to TOKEN_UNAVAILABLE.
  assert.equal(readTokenFile(join(TEST_HOME, 'no-such-token')), null);
  const short = join(TEST_HOME, 'short-token');
  writeFileSync(short, 'tiny');
  assert.equal(readTokenFile(short), null);
});

test('acl — POSIX perm check: other-bits fail, 0600 passes, owner pin works', { skip: process.platform === 'win32' }, () => {
  const f = join(TEST_HOME, 'vault.kdbx');
  writeFileSync(f, 'x');
  chmodSync(f, 0o600);
  assert.equal(posixPermCheck(f, { what: 'kdbx' }).ok, true);
  assert.equal(posixPermCheck(f, { what: 'kdbx', ownerUid: process.getuid!() }).ok, true);
  assert.equal(posixPermCheck(f, { what: 'kdbx', ownerUid: 999999 }).ok, false);
  chmodSync(f, 0o644);
  const bad = posixPermCheck(f, { what: 'kdbx' });
  assert.equal(bad.ok, false);
  assert.match(bad.detail!, /other_access_bits/);
  assert.equal(posixPermCheck(join(TEST_HOME, 'missing'), { what: 'kdbx' }).ok, false);
});

test('acl — Windows icacls allow-list: foreign principal fails, configured set passes', { skip: process.platform !== 'win32' }, () => {
  const f = join(TEST_HOME, 'vault.kdbx');
  writeFileSync(f, 'x');
  const me = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
  // Lock the file down to the current user only → a known principal set.
  let r = spawnSync('icacls', [f, '/inheritance:r', '/grant:r', `${me}:F`, '*S-1-5-18:F', 'BUILTIN\\Administrators:F'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const allowed = [me, 'NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators'];
  assert.equal(winAclCheck(f, allowed).ok, true, 'fully-listed ACE set should pass');
  // Allow-list semantics: a granted principal missing from the list fails —
  // even a benign-looking one (the gate can't model partial truth).
  const short = winAclCheck(f, [me, 'NT AUTHORITY\\SYSTEM']);
  assert.equal(short.ok, false);
  assert.match(short.detail!, /foreign_principal/);
  // Unconfigured allow-list → unmet (fail-closed, not assumed-safe).
  assert.equal(winAclCheck(f, undefined).ok, false);
  assert.equal(winAclCheck(f, []).ok, false);
  // Any grant outside the allow-list fails (Everyone, INTERACTIVE, …).
  r = spawnSync('icacls', [f, '/grant', 'Everyone:R'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const bad = winAclCheck(f, allowed);
  assert.equal(bad.ok, false);
  assert.match(bad.detail!, /foreign_principal:everyone/);
});

test('acl — icacls parser extracts ACE principals', () => {
  const out = [
    'C:\\tmp\\f.kdbx NT AUTHORITY\\SYSTEM:(I)(F)',
    '             BUILTIN\\Administrators:(I)(F)',
    '             DOMAIN\\agent:(I)(R)',
    '             Everyone:(DENY)(R)',
    '',
    'Successfully processed 1 files; Failed processing 0 files',
  ].join('\n');
  const p = parseIcaclsPrincipals(out, 'C:\\tmp\\f.kdbx');
  assert.deepEqual(p, ['nt authority\\system', 'builtin\\administrators', 'domain\\agent', 'everyone']);
});

test('acl — environment gate: token+KDBX failures surface as check list', () => {
  const f = join(TEST_HOME, 'env.kdbx');
  writeFileSync(f, 'x');
  const cfg = cfgBase();
  if (process.platform === 'win32') {
    // Allow-list is required on Windows — give the file a foreign principal.
    const r = spawnSync('icacls', [f, '/grant', 'Everyone:R'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    cfg.hardened.allowed_sids = [`${process.env.USERDOMAIN}\\${process.env.USERNAME}`];
  } else chmodSync(f, 0o644);
  const fails = verifyHardenedEnvironment(cfg, {
    tokenPath: join(TEST_HOME, 'missing-token'),
    kdbxPaths: [f],
  });
  assert.ok(fails.length >= 2, JSON.stringify(fails));
  assert.ok(fails.some((c) => c.check === 'token_file_perms'));
  assert.ok(fails.some((c) => c.check === 'kdbx_isolation'));
});

test('acl — serviceSelfCheck honors allowed_sids end-to-end (B1)', () => {
  // Regression for the blocker: serviceSelfCheck dropped the allow-list,
  // so on Windows every startup died with allowed_sids_unconfigured.
  // Call it directly (NOT through the SELFTEST hook, which hides this path).
  delete process.env.KEEPASS_AGENT_SERVICE_SELFTEST;
  const tokenPath = join(TEST_HOME, 'selfcheck-token');
  const sessionDir = join(TEST_HOME, 'selfcheck-sessions');
  writeTokenFile(tokenPath, newToken());
  mkdirSync(sessionDir, { recursive: true });
  const cfg = cfgBase();
  if (process.platform === 'win32') {
    const me = `${process.env.USERDOMAIN}\\${process.env.USERNAME}`;
    cfg.hardened.allowed_sids = [me, 'NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators'];
    // Temp dirs inherit environment ACEs — pin both files to the listed set.
    for (const [p, pmod] of [[tokenPath, 'F'], [sessionDir, '(OI)(CI)F']] as const) {
      const r = spawnSync('icacls', [p, '/inheritance:r', '/grant:r', `${me}:${pmod}`, `*S-1-5-18:${pmod}`, `BUILTIN\\Administrators:${pmod}`], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr || r.stdout);
    }
    const checks = serviceSelfCheck(cfg, { tokenPath, sessionDir });
    const token = checks.find((c) => c.check === 'token_file_perms')!;
    assert.equal(token.ok, true, `allowed-list configured but rejected: ${token.detail}`);
    // And prove the allow-list is actually applied: no allowed_sids → unmet.
    cfg.hardened.allowed_sids = undefined;
    const checks2 = serviceSelfCheck(cfg, { tokenPath, sessionDir });
    assert.equal(checks2.find((c) => c.check === 'token_file_perms')!.ok, false);
    assert.match(checks2.find((c) => c.check === 'token_file_perms')!.detail!, /allowed_sids_unconfigured/);
  } else {
    chmodSync(tokenPath, 0o640);
    chmodSync(sessionDir, 0o700);
    const checks = serviceSelfCheck(cfg, { tokenPath, sessionDir });
    assert.deepEqual(checks.filter((c) => !c.ok), [], JSON.stringify(checks));
  }
});

test('peer — ss output parser finds the client pid by peer inode', () => {
  const ss = [
    'Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
    'u_str ESTAB  0      0      /run/kp/svc.sock 1001 * 2002 users:(("node",pid=4242,fd=12))',
    'u_str ESTAB  0      0      * 2002 * 1001 users:(("kp",pid=777,fd=8))',
  ].join('\n');
  // Our accepted socket inode is 1001; the client's socket (ino 2002) pairs
  // back to us — its users clause carries the client pid 777.
  assert.equal(parseSsPeerPid(ss, '1001'), 777);
  assert.equal(parseSsPeerPid(ss, '9999'), null);
});

test('peer — verify decision: strict rejects unknown/unlisted, auto tolerates', () => {
  const unavailable = { ok: false, mechanism: 'unavailable' } as const;
  assert.equal(peerVerifyDecision('strict', unavailable).reject, true);
  assert.equal(peerVerifyDecision('auto', unavailable).reject, false);
  assert.equal(peerVerifyDecision('off', unavailable).reject, false);
  const id = { ok: true, uid: 1000, pid: 5, mechanism: 'ss-procfs' } as const;
  assert.equal(peerVerifyDecision('strict', id, [1000]).reject, false);
  const denied = peerVerifyDecision('strict', id, [2000]);
  assert.equal(denied.reject, true);
  assert.match(denied.reason!, /peer_uid_1000_not_allowed/);
  // allowed_uids unset → any resolved peer passes strict.
  assert.equal(peerVerifyDecision('strict', id, undefined).reject, false);
});

test('config — hardened section parses/normalizes/validates', () => {
  const c = normalize({
    hardened: {
      enabled: true, endpoint: '/run/kp/svc.sock', token_file: '/run/kp/ipc-token',
      state_dir: '/var/lib/kp', service_uid: 999, peer_verify: 'strict',
      allowed_uids: [1000], connect_timeout_ms: 3000,
    },
  });
  assert.equal(c.hardened.enabled, true);
  assert.equal(c.hardened.service_uid, 999);
  assert.equal(c.hardened.peer_verify, 'strict');
  assert.deepEqual(c.hardened.allowed_uids, [1000]);
  // Defaults: absent section → disabled, undefined extras.
  const d = normalize({});
  assert.equal(d.hardened.enabled, false);
  assert.equal(d.hardened.endpoint, undefined);
});
