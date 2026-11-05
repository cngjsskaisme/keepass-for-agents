// Audit log unit tests — JSONL schema, control-char hygiene, POSIX mode,
// rotation, and the no-secret contract.
// Import order: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync, writeFileSync, unlinkSync } from 'node:fs';
import { audit, readAudit, AUDIT_LOG } from '../../src/policy/audit.ts';
import { CONFIG_DIR } from '../../src/config/config.ts';

assert.ok(CONFIG_DIR.startsWith(TEST_HOME), `CONFIG_DIR escaped TEST_HOME: ${CONFIG_DIR}`);

const clear = () => { try { unlinkSync(AUDIT_LOG); } catch {} try { unlinkSync(AUDIT_LOG + '.1'); } catch {} };

test('audit — appends one JSONL record with the contract schema', () => {
  clear();
  audit({ agent: 'bot1', action: 'search', db: 'personal', decision: 'allow', target: 'query:github.com', result_code: 'OK' });
  const lines = readFileSync(AUDIT_LOG, 'utf8').trim().split('\n');
  assert.equal(lines.length, 1);
  const rec = JSON.parse(lines[0]);
  assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(rec.ts));
  assert.equal(rec.agent, 'bot1');
  assert.equal(rec.action, 'search');
  assert.equal(rec.db, 'personal');
  assert.equal(rec.decision, 'allow');
  assert.equal(rec.target, 'query:github.com');
  assert.equal(rec.result_code, 'OK');
  // No fields outside the schema survive.
  assert.deepEqual(Object.keys(rec).sort(), ['action', 'agent', 'db', 'decision', 'result_code', 'target', 'ts'].sort());
});

test('audit — success, failure and deny events all recorded', () => {
  clear();
  audit({ agent: 'bot', action: 'login', decision: 'deny', result_code: 'POLICY_DENIED' });
  audit({ agent: 'bot', action: 'search', decision: 'allow', result_code: 'UNLOCK_REQUIRED' });
  audit({ agent: 'bot', action: 'login', decision: 'allow', result_code: 'OK', target: 'entry:abc' });
  const recs = readAudit(10);
  assert.equal(recs.length, 3);
  assert.deepEqual(recs.map((r) => r.result_code), ['POLICY_DENIED', 'UNLOCK_REQUIRED', 'OK']);
});

test('audit — secrets never logged; control chars stripped; unknown fields dropped', () => {
  clear();
  // A caller mistakenly passing secret-shaped data must not have it land in
  // fields outside the schema; also assert the file carries no secret value.
  audit({ agent: 'bot', action: 'login', target: 'entry:abc', result_code: 'OK', ...( { password: 's3cr3t' } as any) });
  audit({ agent: 'b\x07ot', action: 'login', target: 'title:\nINJECTION', result_code: 'OK' });
  const raw = readFileSync(AUDIT_LOG, 'utf8');
  assert.ok(!raw.includes('s3cr3t'), 'secret material must never reach audit.log');
  assert.ok(!raw.includes('\x07'), 'control chars stripped');
  assert.ok(!raw.includes('INJECTION\n'), 'no log-line injection');
  const recs = readAudit(10);
  assert.equal(recs[0].agent, 'bot');
  assert.equal((recs[0] as any).password, undefined);
  assert.equal(recs[1].agent, 'bot'); // \x07 stripped
  assert.equal(recs[1].target, 'title:INJECTION');
});

test('audit — POSIX mode 0600 (skipped on Windows)', () => {
  clear();
  audit({ agent: 'bot', action: 'search', result_code: 'OK' });
  if (process.platform !== 'win32') {
    assert.equal(statSync(AUDIT_LOG).mode & 0o777, 0o600);
  }
});

test('audit — rotation: over the byte cap → audit.log.1', () => {
  clear();
  const max = 400;
  for (let i = 0; i < 6; i++)
    audit({ agent: 'bot', action: 'search', target: `q:${'x'.repeat(60)}${i}`, result_code: 'OK' }, max);
  assert.ok(existsSync(AUDIT_LOG + '.1'), 'rotated file must exist');
  assert.ok(statSync(AUDIT_LOG + '.1').size > 0);
  assert.ok(statSync(AUDIT_LOG).size <= max + 512, 'fresh log stays near the cap');
  const recs = readAudit(100);
  assert.ok(recs.length >= 1 && recs.length < 6, 'some records rotated out of the live file');
});

test('readAudit — tolerates a torn trailing line', () => {
  clear();
  writeFileSync(AUDIT_LOG, JSON.stringify({ ts: 't', agent: 'a', action: 'x' }) + '\n{"partial":');
  const recs = readAudit();
  assert.equal(recs.length, 1);
  assert.equal(recs[0].agent, 'a');
});
