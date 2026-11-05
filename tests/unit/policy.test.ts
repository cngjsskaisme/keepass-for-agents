// Policy engine unit tests — deny-by-default, glob action matching,
// entry/host restrictions, agent identity resolution.
// Import order: tmp-home must evaluate before any src module.
import '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalize } from '../../src/config/config.ts';
import {
  evaluate, resolveAgentId, agentPolicy, entryPermitted, entryMatches,
  hostAllowed, globMatch, APPROVABLE_ACTIONS, DEFAULT_AGENT,
} from '../../src/policy/engine.ts';

const cfgOf = (agents: Record<string, any>) => normalize({ agents });

test('deny-by-default — no policy at all denies every action', () => {
  const cfg = cfgOf({});
  for (const action of ['search', 'login', 'db.list', 'unlock', 'entry.add', 'audit.read']) {
    const ev = evaluate(cfg, 'default', action);
    assert.equal(ev.decision, 'deny', action);
    assert.equal(ev.policy, 'none');
    assert.match(ev.reason, /no policy/);
  }
});

test('deny-by-default — unlisted action denied even when other actions allowed', () => {
  const cfg = cfgOf({ default: { allowed: ['search'] } });
  assert.equal(evaluate(cfg, 'default', 'search').decision, 'allow');
  assert.equal(evaluate(cfg, 'default', 'login').decision, 'deny');
  assert.equal(evaluate(cfg, 'default', 'db.sync').decision, 'deny');
});

test('unnamed agent falls back to agents.default; unknown action glob denied', () => {
  const cfg = cfgOf({ default: { allowed: ['db.*'], } });
  assert.equal(evaluate(cfg, 'whoever', 'db.list').decision, 'allow');
  assert.equal(evaluate(cfg, 'whoever', 'db.list').policy, 'default');
  assert.equal(evaluate(cfg, 'whoever', 'login').decision, 'deny');
});

test('named agent policy beats default; wildcard allowed', () => {
  const cfg = cfgOf({
    default: { allowed: ['search'] },
    admin: { allowed: ['*'] },
  });
  assert.equal(evaluate(cfg, 'admin', 'db.sync').decision, 'allow');
  assert.equal(evaluate(cfg, 'admin', 'db.sync').policy, 'admin');
  assert.equal(evaluate(cfg, 'default', 'db.sync').decision, 'deny');
});

test('require_approval — decision returned, approvable set distinguishes channel', () => {
  const cfg = cfgOf({ bot: { allowed: ['search'], require_approval: ['entry.add', 'login'] } });
  const add = evaluate(cfg, 'bot', 'entry.add');
  assert.equal(add.decision, 'require_approval');
  assert.ok(APPROVABLE_ACTIONS.has('entry.add'));
  const login = evaluate(cfg, 'bot', 'login');
  assert.equal(login.decision, 'require_approval');
  assert.ok(!APPROVABLE_ACTIONS.has('login'));
});

test('require_approval beats a matching allowed entry (stricter wins)', () => {
  const cfg = cfgOf({ bot: { allowed: ['*'], require_approval: ['entry.*'] } });
  assert.equal(evaluate(cfg, 'bot', 'entry.add').decision, 'require_approval');
  assert.equal(evaluate(cfg, 'bot', 'entry.sync-cookies').decision, 'require_approval');
  assert.equal(evaluate(cfg, 'bot', 'search').decision, 'allow');
});

test('entry restrictions — denied_entries wins over allowed_entries', () => {
  const cfg = cfgOf({
    bot: { allowed: ['login'], allowed_entries: ['github.com'], denied_entries: ['*prod*'] },
  });
  const ok = evaluate(cfg, 'bot', 'login', { entry: { title: 'gh', url: 'https://github.com/x' } });
  assert.equal(ok.decision, 'allow');
  const denied = evaluate(cfg, 'bot', 'login', { entry: { title: 'prod db', url: 'https://github.com/prod' } });
  assert.equal(denied.decision, 'deny');
  assert.match(denied.reason, /entry not permitted/);
  const outside = evaluate(cfg, 'bot', 'login', { entry: { title: 'other', url: 'https://example.com' } });
  assert.equal(outside.decision, 'deny');
});

test('entry restrictions — trailing-dot host cannot evade denied_entries', () => {
  const cfg = cfgOf({ bot: { allowed: ['login'], denied_entries: ['evil.com'] } });
  // https://evil.com./ normalizes asymmetrically — must still hit the deny rule.
  const ev = evaluate(cfg, 'bot', 'login', { entry: { title: 'x', url: 'https://evil.com./login' } });
  assert.equal(ev.decision, 'deny', 'trailing-dot URL must match denied_entries');
  // And the same normalization applies to the host allowlist path.
  const cfg2 = cfgOf({ bot: { allowed: ['login'], allowed_hosts: ['good.com'] } });
  const ev2 = evaluate(cfg2, 'bot', 'login',
    { entry: { title: 'x', url: 'https://good.com./' }, host: 'good.com.' });
  assert.equal(ev2.decision, 'allow', 'trailing-dot host must normalize identically');
  const ev3 = evaluate(cfg2, 'bot', 'login',
    { entry: { title: 'x', url: 'https://evil.com./' }, host: 'evil.com.' });
  assert.equal(ev3.decision, 'deny');
});

test('entry restrictions — uuid: pattern matches dash-insensitively', () => {
  assert.ok(entryMatches('uuid:abcd-1234', { id: 'ABCD1234' }));
  assert.ok(!entryMatches('uuid:abcd-1234', { id: 'FFFF' }));
});

test('allowed_hosts — dot-boundary for plain names, glob for patterns', () => {
  const cfg = cfgOf({
    bot: { allowed: ['login'], allowed_hosts: ['github.com', '*.corp.local'] },
  });
  const entry = { title: 't', url: 'https://github.com/login' };
  assert.equal(evaluate(cfg, 'bot', 'login', { entry, host: 'github.com' }).decision, 'allow');
  assert.equal(evaluate(cfg, 'bot', 'login', { entry, host: 'gist.github.com' }).decision, 'allow');
  assert.equal(evaluate(cfg, 'bot', 'login', { entry, host: 'mygithub.com' }).decision, 'deny');
  assert.equal(evaluate(cfg, 'bot', 'login', { entry, host: 'ci.corp.local' }).decision, 'allow');
  const ev = evaluate(cfg, 'bot', 'login', { entry, host: 'evil.net' });
  assert.equal(ev.decision, 'deny');
  assert.match(ev.reason, /allowed_hosts/);
});

test('entryPermitted — null policy fails closed; unrestricted policy permits', () => {
  assert.equal(entryPermitted(null, { title: 'x' }), false);
  assert.equal(entryPermitted({ allowed: ['search'] }, { title: 'x' }), true);
  assert.equal(entryPermitted({ allowed_entries: ['GitHub*'] }, { title: 'GitHub Work' }), true);
  assert.equal(entryPermitted({ allowed_entries: ['GitHub*'] }, { title: 'gitlab' }), false);
});

test('hostAllowed — absent list means no restriction', () => {
  assert.equal(hostAllowed({}, 'anything.com'), true);
  assert.equal(hostAllowed(undefined, 'anything.com'), true);
  assert.equal(hostAllowed({ allowed_hosts: ['a.com'] }, ''), false);
});

test('globMatch — wildcard action patterns', () => {
  assert.ok(globMatch('db.*', 'db.list'));
  assert.ok(globMatch('*', 'anything'));
  assert.ok(globMatch('entry.*', 'entry.add'));
  assert.ok(!globMatch('db.*', 'search'));
  assert.ok(globMatch('*prod*', 'my prod db'));
});

test('resolveAgentId — flag wins over env; default fallback; charset enforced', () => {
  assert.deepEqual(resolveAgentId({}, undefined), { ok: true, agent: DEFAULT_AGENT });
  assert.deepEqual(resolveAgentId({ KEEPASS_AGENT_ID: 'bot1' }, undefined), { ok: true, agent: 'bot1' });
  assert.deepEqual(resolveAgentId({ KEEPASS_AGENT_ID: 'bot1' }, 'cli-agent'), { ok: true, agent: 'cli-agent' });
  assert.equal(resolveAgentId({ KEEPASS_AGENT_ID: 'bad id!' }, undefined).ok, false);
  assert.equal(resolveAgentId({ KEEPASS_AGENT_ID: 'a'.repeat(65) }, undefined).ok, false);
  assert.equal(resolveAgentId({ KEEPASS_AGENT_ID: 'dot.name' }, undefined).ok, false); // dots would nest TOML sections
  for (const bad of ['__proto__', 'constructor', 'prototype', '__PROTO__'])
    assert.equal(resolveAgentId({ KEEPASS_AGENT_ID: bad }, undefined).ok, false, `reserved id ${bad} must be rejected`);
});

test('agentPolicy — named → default → null resolution', () => {
  const cfg = cfgOf({ default: { allowed: ['search'] }, named: { allowed: ['*'] } });
  assert.equal(agentPolicy(cfg, 'named')?.allowed?.[0], '*');
  assert.equal(agentPolicy(cfg, 'stranger')?.allowed?.[0], 'search');
  assert.equal(agentPolicy(cfgOf({}), 'x'), null);
});
