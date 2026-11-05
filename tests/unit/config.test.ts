// Preventive home isolation — pure-function tests today, but importing
// tmp-home first guarantees any future session/config writes stay in a
// throwaway home and cleans it up via after().
import '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseToml, validateConfig, normalize, tomlEscape, defaultConfig } from '../../src/config/config.ts';
import { searchEntries, normalizeHost } from '../../src/broker/broker.ts';
import { validateSecretOutput } from '../../src/keepass/kpscript.ts';
import { resolveWorker } from '../../src/worker/registry.ts';

test('toml parse — sections, scalars, unicode paths, arrays', () => {
  const c = parseToml(`
[keepass]
executable = "C:/Program Files/KeePass Password Safe 2/KeePass.exe"
default_database = "personal"

[databases.personal]
path = "D:/내 문서/개인 비밀.kdbx"
key_file = "D:/Secrets/k f.keyx"
session_timeout = 900

[policy]
audit_max_bytes = 2097152

[agents.scout]
allowed = ["search", "db.list"] # allowed actions
denied_entries = ["*prod*"]
`);
  assert.equal(c.keepass.default_database, 'personal');
  assert.equal(c.databases.personal.path, 'D:/내 문서/개인 비밀.kdbx');
  assert.equal(c.databases.personal.key_file, 'D:/Secrets/k f.keyx');
  assert.equal(c.databases.personal.session_timeout, 900);
  assert.equal(c.policy.audit_max_bytes, 2097152);
  assert.deepEqual(c.agents.scout.allowed, ['search', 'db.list']);
  assert.deepEqual(c.agents.scout.denied_entries, ['*prod*']);
});

test('normalize — agents/policy sections survive; dropped [security] keys are ignored', () => {
  const c = normalize({
    agents: { bot: { allowed: ['search'], denied_entries: 'prod*' } },
    policy: { audit_max_bytes: 2048 },
    security: { allow_raw_secret_output: true }, // legacy key — must be dropped
  });
  assert.deepEqual(c.agents.bot.allowed, ['search']);
  assert.deepEqual(c.agents.bot.denied_entries, ['prod*']);
  assert.equal(c.policy.audit_max_bytes, 2048);
  assert.equal((c as any).security, undefined);
});

test('toml — __proto__/prototype-key sections and keys cannot pollute Object.prototype', () => {
  const before = ({} as any).allowed;
  const c = parseToml(`
[agents.__proto__]
allowed = ["*"]

[agents.constructor]
allowed = ["*"]

[agents.ok]
prototype = ["x"]
hasOwnProperty = ["y"]
__proto__ = ["z"]
`);
  assert.equal(({} as any).allowed, before, 'Object.prototype must be untouched');
  assert.equal(({} as any).constructor?.allowed, undefined);
  // The poisoned sections are diverted to a sink — they never land in the tree.
  assert.ok(!Object.hasOwn(c.agents, '__proto__'));
  assert.ok(!Object.hasOwn(c.agents, 'constructor'));
  // Ordinary property-name keys still parse as own props (harmless shadow).
  assert.ok(c.agents.ok);
  // evaluate() must not see a poisoned policy through inheritance either.
  const norm = normalize(c);
  assert.ok(!Object.hasOwn(norm.agents, '__proto__'));
  assert.ok(!Object.hasOwn(norm.agents, 'constructor'));
});

test('toml — array items containing " #" are not misparsed as comments', () => {
  const c = parseToml(`
[agents.bot]
allowed_entries = ["prod #1", "b #c", 'd #e']
allowed = ["search"] # real trailing comment
`);
  assert.deepEqual(c.agents.bot.allowed_entries, ['prod #1', 'b #c', 'd #e']);
  assert.deepEqual(c.agents.bot.allowed, ['search']);
});

test('defaultConfig — seeds agents.default allow-all for first-run usability', () => {
  const c = defaultConfig();
  assert.deepEqual(c.agents.default?.allowed, ['*']);
});

test('validate — agent names + policy bounds', () => {
  const c = normalize({ databases: {} });
  c.agents = { 'bad.name': { allowed: ['search'] } };
  c.policy.audit_max_bytes = 5;
  const errs = validateConfig(c);
  assert.ok(errs.some((e) => e.includes('agents.bad.name')));
  assert.ok(errs.some((e) => e.includes('audit_max_bytes')));
});

test('toml round-trip — escape handles backslashes/quotes', () => {
  const s = tomlEscape('C:\\path\\"quoted"\\x');
  assert.equal(JSON.parse(s), 'C:\\path\\"quoted"\\x');
});

test('validate — bad alias, non-absolute path, traversal, bad host', () => {
  const c = normalize({
    databases: { 'bad alias!': { path: 'rel/x.kdbx' }, ok: { path: 'C:/a/../b.kdbx' } },
    unlock: { host: '0.0.0.0', port: 70000 },
  });
  const errs = validateConfig(c);
  assert.ok(errs.some((e) => e.includes('alias')));
  assert.ok(errs.some((e) => e.includes('absolute')));
  assert.ok(errs.some((e) => e.includes("..")));
  assert.ok(errs.some((e) => e.includes('loopback')));
  assert.ok(errs.some((e) => e.includes('port')));
});

test('search — title, username, domain normalization', () => {
  const es = [
    { id: '1', title: 'GitHub Work', username: 'w@x.com', url: 'https://github.com/login' },
    { id: '2', title: 'GitHub Personal', username: 'p@x.com', url: 'https://www.github.com/' },
    { id: '3', title: 'github evIl', username: 'e@x.com', url: 'https://github.com.evil.net/' },
  ];
  assert.equal(searchEntries(es, { title: 'github work' }).length, 1);
  assert.equal(searchEntries(es, { username: 'w@x' }).length, 1);
  const site = searchEntries(es, { site: 'github.com' });
  assert.deepEqual(site.map((e) => e.id).sort(), ['1', '2']); // evil.net must NOT match
  assert.equal(searchEntries(es, { site: 'github.com', username: 'w@x' }).length, 1);
});

test('normalizeHost — strips scheme/www', () => {
  assert.equal(normalizeHost('https://www.GitHub.com/a'), 'github.com');
  assert.equal(normalizeHost('github.com'), 'github.com');
  assert.equal(normalizeHost(''), null);
});

test('secret output validation — diagnostics, multiline, oversize rejected', () => {
  assert.equal(validateSecretOutput('hunter2\n').ok, true);
  assert.equal(validateSecretOutput('pä$$wörd™').ok, true);
  assert.equal(validateSecretOutput('E: something failed').ok, false);
  assert.equal(validateSecretOutput('line1\nline2\n').ok, false);
  assert.equal(validateSecretOutput('x'.repeat(5000)).ok, false);
  assert.equal(validateSecretOutput('  spaced  ').ok, true);
});

test('worker allowlist — only registered names, no arbitrary paths', () => {
  assert.equal(resolveWorker('local-test').ok, true);
  assert.equal(resolveWorker('C:/evil.exe').ok, false);
  assert.equal(resolveWorker('../../etc/passwd').ok, false);
  assert.equal(resolveWorker('random').ok, false);
});
