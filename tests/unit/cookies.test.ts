// Cookie-domain boundary + CDP endpoint policy tests.
// Import order matters: tmp-home must evaluate before any src module.
import { TEST_HOME } from '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { domainMatch, isLoopbackCdpEndpoint, DEFAULT_CDP_ENDPOINT } from '../../src/cdp/cookies.ts';
import { SESSION_DIR } from '../../src/config/config.ts';

assert.ok(SESSION_DIR.startsWith(TEST_HOME), `SESSION_DIR escaped TEST_HOME: ${SESSION_DIR}`);

test('domainMatch — exact host and dot-boundary subdomains match', () => {
  // cookie domain ↔ entry host, either direction, at a dot boundary
  assert.equal(domainMatch('github.com', 'github.com'), true);
  assert.equal(domainMatch('.github.com', 'github.com'), true);   // leading-dot cookie form
  assert.equal(domainMatch('www.github.com', 'github.com'), true); // cookie scoped to subdomain of entry host
  assert.equal(domainMatch('sub.github.com', 'github.com'), true);
  assert.equal(domainMatch('github.com', 'www.github.com'), true); // parent cookie covers entry host
  assert.equal(domainMatch('a.b.github.com', 'github.com'), true);
});

test('domainMatch — suffix lookalikes and off-boundary domains never match', () => {
  assert.equal(domainMatch('github.com', 'mygithub.com'), false);  // entry must not harvest github.com cookies
  assert.equal(domainMatch('mygithub.com', 'github.com'), false);  // nor the reverse
  assert.equal(domainMatch('github.com.evil.net', 'github.com'), false);
  assert.equal(domainMatch('github.com', 'github.com.evil.net'), false);
  assert.equal(domainMatch('evilgithub.com', 'github.com'), false);
  assert.equal(domainMatch('github.com', 'github.comm'), false);
  assert.equal(domainMatch('notgithub.com', 'github.com'), false);
});

test('domainMatch — case/edge hygiene', () => {
  assert.equal(domainMatch('GitHub.COM', 'github.com'), true);
  assert.equal(domainMatch('github.com', 'GITHUB.COM'), true);
  assert.equal(domainMatch('', 'github.com'), false);
  assert.equal(domainMatch('github.com', ''), false);
  assert.equal(domainMatch('', ''), false);
});

test('isLoopbackCdpEndpoint — loopback hosts pass on any port (T11)', () => {
  assert.equal(isLoopbackCdpEndpoint(DEFAULT_CDP_ENDPOINT), true);
  assert.equal(isLoopbackCdpEndpoint('http://127.0.0.1:9222'), true);
  assert.equal(isLoopbackCdpEndpoint('http://127.0.0.1:13337'), true);
  assert.equal(isLoopbackCdpEndpoint('http://localhost:9222'), true);
  assert.equal(isLoopbackCdpEndpoint('http://[::1]:9222'), true);
  assert.equal(isLoopbackCdpEndpoint('https://127.0.0.1:9222'), true);
});

test('isLoopbackCdpEndpoint — remote hosts, private IPs, and odd forms are refused', () => {
  assert.equal(isLoopbackCdpEndpoint('http://evil.com:9222'), false);
  assert.equal(isLoopbackCdpEndpoint('http://192.168.1.5:9222'), false);
  assert.equal(isLoopbackCdpEndpoint('http://10.0.0.9:9222'), false);
  assert.equal(isLoopbackCdpEndpoint('http://169.254.169.254/'), false); // cloud metadata SSRF
  assert.equal(isLoopbackCdpEndpoint('http://127.0.0.1.evil.com'), false);
  assert.equal(isLoopbackCdpEndpoint('http://localhost.evil.com'), false);
  assert.equal(isLoopbackCdpEndpoint('http://0.0.0.0:9222'), false);
  assert.equal(isLoopbackCdpEndpoint('http://[::]:9222'), false);
  assert.equal(isLoopbackCdpEndpoint('file:///etc/passwd'), false);
  assert.equal(isLoopbackCdpEndpoint('not a url'), false);
});
