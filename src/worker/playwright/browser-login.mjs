// playwright worker — form-login against a real browser via CDP. Despite the
// registry name it does NOT use the playwright npm package (dependency-free):
// it speaks the DevTools Protocol directly over Node's built-in WebSocket to
// a loopback Chrome endpoint, inside an isolated browser context.
//
// stdin JSON: {url, username, password, db, entry,
//   cdp?             — loopback endpoint (operator config cdp.endpoint piped
//                      by the broker; else KEEPASS_AGENT_CDP_ENDPOINT as a
//                      test hook — warns on stderr; else 127.0.0.1:9222)
//   isolated?        — '0' attaches the default context (only for CDP
//                      instances that ARE a dedicated profile; see docs)
//   settleMs?, outcomeWaitMs?, mfaWaitMs?, pollMs? — capped tuning knobs
// }
//
// Contract (AGENTS.md): exactly one JSON result on stdout —
// {success,status} | {success:false,code,detail}; secrets never printed.
// Credentials are typed only while page origin === entry URL origin
// (REDIRECT_REJECTED otherwise — in-page guards re-check at fill/submit).

import { isLoopbackCdpEndpoint } from '../../cdp/cookies.ts';
import { createCdpDriver } from './cdp-driver.ts';
import { runBrowserLogin } from './login-core.ts';

const DEFAULT_ENDPOINT = 'http://127.0.0.1:9222';

let raw = '';
process.stdin.on('data', (c) => { raw += c; if (raw.length > 1 << 16) process.exit(2); });
process.stdin.on('end', async () => {
  try {
    const j = JSON.parse(raw);
    raw = '';
    const pw = j.password ?? ''; // read once, never printed
    if (!j.url) return done(false, 'NO_URL');
    // Endpoint resolution: stdin `cdp` (operator config cdp.endpoint, piped
    // by the broker — the trusted channel) → env hook → default. The env var
    // is a TEST HOOK only: an agent env can point it at a hostile loopback
    // socket that harvests the typed credentials, so using it warns loudly
    // (same convention as KEEPASS_AGENT_HELPER_CMD/SPRITE_CMD).
    let endpoint = j.cdp;
    if (!endpoint && process.env.KEEPASS_AGENT_CDP_ENDPOINT) {
      process.stderr.write(
        'browser-login: warning: KEEPASS_AGENT_CDP_ENDPOINT override active — ' +
        'worker receives vault secrets via this endpoint\n',
      );
      endpoint = process.env.KEEPASS_AGENT_CDP_ENDPOINT;
    }
    endpoint = endpoint || DEFAULT_ENDPOINT;
    if (!isLoopbackCdpEndpoint(endpoint))
      return done(false, 'WORKER_CDP_ENDPOINT_REJECTED', 'cdp endpoint must be loopback');
    // Transport faults get one retry (policy: navigation/network errors
    // retry once; deterministic answers never do). Connect failure is a
    // transport fault — attempt twice before WORKER_CDP_UNAVAILABLE.
    let driver;
    for (let i = 0; ; i++) {
      try {
        driver = await createCdpDriver({ endpoint, isolated: j.isolated !== '0' });
        break;
      } catch (e) {
        if (i === 1) return done(false, 'WORKER_CDP_UNAVAILABLE', msg(e));
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    try {
      const r = await runBrowserLogin(
        { url: j.url, username: j.username || '', password: pw },
        driver,
        {
          settleMs: num(j.settleMs), outcomeWaitMs: num(j.outcomeWaitMs),
          mfaWaitMs: num(j.mfaWaitMs), pollMs: num(j.pollMs),
        },
      );
      if (!r.ok) {
        // MFA → leave the page open (user completes the challenge, then the
        // agent re-runs login) but blank the typed password first. Any other
        // failure → tear the page/context down.
        if (r.code === 'WORKER_MFA_REQUIRED') {
          await driver.clearPasswordField().catch(() => {});
          driver.detach();
        } else await driver.dispose().catch(() => {});
        return done(false, r.code, r.detail);
      }
      // Success → the isolated context (page + cookie jar) stays alive at the
      // endpoint: that live context IS the session handle — blank the typed
      // password before letting go of the page. Persisting it into the KDBX
      // entry reuses the login-capture contract — see docs/security.
      await driver.clearPasswordField().catch(() => {});
      driver.detach();
      return done(true, r.status);
    } catch (e) {
      await driver.dispose().catch(() => {});
      return done(false, 'WORKER_ERROR', msg(e));
    }
  } catch {
    return done(false, 'WORKER_ERROR');
  }
});

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

function msg(e) {
  return String((e && e.message) || e).slice(0, 120);
}

function done(ok, code, detail) {
  const out = ok
    ? { success: true, status: code }
    : { success: false, code, ...(detail ? { detail: String(detail).slice(0, 200) } : {}) };
  process.stdout.write(JSON.stringify(out));
  process.exit(ok ? 0 : 1);
}
