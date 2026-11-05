// local-test worker — stdin {url,username,password,db,entry}
// performs a real HTTP form login against a local test endpoint
// (default: POST /login expecting 200). Used for E2E without external services.
//
// Worker contract (see AGENTS.md): exactly one JSON result on stdout —
// {success,status} or {success:false,code,detail}. Secrets never reach
// stdout/stderr, and a request carrying credentials never follows redirects
// (redirect:'manual' → REDIRECT_REJECTED).

let raw = '';
process.stdin.on('data', (c) => { raw += c; if (raw.length > 1 << 16) process.exit(2); });
process.stdin.on('end', async () => {
  try {
    const j = JSON.parse(raw);
    raw = '';
    const pw = j.password; // read once, never printed
    if (!j.url) return done(false, 'NO_URL');
    const body = new URLSearchParams({ username: j.username || '', password: pw }).toString();
    const r = await fetch(j.url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(20_000),
    });
    if (r.type === 'opaqueredirect' || (r.status >= 300 && r.status < 400))
      return done(false, 'REDIRECT_REJECTED', 'credential request was redirected');
    const text = (await r.text()).slice(0, 200);
    const ok = r.ok && !/invalid|error|fail/i.test(text);
    return ok ? done(true, 'authenticated') : done(false, 'CREDENTIALS_REJECTED', `http ${r.status}`);
  } catch {
    return done(false, 'WORKER_ERROR');
  }
});

function done(ok, code, detail) {
  const out = ok
    ? { success: true, status: code }
    : { success: false, code, ...(detail ? { detail: String(detail).slice(0, 200) } : {}) };
  process.stdout.write(JSON.stringify(out));
  process.exit(ok ? 0 : 1);
}
