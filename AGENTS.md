# AGENTS.md

**keepass-agent** — KeePass 2 credential gateway for AI agents. Secrets move
on stdin only: master key → KPScript/PyKeePass, entry password → approved
worker stdin. Nothing secret is ever returned to the agent or printed.

TypeScript runs **directly on Node ≥22.18 (or ≥23.6) via native type-stripping
— there is no build step**. ESM only. Runtime has exactly one npm dependency
(`iconv-lite`, Windows KPScript CP949 path only). Python helpers use
Python ≥3.10 + pykeepass.

## Commands

```bash
node src/cli/kp.ts            # run the CLI — no build
npm test                      # node --test "tests/**/*.test.ts"
npm run typecheck             # tsc --noEmit (strict, nodenext)
npm run lint:py               # ruff check src/keepass (skips if ruff absent)
npm run check                 # typecheck + test
npm run docs:dev              # VitePress dev server for docs/
npm run docs:build            # VitePress static build → docs/.vitepress/dist
npm run docs:preview          # serve the built docs site
```

Launchers: `bin/kp` (bash), `bin/kp.cmd`, `bin/kp.ps1` — all exec
`node src/cli/kp.ts`. On Windows `npm link`/`npm i -g` generates its own shims.

Python helper setup (required for `db create`, `entry add`, and all
KPScript-free POSIX paths):

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
```

KeePass 2 + KPScript binaries go in `tools/keepass/` — see
`tools/keepass/README.md`. **Never commit the binaries (GPL).** CI never
installs them; KPScript-dependent tests are designed to skip.

## Security invariants — do not regress

1. **Secrets on stdin only.** Master keys and entry passwords must never
   appear in argv, env vars, TOML config, or stdout. KPScript gets the key via
   `-keyprompt` stdin (`keyStdin`); workers get `{...meta, password}` JSON via
   stdin.
2. **No secret output channels.** Helper and worker stderr must not become a
   secret/log channel — `provider/pykeepass.ts` discards helper stderr
   entirely, and
   `broker.ts` redacts the piped password/username from worker output
   (`[redacted]`) before anything reaches the CLI. Redaction covers direct
   echo plus casing/whitespace-insertion variants, applied both to raw
   output and to parsed `code`/`detail`/`status` fields — it is a
   **best-effort backstop, not a guarantee**: encoding-level variants
   (base64, NFC/NFD, URL-encoding, …) are not detected. Workers must never
   write secrets to stdout/stderr at all.
3. **Worker allowlist.** New workers must be registered in
   `src/worker/registry.ts` — `resolveWorker` maps a fixed name → file inside
   `src/worker/`; arbitrary paths/commands are rejected
   (`UNSUPPORTED_WORKER`).
4. **Session files are encrypted.** `~/.config/keepass-agent/sessions/*.json`
   payloads are DPAPI-protected on Windows (CurrentUser scope, PowerShell
   stdin) or AES-256-GCM `localCrypt` elsewhere — never write plaintext
   sessions.
5. **Worker egress + output contract.** Before any secret is piped, the
   broker validates the entry URL: `https:` any host, `http:` loopback only
   (`127.0.0.1`/`localhost`/`[::1]`) — everything else is
   `WORKER_URL_REJECTED` (`entry add` may store such URLs with a warning,
   but `login` never fires). Workers must **not follow redirects on
   credentialed requests** — local-test uses `redirect:'manual'` →
   `REDIRECT_REJECTED`; the playwright (browser-login) worker types
   credentials ONLY while `location.origin === origin(entry.url)`: a
   post-navigation origin change, ANY cross-origin submit destination
   (`<form action>` or `button/input[formaction]`, re-checked in-page at
   click time), or an origin drift caught by the in-page guard at
   fill/submit time all fail `REDIRECT_REJECTED` before/instead of
   typing. SSO/OAuth chains that leave the entry origin are out of scope
   (allowed-domain lists are a follow-up). The playwright worker also runs
   logins in an **isolated browser context** (CDP
   `Target.createBrowserContext` — fail-closed, no default-profile
   fallback) so sessions never mix with the user's; `login --no-isolate`
   requires operator opt-in `cdp.allow_default_context=true`
   (dedicated-profile CDP instances only). Its CDP endpoint is
   operator-managed — `cdp.endpoint` in config.toml (loopback-validated,
   default `http://127.0.0.1:9222`), piped via broker stdin; there is no
   `login --cdp` flag because an agent-chosen endpoint is a hostile-socket
   credential sink. `KEEPASS_AGENT_CDP_ENDPOINT` is a warned test-hook
   only. Workers
   print exactly one JSON result — `{success,status}` or
   `{success:false,code,detail}`. Codes must be known worker codes or
   custom `WORKER_*` namespaced codes — broker-owned (`WORKER_TIMEOUT`,
   `WORKER_SPAWN_FAILED`, `WORKER_OUTPUT_INVALID`, `WORKER_URL_REJECTED`)
   and system codes (`UNLOCK_REQUIRED`, `AUTHENTICATION_FAILED`, …)
   cannot be spoofed and yield `WORKER_OUTPUT_INVALID`. The broker drops
   unknown fields, caps `detail` at 200 chars, strips control chars
   (ANSI/OSC escapes) and collapses absolute paths in returned text, and
   on timeout kills the whole process tree (taskkill /T /F on Windows,
   process-group SIGKILL on POSIX).
6. **Cookies are authentication-grade; remote channels are argv-only.**
   `entry sync-cookies`/`login-capture` must go through the same one-time
   token web approval as unlock (no direct CLI harvest), CDP endpoints are
   loopback-only (`isLoopbackCdpEndpoint`), and cookie-domain matching is
   dot-boundary (`domainMatch` — `mygithub.com` ≠ `github.com`). `db sync`
   and `tools/relay-unlock.mjs` never build shell strings for `sprite
   exec` — remote commands travel as argv entries and `--remote`/`--sprite`
   are validated to metacharacter-free charsets. Pulls replace the local
   KDBX atomically (tmp → md5 verify → `.bak` → rename). The relay is a
   pure proxy: it serves the remote unlock page verbatim and forwards the
   encrypted `p` body byte-for-byte — plaintext passwords must never
   transit it.
7. **Policy is deny-by-default; audit records carry no secrets.** Every `kp`
   command (except `config`/`help`/`doctor`/`mcp` — the diagnostics and the
   MCP adapter launch need no grant; each MCP *tool call* is still evaluated)
   against `[agents.<id>]`/`[policy]` from config.toml — the caller's
   identity is *declared* (`--agent`/`KEEPASS_AGENT_ID`, fallback
   `default`), not authenticated. Unlisted actions → `POLICY_DENIED`;
   `require_approval` on an action without a web-approval channel →
   `POLICY_APPROVAL_REQUIRED`. `pipeSecretToWorker` re-evaluates at the pipe
   boundary (`policyGate`). `~/.config/keepass-agent/audit.log` is
   append-only JSONL `{ts, agent, action, target, decision, result_code,
   db}` — a fixed whitelist schema; secrets/passwords/cookie values must
   never be passed to `audit()`. The legacy `[security]` booleans were
   removed: their behaviors are unconditional invariants, not options.
8. **Hardened Mode is fail-closed and secret-free across IPC.** When
   `hardened.enabled=true`, all credential-touching commands go through the
   Credential Service (`src/service/`, a separate OS principal) over the
   capability-token handshake — a service that is down, an unauthenticated
   caller, or an unmet isolation check MUST fail with an explicit
   `HARDENED_*` code and MUST NOT fall back to the in-process path. The IPC
   wire never carries secrets: `login` is executed entirely service-side
   (the service resolves the entry, re-checks policy, spawns the worker,
   and pipes the secret itself). Approval flows (unlock/entry add/cookies/
   db create) run the web round-trip inside the service — the master key
   travels browser → service, never through the agent process. Standard
   Mode (`hardened.enabled=false`, the default) must stay byte-equivalent.

## Module layout (`src/`)

| Path | Role |
| --- | --- |
| `cli/kp.ts` | CLI router — parse → dispatch → single JSON result on stdout |
| `config/config.ts` | TOML config load/validate/atomic save (`~/.config/keepass-agent/`) |
| `database/manager.ts` | KDBX registry only (add/remove/default/info) — never touches keys or backends |
| `provider/provider.ts` | `CredentialProvider` seam — unified contract + `createProvider(kpscript)` factory (win32 → KPScript, else → PyKeePass) + frozen error-code namespace |
| `provider/kpscript.ts` | KPScript backend (win32) — verify/list/getSecret; write ops inherited from PyKeePass |
| `provider/pykeepass.ts` | PyKeePass backend — all ops via `src/keepass/*.py` helpers (stdin JSON → stdout JSON); also the write path on Windows |
| `keepass/kpscript.ts` | KPScript spawn wrapper — stdin key, output validation, CP949 (low-level runner used by `provider/kpscript.ts`) |
| `keepass/*.py` | PyKeePass helpers (create/add/update/helper) — KPScript-free path |
| `master-key/manager.ts` | per-DB unlock state; provider.verifyKey → encrypted session |
| `security/dpapi.ts` | session store: DPAPI (win32) / AES-256-GCM localCrypt (POSIX) |
| `broker/broker.ts` | trusted path: list/search entries, pipe secret → worker stdin (optional `policyGate` re-check) |
| `policy/engine.ts` | declared agent identity + deny-by-default `evaluate(agent, action, target)`; entry/host restrictions |
| `policy/audit.ts` | append-only JSONL audit log (schema whitelist, mode 600, size rotation) |
| `unlock-server/server.ts` | loopback-only web UI for master-key entry (one-time token) |
| `mgmt/server.ts` | `kp ui` operator console — loopback mgmt web server + JSON API (`web/mgmt-ui/`). One-time page token in launch URL (consumed on serve) + apiToken (`x-kp-ui-token` header; `kpui` HttpOnly SameSite=Strict cookie for reloads) + Host/Origin + POST-only mutations; `x-kp-agent` header → deny-by-default `ui.*` gate, absent → `operator` (bypasses `[agents.*]` unless `[agents.operator]` configured; `ui.agents.write` is OPERATOR_ONLY for declared agents); every call audits `ui.*`; approvals capped (UNLOCK_BUSY). Unlock delegates to the existing approval flow; hardened routes status/audit/lock/approval over service IPC |
| `cdp/cookies.ts` | minimal CDP cookie reader / page opener + loopback endpoint policy + dot-boundary domain match |
| `cdp/client.ts` | generic CDP client — flat-protocol WebSocket (`call`/`waitEvent`), loopback-verified `browserWebSocketUrl`, `openCdpPage` (isolated browser context, fail-closed) + `closeCdpPage` |
| `mcp/` | MCP adapter — `server.ts` (JSON-RPC 2.0 over stdio: initialize/ping/tools.list/tools.call, handshake-era revisions 2024-11-05→2025-11-25, sequential dispatch, **stdout is protocol-only** — logs go to stderr) + `tools.ts` (tool defs routed into the same modules the CLI uses; every call `evaluate()`d under the canonical CLI action — `search`/`unlock`/`status`/`login`/`lock`/`audit.read` — and writes one audit record `mcp.<tool>`; hardened mode routes over service IPC). Session agent identity: initialize `params.agent` → `[mcp.clients.<clientInfo.name>]` → `kp mcp --agent`/`KEEPASS_AGENT_ID` → `mcp.agent` → `default`. Tool surface is structurally secret-free (metadata/status/approval-URL only) |
| `worker/registry.ts` | worker allowlist (+ per-worker `timeoutMs`) + `local-test`/`playwright` workers |
| `worker/playwright/` | CDP browser-login worker (name kept; no playwright npm dep — raw DevTools Protocol over Node's WebSocket): `browser-login.mjs` entry → `login-core.ts` (origin-gated fill incl. formaction-destination checks, outcome classification — `cookie`/new-HttpOnly is the only strong signal; 1-retry policy; driver-injected for tests) → `cdp-driver.ts` (page ops via `src/cdp/client.ts`; `conn.call` capped 30s; pw field blanked before detach). stdin takes `cdp` (from `cdp.endpoint` config, NOT a flag), `isolated` (gated by `cdp.allow_default_context`), `*WaitMs`/`pollMs`. Codes: known set + `WORKER_{MFA_REQUIRED,CDP_*,NAVIGATION_FAILED,NO_LOGIN_FORM,OUTCOME_UNCERTAIN,EGRESS_REJECTED}` |
| `service/` | Credential Service (Hardened Mode): `mode` (endpoint/token paths), `protocol` (JSON-lines wire), `auth` (capability token + HMAC handshake), `acl` (POSIX stat checks + icacls allow-list vs `allowed_sids`), `peer` (optional POSIX peer-uid verify), `server` (socket/pipe listener), `handlers` (ops + service-side policy re-check/audit + post-parse submission gate), `service.ts` (daemon), `client` (kp-side IPC client). `hardened.*` keys are operator-managed — `config set` rejects them (`CONFIG_KEY_READONLY`) |

## Test conventions

- `node --test` (no framework). Each `.test.ts` runs in its own process.
- **Never touch the real home dir.** Any test needing sessions/config imports
  `tests/fixtures/tmp-home.ts` **first** — it points HOME/USERPROFILE at a
  mkdtemp dir before `config.ts` binds `homedir()`, and cleans up via
  `after()`. Mocks live inside `TEST_HOME` (unique per file/process).
- **KPScript skip-gate**: integration tests check `existsSync(KPScript.exe)`
  and pass `{ skip: ... }` — CI has no GPL binaries.
- **POSIX helper injection**: `pipeSecretToWorker`/unlock verification call
  `kdbx_helper.py` on non-Windows (via `PyKeePassProvider` —
  `helperCmd()` lives in `src/provider/pykeepass.ts`). Tests set
  `KEEPASS_AGENT_HELPER_CMD` (JSON argv array) to
  `tests/fixtures/mock-helper.mjs`, which speaks the same protocol. When the
  env var is unset, behavior is unchanged. **Test-only hook**: it routes the
  master key to the specified process's stdin — never set it outside tests;
  `helperCmd()` emits a one-time stderr warning whenever it is active.
- **Sprite exec injection**: `db sync` tests set `KEEPASS_AGENT_SPRITE_CMD`
  (JSON argv array) to `tests/fixtures/mock-sprite.mjs`, which emulates
  `sprite exec` against a local fake remote FS (and a real local HTTP
  request for `curl`, used by the relay tests). Same unset-means-unchanged
  and one-time-warning convention as `KEEPASS_AGENT_HELPER_CMD` — never set
  it outside tests.
- **CDP endpoint test hook**: `KEEPASS_AGENT_CDP_ENDPOINT` overrides the
  browser-login worker's CDP endpoint (used to point tests at the fake
  Chrome in `tests/fixtures/mock-cdp.mjs`). Same unset-means-unchanged
  convention as `KEEPASS_AGENT_HELPER_CMD`/`KEEPASS_AGENT_SPRITE_CMD` —
  the worker types vault secrets into whatever browser the endpoint owns,
  so never set it outside tests; `kp login` and the worker each emit a
  one-time stderr warning when it supplies the endpoint. Production
  endpoint: `cdp.endpoint` config (or the `127.0.0.1:9222` default).
- **Service selftest hook**: `KEEPASS_AGENT_SERVICE_SELFTEST` skips the
  Credential Service's startup ACL self-check so tests can run it under the
  same OS principal — never set it outside tests. `KEEPASS_AGENT_CONFIG`
  points the service (or any kp process) at an explicit config.toml path;
  unset means the homedir-derived default.
