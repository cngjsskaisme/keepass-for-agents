---
title: Security implementation reference
description: Detailed threat model, IPC, ACL, browser worker, and audit implementation notes.
---

::: tip Reader-friendly overview
Start with [Security and limitations](/security) if you are choosing a mode or configuring an agent. This page retains the detailed implementation notes for reviewers and maintainers.
:::

# Security Model

## Hardened Mode (Credential Service isolation, opt-in)

Standard Mode trusts the OS principal that runs `kp`. Hardened Mode moves
every credential-touching operation into a **separate OS principal** — the
Credential Service (`src/service/`). `kp` becomes a thin IPC client for those
operations; a same-UID process (including the agent) can no longer read
session files, the service's memory, or — when the vault ACL is applied —
the KDBX itself. Opt-in via `hardened.enabled=true` and **fail-closed**:
service down, IPC auth failure, or an unmet isolation check is an explicit
`HARDENED_*` error — never a silent Standard-Mode fallback.

### Principal model

Three roles, provisioned as distinct OS accounts:

- **Operator** — the human. Owns config.toml, runs the KeePass GUI, performs
  `db sync` (needs KDBX read access), approves unlocks in the browser.
- **Agent** — the untrusted caller. May only *request* operations over IPC;
  receives metadata and sanitized worker results, never secret material.
- **Service** — `node src/service/service.ts` under a dedicated account.
  Owns sessions (its own `SESSION_DIR` + DPAPI CurrentUser/localCrypt scope),
  verifies master keys, reads the KDBX, and spawns workers itself.

### IPC (authenticated, secret-free)

- Transport: POSIX unix socket (`chmod 0660` — Linux enforces write
  permission on connect; group = agent group) or Windows named pipe
  (`\\.\pipe\keepass-agent-svc`).
- Authentication: 256-bit **capability token** written by the service to a
  token file; callers prove possession via HMAC-SHA256(token, server-nonce).
  The token file's filesystem ACL (POSIX ≤0640 / NTFS restricted) IS the
  caller-authorization boundary — Node cannot set a named-pipe DACL, so on
  Windows the token read is the kernel-enforced check.
- Optional POSIX peer verification (`hardened.peer_verify`): `strict` mode
  resolves the connecting peer's uid via procfs+`ss -xp` and requires it in
  `hardened.allowed_uids` (service refuses to start when strict is set with
  an empty list). Pure-Node has no SO_PEERCRED — a native peer-credential
  addon is the documented future seam.
- Windows file-ACL checks are an **allow-list**, not a deny-list: every
  principal granted on the token file and each KDBX must appear in
  `hardened.allowed_sids` (icacls display form or raw sid). Unset → the
  check fails closed (`allowed_sids_unconfigured`); any foreign principal —
  `INTERACTIVE`, `NETWORK`, app-container sids, anything — is `HARDENED_ACL_UNMET`.
- JSON-lines protocol; no op returns secrets. `login` is executed by the
  service end-to-end (resolve entry → policy re-check → spawn worker → pipe
  secret → sanitize result); only `{ok,status|code,detail}` crosses the wire.
- The service **re-evaluates policy** on every op against the declared agent
  id and writes to its own (agent-unreadable) audit log — a bypassed CLI
  cannot skip either layer. Approval ops additionally run a **post-parse
  submission gate** (`makeSubmissionGate`): `evaluate()` is re-checked
  against the *submitted* values (entry url/title, cookies domain/uuid,
  unlock db) and the final payload must match the approved request —
  prefill/target drift → `POLICY_DENIED` (403 to the page, token stays alive).

### Isolation checks (fail-closed gate)

Before any service-routed command the client verifies:

- token file exists and has no other-access permission
  (`HARDENED_ACL_UNMET` otherwise)
- every touched KDBX has no 'other' bits (POSIX) or only allow-listed NTFS
  principals (`hardened.allowed_sids` via `icacls`)
- `hardened.service_uid` (POSIX, optional): KDBX owner uid must equal it,
  proving the agent doesn't own the vault

The service additionally self-checks its socket dir (POSIX 0750 pre-bind),
token file, and session dir at startup and dies on failure (skippable only
via the `KEEPASS_AGENT_SERVICE_SELFTEST` test hook — emits a stderr warning).

Mode toggling is operator-only: `kp config set hardened.*` is rejected with
`CONFIG_KEY_READONLY` (audited) — a same-UID caller cannot `config set` its
way out of hardened mode. `hardened.enabled` flips only by editing
config.toml directly (change control = OS file permissions, same as policy).

### What still crosses the agent process in hardened mode

Nothing secret. The web-approval flows run **inside** the service (the
browser posts the master key to the service's loopback server directly);
the CLI only forwards the approval URL to the user's browser. `db sync`
moves only the *encrypted* KDBX file — it stays local and works for any
principal with read access; an agent without it gets
`HARDENED_KDBX_ACCESS_DENIED`.

### Structural limits (documented, not claimed)

- **Approval is not human-proof.** The approval URL is a loopback GET —
  any local principal that can see the URL (a same-UID agent included) can
  fetch the page and mechanically complete the form. The approval proves
  *some local principal consented within the token TTL*, not necessarily a
  human. This limitation is inherited from Standard Mode. Follow-up
  recommendation: a human-only channel (PIN readout, OS-native consent
  dialog, or second-channel confirmation) so approval proves a person, not
  a process.
- **Attempt-exhaustion sabotage.** A token-holder can burn the 5-attempt
  cap and invalidate a pending approval (DoS, not a leak) — the same is
  true in Standard Mode; the token's short TTL bounds the window.
- The unlock/approval server tries `cfg.unlock.port` first and falls back
  to an **ephemeral port** on EADDRINUSE so concurrent approvals cannot
  collide or be occupied by a squatter; the served URL always carries the
  actual bound port.

## MCP adapter (`src/mcp/`)

The MCP server (`kp mcp` / `node src/mcp/server.ts`) is a second transport
into the same gateway — JSON-RPC 2.0 over stdio, Node built-ins only.

- **stdout is protocol-only.** Every line is a JSON-RPC frame; all
  diagnostics go to stderr.
- **Structurally secret-free surface.** The exposed tools
  (`search_entries`/`request_unlock`/`session_status`/`request_login`/
  `logout`/`revoke_session`/`audit_tail`) call only metadata-level and
  status-level APIs: `listEntries` (metadata only), `pipeSecretToWorker`
  (sanitized worker result), the web-approval channel (URL only), and
  hardened IPC (secret-free by design). Response schemas follow the CLI
  JSON family — `password`/`secret`/`cookie`/`master` fields are absent by
  construction; tests assert this per tool.
- **Same policy model.** Each `tools/call` is `evaluate()`d
  deny-by-default under the canonical CLI action name
  (`search`/`unlock`/`status`/`login`/`lock`/`audit.read`), including the
  phase-2 entry/host re-check for `request_login` and the broker-side
  `policyGate` re-evaluation at the pipe boundary. Every call writes
  exactly one audit record with action `mcp.<tool>`.
- **Declared identity.** The session's agent id resolves at `initialize`:
  `params.agent` → `[mcp.clients.<clientInfo.name>]` → `kp mcp --agent` /
  `KEEPASS_AGENT_ID` → `mcp.agent` → `default`. Same self-declared
  (not authenticated) model as `--agent`; invalid ids fail initialize.
  Scoping an MCP client to its own least-privilege agent id is done via
  the `[mcp.clients.*]` mapping.
- **`request_unlock` collects no master key.** It returns the one-time
  approval URL (`awaiting_user_input`); the human completes the loopback
  web flow. `unlock_method` values other than `local-web` are refused —
  launching the KeePass GUI is outside the MCP surface. The only external
  action the adapter performs is the optional browser auto-open
  (`unlock.auto_open_browser`), same as the CLI.
- **Hardened Mode supported.** Under `hardened.enabled` the tools route
  through the Credential Service (agent → MCP → service) with the same
  pre-flight ACL gate and `HARDENED_*` fail-closed codes — never a
  standard-mode fallback. The service additionally re-checks policy
  service-side, so a hand-rolled MCP client cannot skip the gate.
- Requests before `initialize` are rejected (-32002); malformed JSON,
  non-object messages, batches, unknown methods/tools get the standard
  JSON-RPC errors; notifications never produce a response.
- Dispatch is sequential per session — a credential gateway has no need
  for concurrent mutation, and serialization keeps audit ordering exact.

## Implemented (Standard Mode)
- Passwords never in argv/env/TOML/stdout — stdin only (KPScript & workers)
- Master key persisted only DPAPI-encrypted (CurrentUser), TTL per DB
- KPScript output validated (diagnostic/multiline/oversize rejected); raw never logged
- Worker allowlist — no arbitrary executables
- Worker egress policy — before a secret is piped, the broker validates the entry URL: `https:` any host, `http:` loopback only, else WORKER_URL_REJECTED. `entry add` stores other URLs but reports a `warning` (intranet http compatibility).
- Redirect contract — workers must not follow redirects on credentialed requests; `local-test` uses `redirect:'manual'` and fails REDIRECT_REJECTED.
- Browser-login (`playwright`) worker redirect contract — credentials are typed only while `location.origin === origin(entry.url)`: post-navigation origin drift (settle-polled), ANY cross-origin submit destination (every submitter's effective target: IDL *form owner* action — covers `form=` attribute re-association — plus `formaction` overrides, all resolved against `document.baseURI` so `<base href>` cannot redirect the real POST elsewhere; re-checked in-page at click/requestSubmit time), and in-page origin guards at fill/submit time all fail REDIRECT_REJECTED before the secret is entered. SSO/OAuth chains that leave the entry origin are a documented policy limit (allowed-domain lists are a follow-up).
- Browser-login endpoint provenance — the CDP endpoint is where vault secrets get typed, so it is operator-managed: `cdp.endpoint` in config.toml (loopback-validated; default `http://127.0.0.1:9222`) piped to the worker via broker stdin. There is no `login --cdp` flag (agent-chosen endpoints are hostile-socket credential sinks → INVALID_CONFIG). `KEEPASS_AGENT_CDP_ENDPOINT` remains only as a test hook — both `kp login` and the worker emit a one-time stderr warning when it supplies the endpoint. `sync-cookies`/`login-capture` keep their `--cdp` flag (cookie harvest runs behind the web-approval flow and sends no typed credentials).
- Browser-login worker isolation — logins run in a CDP isolated browser context (`Target.createBrowserContext`, fail-closed — never the user's default profile unless `--no-isolate`, which additionally requires operator opt-in `cdp.allow_default_context=true` for dedicated-profile instances). Success is proven by `authenticated_via:<url_change|marker|cookie>` — url_change/marker are weak, site-controlled heuristics (a failure page can fake them); only `cookie` — a NEW HttpOnly cookie on the entry origin — is strong server-side evidence, and a pre-existing cookie jar alone is downgraded to WORKER_OUTCOME_UNCERTAIN. MFA detection polls inside `mfaWaitMs` leaving the page open (password field blanked first) for user completion, else WORKER_MFA_REQUIRED — an explicit re-run is the retry contract. Retry policy: transport faults (nav/CDP/connect, `conn.call` capped at 30s) retry once; CREDENTIALS_REJECTED/REDIRECT_REJECTED/NO_LOGIN_FORM/MFA_REQUIRED never retry. The live context is the session handle — persisting cookies into the KDBX entry reuses the login-capture contract (`entry sync-cookies`, web approval + `updateEntryFields`) for dedicated-profile/default-context sessions; isolated-context persistence is a documented gap. Session-expiry detection (when a stored session needs re-login) is a follow-up.
- Worker output whitelist + redaction — result must be `{success,status}` or `{success:false,code,detail}`; unknown fields dropped; worker-emitted codes limited to a known set or the `WORKER_*` namespace (system/broker codes cannot be spoofed → WORKER_OUTPUT_INVALID); `detail` capped at 200 chars with control chars stripped and absolute paths collapsed; piped password/username occurrences in worker stdout/stderr and parsed code/detail/status are replaced with `[redacted]`, applied both pre- and post-JSON-parse (JSON-escaped echoes covered). Matching is case-insensitive and tolerates whitespace inserted between secret characters — **redaction is a best-effort backstop for direct echo and trivial variants; encoding-level variants (base64, NFC/NFD, URL-encoding) are not detected**, so workers must never echo secrets at all.
- Worker timeout kills the whole process tree — taskkill /T /F on Windows with a child.kill fallback, detached process-group SIGKILL on POSIX; per-worker `timeoutMs` in the registry (default 60s).
- Secret input charset — CR/LF in master keys or entry passwords rejected at the form boundary (INVALID_SECRET_CHARS) and again in `keyStdin`; non-CP949 entry passwords warned on `entry add` (Windows KPScript decodes stdout as CP949).
- Unlock UI: loopback bind, Host+Origin checks, one-time token (10min), 5-attempt cap (invalidates the token), encrypted payload only (`p` required — no plaintext credential fields, POST only), no-store
- Management UI (`kp ui`): same transport model — loopback bind on a random port, Host+Origin checks, no-store, CSP. Two tokens per run: a **one-time page token** travels in the launch URL (`/?t=`) and is consumed on first page serve — this URL transits the browser-spawn **argv**, which same-UID processes can read briefly, so the token it carries is worthless by the time an attacker could replay it; the real session credential is a separate **apiToken**, embedded only in the served page and required as `x-kp-ui-token` on every `/api` call (401 without it). A `SameSite=Strict` `HttpOnly` cookie carrying the apiToken lets a same-browser reload re-serve the page without a URL token (mutations still require the header — cookies/JS alone are insufficient). The token is never written to stdout/stderr — it appears there only when the browser cannot be opened (`--no-open`/`unlock.auto_open_browser=false`) or on explicit `--print-url`, always with a warning. Mutations are POST + `application/json` only (the custom header requirement also kills cross-origin form CSRF). No secrets cross it: unlock delegates to the existing one-time-token approval flow — the API only returns the approval URL. Identity: `x-kp-agent` declares an agent → the request is evaluated deny-by-default under the `ui.*` action namespace; absent → the reserved `operator` identity, which bypasses `[agents.*]` unless `[agents.operator]` is configured (the console holder already ran the gated `kp ui` and owns config.toml anyway). `ui.agents.write` is **operator-only** — a declared agent can never write policy through the API regardless of its grants. **Granting `ui` (or `ui.agents.write`) to an agent is operator-equivalent**: `kp ui` mints a token usable for policy self-extension — grant these actions only to principals you would trust with config.toml itself. Every call writes one `ui.*` audit record. Concurrent approvals are capped (UNLOCK_BUSY beyond 3 in-flight). Hardened mode routes session/audit/lock/unlock over authenticated service IPC under the declared (or launching) identity — the service re-evaluates policy per op — and fails closed with `HARDENED_*` codes rather than any in-process fallback
- Cookies are authentication-grade secrets — both `entry sync-cookies` and `entry login-capture` require explicit web approval (one-time token, same cookies-mode form); there is no direct CLI harvest path
- CDP endpoints are loopback-only — `--cdp` and the server-side cookies path both enforce 127.0.0.1/localhost/[::1] (CDP_ENDPOINT_REJECTED); a remote debug socket could harvest or inject cookies
- Cookie-domain matching is dot-boundary only — `github.com` ↔ `*.github.com`; suffix lookalikes (`mygithub.com`, `github.com.evil.net`) never match
- `db sync` builds remote commands as pure argv (`sprite exec -- md5sum|stat|base64 <path>`) — no `sh -c` string is ever constructed; `--sprite`/`--remote` are additionally validated to metacharacter-free charsets (INVALID_SPRITE/INVALID_REMOTE_PATH). Pulls replace the local KDBX atomically: staged tmp file → md5 verify → `.bak` backup → same-dir rename; any pre-rename failure preserves the original
- `tools/relay-unlock.mjs` is a pure proxy — it serves the remote unlock page verbatim (remote RSA key embedded) and forwards POST bodies byte-for-byte via `sprite exec curl`; the relay never sees a plaintext password. Loopback Host/Origin checks, relay-owned token enforcement (foreign tokens never reach upstream), 64KB body cap, no-store, fail-closed when the remote channel is unavailable
- `tools/deploy-sprite.sh` is an operator-only script — sprite name and remote dir are validated to metacharacter-free charsets before any remote `sh -c` interpolation, and all variables are quoted
- Policy engine — every `kp` command (except `config`/`help`/`doctor`/`mcp` — read-only diagnostics and the MCP adapter launch; each MCP tool call is still evaluated) is evaluated against `[agents.<id>]`/`[policy]` in config.toml **deny-by-default**: unlisted actions → `POLICY_DENIED`; `require_approval` actions only proceed through the existing one-time-token web approval flow (`unlock`/`entry.add`/`entry.sync-cookies`/`entry.login-capture`/`db.create`), otherwise `POLICY_APPROVAL_REQUIRED`. Entry remit via `allowed_entries`/`denied_entries` (title/host globs or `uuid:`; `search` results are filtered, single-entry actions are denied); worker destination via `allowed_hosts` (dot-boundary or glob). `pipeSecretToWorker` re-evaluates at the pipe boundary (`policyGate`) so a denied secret never reaches the worker
- Agent identity is **declared, not authenticated** — `--agent`/`KEEPASS_AGENT_ID`, charset-enforced, fallback `default`. It scopes policy and audit attribution only; a same-UID caller can claim any id (Hardened Mode concern)
- Audit log — `~/.config/keepass-agent/audit.log`, append-only JSONL `{ts, agent, action, target, decision, result_code, db}`, POSIX 0600, rotated to `.1` at `policy.audit_max_bytes` (default 1 MiB). The record schema is a fixed whitelist — secrets/passwords/cookie values are structurally excluded. `config set` writes are audited too; policy-file edit rights rest on OS file permissions
- spawn argv arrays — no shell string

## NOT implemented (explicit)
- Kernel-level peer credentials (SO_PEERCRED /
  GetNamedPipeClientProcessId) need a native addon — the `peer.ts` seam +
  `hardened.peer_verify` knob cover the pure-Node subset. (OS-account
  creation, ACL application, and autostart are provisioned by
  `tools/setup-hardened.{sh,ps1}` — operator-run, plan → confirm → apply;
  see docs/operations.md.)
- Plaintext-zero memory guarantee — GC runtime; session file is the trust anchor.

## Threat notes
Same-UID agent can read KDBX/session files — Standard Mode guarantees output hygiene only, not physical secret isolation.
A same-UID process can also claim any `--agent`/`KEEPASS_AGENT_ID` and can
edit config.toml directly — the policy engine constrains *declared*
identities and is bypassed by none of the documented flows (deny-by-default,
broker-side re-check), but it is not a boundary against a process that
deliberately forges its identity. That separation is Hardened Mode.
