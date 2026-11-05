---
title: Architecture internals
description: Module map, implementation details, IPC flows, and synchronization paths.
---

::: tip Prefer a high-level explanation?
Read [Architecture](/architecture) first. This reference retains the detailed module and call-path map for maintainers.
:::

# Architecture

```
AI Agent → bin/kp (bash) → src/cli/kp.ts → modules
  config/     TOML load·validate·atomic save (~/.config/keepass-agent/config.toml)
  database/   KDBX registry (add/remove/default/info) — config bookkeeping only
  provider/   CredentialProvider seam — one contract, two backends:
                provider.ts    interface + createProvider(kpscript) factory
                               (win32 → kpscript, else → pykeepass) + error-code
                               namespace (frozen — CLI prints codes verbatim)
                kpscript.ts    KPScript backend: verifyKey/listEntries/getSecret;
                               write ops inherited from the PyKeePass backend
                pykeepass.ts   PyKeePass backend: all ops via keepass/*.py
                               (stdin JSON → stdout JSON, helper stderr dropped)
  master-key/ session state per DB (LOCKED/UNLOCKED/EXPIRED) — verifyKey via provider
  security/   DPAPI session store (CurrentUser scope, PowerShell stdin)
  keepass/    KPScript runner — argv spawn, stdin keys, output validation
              + PyKeePass helper scripts (*.py) — KPScript-free path
  broker/     listEntries·searchEntries·pipeSecretToWorker (stdin-only secret,
              KDBX access via provider; optional policyGate re-check)
  policy/     engine.ts  declared agent identity (--agent/KEEPASS_AGENT_ID),
                         deny-by-default evaluate(agent, action, target),
                         entry/host restrictions, approvable-action routing
              audit.ts   append-only JSONL audit.log (schema whitelist,
                         mode 600, size rotation)
  mcp/          MCP adapter — JSON-RPC over stdio server (server.ts:
                handshake-era revisions, initialize/ping/tools.list/
                tools.call, sequential dispatch, stdout protocol-only)
                + tools.ts (tool defs → same modules the CLI uses;
                per-call evaluate() under canonical actions, one audit
                record per call as `mcp.<tool>`, hardened IPC routing)
  unlock-server/ loopback web UI, one-time token, CSRF/host/origin checks
  worker/     allowlist registry + local-test worker (per-worker timeoutMs)
              + playwright/browser-login (CDP-driven form login:
              login-core.ts policy layer over cdp-driver.ts page ops)
  cdp/        cookie reader + generic CDP client (client.ts — flat-
              protocol WebSocket, isolated browser contexts)
  service/    Credential Service (Hardened Mode, opt-in) — a separate OS
              principal holding master keys/sessions/KDBX access:
                mode.ts      endpoint/token-file/state-dir resolution
                protocol.ts  JSON-lines wire format + error-code namespace
                auth.ts      256-bit capability token + HMAC handshake
                acl.ts       isolation checks (POSIX stat / icacls scan)
                peer.ts      optional POSIX peer-uid verify (procfs+ss)
                server.ts    unix-socket/named-pipe listener + handshake
                handlers.ts  ops: status/list/login/lock/approval/audit —
                             service-side policy re-check + audit
                service.ts   daemon entrypoint (runs as service account)
                client.ts    kp-side IPC client (callService/probeService)
```

Hardened Mode data flow (`hardened.enabled=true`):

```
agent → kp → policy gate (local audit) → hardGate (token+KDBX ACL checks)
      → capability-token handshake → service
        → policy re-check + service-side audit → provider/worker (secret
          never leaves the service) → sanitized result → kp → JSON out
```

Secrets never cross IPC: `login` returns only the worker's sanitized result;
approval ops run the web round-trip inside the service and stream the
approval URL back as an interim frame. Standard Mode is unchanged
(`hardened.enabled=false`, the default).

Dependency direction: `cli` → `broker`/`master-key`/`unlock-server` →
`provider` → `keepass` backends. Lower layers never import upward; the
`process.platform` backend split lives only in `provider.createProvider`.

Key flows:
- `kp unlock` → token → 127.0.0.1 UI → POST pw → provider.verifyKey → DPAPI session write
- `kp search` → DPAPI decrypt → provider.listEntries (stdin key) → filter → metadata JSON
- `kp login` → UUID resolve → provider.getSecret → validate → worker stdin JSON → status only
- `kp entry add`/`db create` → web form → provider.addEntry/createDb (PyKeePass on every platform)
- `kp entry sync-cookies`/`login-capture` → cookies-mode approval page (one-time token) → unlock server reads CDP cookies (loopback endpoint only) → provider.updateEntryFields
- `kp db sync` → sprite exec argv probes (md5sum/stat) → push via `--file` or pull via `base64` → pull: tmp stage → md5 verify → `.bak` → atomic rename
- Remote unlock → `tools/relay-unlock.mjs` pure proxy: remote page verbatim + POST passthrough through `sprite exec curl` (plaintext never transits the relay)
- Hardened `kp login` → IPC `list`+`login` ops → service resolves entry →
  service re-checks policy → service spawns worker and pipes the secret →
  sanitized result crosses IPC only
- Hardened `kp unlock`/`entry add`/`sync-cookies`/`db create` → IPC
  `approval` op → service hosts the loopback web flow (master key goes
  browser → service, never through the agent) → approval URL streams back
  as an interim frame for the operator's browser
