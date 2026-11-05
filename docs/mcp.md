---
title: Connect an AI agent (MCP)
description: Connect an MCP-capable client to keepass-agent and restrict its permissions.
---

# Connect an AI agent (MCP)

MCP lets an AI client request approved account searches and login tasks. **It does not expose a password retrieval tool.**

::: tip Prerequisite
Complete [Quick start](/quickstart) first. Your KeePass database should already be connected and `doctor` should report no failed checks.
:::

## 1. Give the agent limited access

From the repository root:

```sh
node src/cli/kp.ts config set agents.assistant.allowed "status,search,unlock,login,lock"
node src/cli/kp.ts config set agents.assistant.allowed_hosts "github.com"
node src/cli/kp.ts config validate
```

Here `assistant` is an example agent name and `github.com` is an example destination. Set them to the actual agent and sites you trust. Also restrict `allowed_entries` for sensitive accounts in [Configuration](/configuration).

::: warning Agent identity
Agent IDs are **declared by the caller**; Standard Mode does not verify the OS process behind the name. Restrict the initial `agents.default.allowed = ["*"]` policy before connecting any AI client.
:::

## 2. Register the local MCP server

Use your client's MCP configuration screen or file. The exact location varies by client; this is a generic **stdio MCP** example, not a universal client-specific config:

```json
{
  "mcpServers": {
    "keepass-agent": {
      "command": "node",
      "args": ["/absolute/path/to/nougat-worker/src/mcp/server.ts"],
      "env": {
        "KEEPASS_AGENT_ID": "assistant"
      }
    }
  }
}
```

Replace the script path with the actual **absolute path** on your computer. Windows JSON paths should use `/` or escaped backslashes. Node.js 22.18+ (or 23.6+) is required.

Never put the KeePass master password or API keys in MCP configuration.

## 3. Check the connection

Restart or reload your MCP client, then:

1. Verify that it lists the `keepass-agent` tools.
2. Ask it to call `session_status` for the connected database.
3. If the session is locked, use `request_unlock` and **complete the local approval page yourself**.
4. Call `search_entries` to find account metadata.

If the tools are missing, check the absolute path, Node version, and your client's stdio logs.

## 4. Available tools

| Tool | Purpose |
| --- | --- |
| `session_status` | Check whether a KeePass database is unlocked. |
| `request_unlock` | Request a local browser approval URL. |
| `search_entries` | Search account metadata; no passwords returned. |
| `request_login` | Run an approved authentication worker. |
| `logout`, `revoke_session` | End the unlocked session. |
| `audit_tail` | Read audit records when permitted. |

::: info Browser login is separate
To log in to supported websites, the `playwright` worker needs a separately configured local CDP browser. Despite the name, it uses the Chrome DevTools Protocol, not the Playwright npm package. Read [CLI: Authentication and login](/cli#authentication-and-login) and [Security](/security).
:::

For errors such as `POLICY_DENIED` or `HARDENED_SERVICE_UNAVAILABLE`, see [Troubleshooting](/troubleshooting).
