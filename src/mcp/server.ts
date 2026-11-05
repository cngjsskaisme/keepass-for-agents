// MCP Adapter — Model Context Protocol server over stdio.
//
// Wire format: newline-delimited JSON-RPC 2.0 (MCP stdio transport —
// each message is a single JSON object terminated by \n). stdout carries
// PROTOCOL MESSAGES ONLY; every diagnostic goes to stderr.
//
// Implemented surface (handshake-era revisions 2024-11-05 → 2025-11-25):
//   initialize / notifications/initialized / ping / tools/list / tools/call
// No external MCP framework — Node built-ins only.
//
// Identity: the declared agent id is resolved once at `initialize` —
// params.agent → [mcp.clients.<clientInfo.name>] mapping → `kp mcp
// --agent` / KEEPASS_AGENT_ID env → mcp.agent → 'default'. It scopes
// policy and audit exactly like the CLI's declared identity; it is NOT
// an authentication boundary.
//
// Secrets: the tool surface is structurally secret-free (see tools.ts) —
// no request parameter and no response field carries passwords, master
// keys, or cookie values.

import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig, configExists, type AppConfig } from '../config/config.ts';
import { resolveAgentId } from '../policy/engine.ts';
import { callTool, hasTool, toolList, type McpSession } from './tools.ts';

/** Handshake-era protocol revisions this server speaks (newest first). */
export const SUPPORTED_PROTOCOL_VERSIONS = [
  '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05',
] as const;
export const LATEST_PROTOCOL_VERSION: string = SUPPORTED_PROTOCOL_VERSIONS[0];
export const SERVER_INFO = { name: 'keepass-agent', version: '0.1.0' } as const;

// JSON-RPC 2.0 error codes.
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
/** MCP convention: requests before a completed initialize are rejected. */
const SERVER_NOT_INITIALIZED = -32002;

const MAX_LINE_BYTES = 1 << 20; // same cap as the service IPC protocol

export interface ServeOpts {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  errput?: NodeJS.WritableStream;
  /** `kp mcp --agent <id>` — pre-env identity fallback for the session. */
  cliAgent?: string;
}

const errObj = (id: unknown, code: number, message: string, data?: any) =>
  ({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } });
const okObj = (id: unknown, result: any) => ({ jsonrpc: '2.0', id, result });

/** Normalize a clientInfo.name into the [a-z0-9_-] charset used by
 *  [mcp.clients.<name>] section names ("Visual Studio Code" → visual-studio-code). */
function clientKey(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
}

/**
 * Session identity resolution — first match wins:
 *   initialize params.agent → [mcp.clients.<clientInfo.name>].agent →
 *   cliAgent (kp mcp --agent) → KEEPASS_AGENT_ID env → mcp.agent → 'default'
 * resolveAgentId enforces the charset and supplies the env/default tail.
 */
function resolveSessionAgent(cfg: AppConfig | null | undefined, params: any, cliAgent?: string):
  { ok: true; agent: string; source: string } | { ok: false; reason: string } {
  if (params?.agent !== undefined && typeof params.agent !== 'string')
    return { ok: false, reason: 'params.agent must be a string agent id' };
  let flagAgent: string | undefined = params?.agent;
  let source = flagAgent ? 'initialize.params.agent' : '';
  const clients = cfg?.mcp?.clients ?? {};
  if (!flagAgent) {
    const cname = typeof params?.clientInfo?.name === 'string' ? params.clientInfo.name : '';
    const cl = cname
      ? (Object.hasOwn(clients, cname) ? clients[cname] : clients[clientKey(cname)])
      : undefined;
    if (cl?.agent) { flagAgent = cl.agent; source = `mcp.clients.${clientKey(cname) || cname}`; }
  }
  if (!flagAgent && cliAgent) { flagAgent = cliAgent; source = 'kp mcp --agent'; }
  // resolveAgentId applies flag > KEEPASS_AGENT_ID > 'default'. mcp.agent is
  // the operator-configured default — it applies only when neither an
  // explicit declaration nor the env identity exists.
  const effFlag = flagAgent || (process.env.KEEPASS_AGENT_ID ? undefined : cfg?.mcp?.agent);
  const r = resolveAgentId(process.env, effFlag);
  if (!r.ok) return { ok: false, reason: r.reason };
  if (!source)
    source = process.env.KEEPASS_AGENT_ID ? 'KEEPASS_AGENT_ID' : cfg?.mcp?.agent ? 'mcp.agent' : 'default';
  return { ok: true, agent: r.agent, source };
}

/**
 * Run the MCP server until the input stream ends. Requests are dispatched
 * sequentially — a credential gateway has no need for concurrent mutation,
 * and serialization keeps audit ordering and single pending approval state
 * trivially correct.
 */
export async function serveMcp(opts: ServeOpts = {}): Promise<void> {
  const input = opts.input ?? process.stdin;
  const output = opts.output ?? process.stdout;
  const errput = opts.errput ?? process.stderr;
  const write = (o: any) => { try { output.write(JSON.stringify(o) + '\n'); } catch {} };
  const log = (s: string) => { try { errput.write(`kp-mcp: ${s}\n`); } catch {} };

  // Session state — identity resolved at initialize; config snapshot kept
  // as the last-good fallback (tools.ts reloads per call).
  let cfg: AppConfig | null = null;
  try { cfg = configExists() ? loadConfig() : null; } catch { cfg = null; }
  const session: McpSession = {
    agent: 'default', agentOk: true,
    cfg: cfg ?? undefined,
    log,
  };
  let initialized = false;

  const dispatch = async (m: any): Promise<any | null> => {
    // Notifications (no `id` member) never get a response — MCP mandates it.
    const hasId = m && typeof m === 'object' && 'id' in m;
    if (!m || typeof m !== 'object' || Array.isArray(m))
      return errObj(null, INVALID_REQUEST, 'Invalid Request — a single JSON-RPC object per line');
    if (!hasId) {
      // notifications/initialized and any other notification: accept, ignore.
      return null;
    }
    if (typeof m.method !== 'string')
      return errObj(m.id, INVALID_REQUEST, 'Invalid Request — method must be a string');

    if (!initialized && m.method !== 'initialize' && m.method !== 'ping')
      return errObj(m.id, SERVER_NOT_INITIALIZED, 'Server not initialized — send initialize first');

    switch (m.method) {
      case 'initialize': {
        if (initialized)
          return errObj(m.id, INVALID_REQUEST, 'initialize already completed');
        const p = m.params;
        if (!p || typeof p !== 'object' || typeof p.protocolVersion !== 'string' || !p.protocolVersion)
          return errObj(m.id, INVALID_PARAMS, 'initialize requires params.protocolVersion');
        const identity = resolveSessionAgent(cfg ?? session.cfg, p, opts.cliAgent);
        if (!identity.ok) {
          // Fail closed: an undeclarable identity is rejected outright, the
          // same INVALID_AGENT_ID boundary as the CLI.
          session.agentOk = false;
          return errObj(m.id, INVALID_PARAMS, 'INVALID_AGENT_ID', { reason: identity.reason });
        }
        session.agent = identity.agent;
        session.agentOk = true;
        initialized = true;
        // Version negotiation: honor a supported request verbatim, otherwise
        // reply with our latest (per the handshake-spec negotiation rule).
        const protocolVersion = (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(p.protocolVersion)
          ? p.protocolVersion : LATEST_PROTOCOL_VERSION;
        log(`initialized: client=${typeof p.clientInfo?.name === 'string' ? p.clientInfo.name : '?'} agent=${session.agent} (via ${identity.source}) protocol=${protocolVersion}`);
        return okObj(m.id, {
          protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions:
            'keepass-agent credential gateway. Tools return metadata/status only — ' +
            'passwords, master keys, and cookie values never cross this channel.',
        });
      }
      case 'ping':
        return okObj(m.id, {});
      case 'tools/list':
        return okObj(m.id, { tools: toolList() });
      case 'tools/call': {
        const p = m.params;
        const name = p?.name;
        if (typeof name !== 'string' || !hasTool(name))
          return errObj(m.id, INVALID_PARAMS, `unknown tool: ${typeof name === 'string' ? name : '?'}`);
        const args = p?.arguments ?? {};
        if (typeof args !== 'object' || args === null || Array.isArray(args))
          return errObj(m.id, INVALID_PARAMS, 'tools/call arguments must be an object');
        const result = await callTool(session, name, args);
        return okObj(m.id, {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
          isError: !result.success,
        });
      }
      default:
        return errObj(m.id, METHOD_NOT_FOUND, `Method not found: ${m.method}`);
    }
  };

  await new Promise<void>((resolvePromise) => {
    const rl = createInterface({ input, crlfDelay: Infinity, terminal: false });
    let chain: Promise<void> = Promise.resolve();
    rl.on('line', (line) => {
      chain = chain.then(async () => {
        const trimmed = line.trim();
        if (!trimmed) return;
        if (trimmed.length > MAX_LINE_BYTES) {
          write(errObj(null, PARSE_ERROR, 'Parse error — message exceeds size limit'));
          return;
        }
        let m: any;
        try { m = JSON.parse(trimmed); }
        catch { write(errObj(null, PARSE_ERROR, 'Parse error')); return; }
        try { const r = await dispatch(m); if (r) write(r); }
        catch (e) { write(errObj(m?.id, -32603, `Internal error: ${String((e as any)?.message || e).slice(0, 200)}`)); }
      }).catch(() => { /* dispatch chain must never stall */ });
    });
    rl.on('close', () => { chain = chain.finally(() => { try { rl.close(); } catch {} resolvePromise(); }); });
    input.on('error', () => { try { rl.close(); } catch {} });
  });
}

// Direct entrypoint: `node src/mcp/server.ts` (also `kp mcp`, which calls
// serveMcp in-process). stdout is protocol-only from this point on.
const invokedDirectly = process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  serveMcp().catch((e) => {
    try { process.stderr.write(`kp-mcp: fatal: ${String((e as any)?.message || e)}\n`); } catch {}
    process.exit(1);
  });
}
