// Credential Service IPC protocol — newline-delimited JSON over a unix
// socket (POSIX) or named pipe (Windows).
//
// Wire shape:
//   server → client   {"t":"challenge","nonce":"<b64>"}
//   client → server   {"t":"auth","hmac":"<hex hmac-sha256(token,nonce)>"}
//   server → client   {"t":"ready", ...service info}
//                or   {"t":"denied","code":"HARDENED_AUTH_FAILED"}
//   client → server   {"t":"req","id":<n>,"op":"<op>","agent":"<id>",...params}
//   server → client   {"t":"interim","id":<n>, ...}    (e.g. approval url)
//   server → client   {"t":"res","id":<n>,"ok":true,...} | {"ok":false,"code":...}
//
// Security contract:
//   - The capability-token HMAC handshake proves the caller could read the
//     token file; the file's ACL (POSIX mode/group, Windows NTFS) is the
//     kernel-enforced authorization boundary.
//   - Secrets NEVER cross this channel. listEntries returns metadata only;
//     the login op returns the sanitized worker result — the worker itself is
//     spawned and fed by the service, so no secret transits the agent process
//     or the IPC stream.
//   - Messages are capped (MAX_MSG_BYTES); anything larger or unparseable
//     drops the connection (fail-closed).

export const PROTOCOL_VERSION = 1;
export const MAX_MSG_BYTES = 1 << 20; // 1 MiB — entries lists stay well under this

/** Ops the service dispatches. Extend by adding a handler in handlers.ts. */
export const OPS = new Set([
  'hello',    // service identity/health (post-auth ping)
  'status',   // {db?} → {states:{alias:STATE}}
  'list',     // {db} → {entries} (policy-filtered for the declared agent)
  'login',    // {db,entry,worker,args,meta} → worker result (service spawns worker)
  'lock',     // {db} → {}
  'approval', // {mode:'unlock'|'create'|'entry'|'cookies',...} → interim url + result
  'audit',    // {limit} → {events} (service-side audit log)
]);

/** Client-visible hardened error codes (emitted verbatim in `code`). */
export const HARDENED_CODES = {
  SERVICE_UNAVAILABLE: 'HARDENED_SERVICE_UNAVAILABLE',
  TOKEN_UNAVAILABLE: 'HARDENED_TOKEN_UNAVAILABLE',
  AUTH_FAILED: 'HARDENED_AUTH_FAILED',
  ACL_UNMET: 'HARDENED_ACL_UNMET',
  IPC_ERROR: 'HARDENED_IPC_ERROR',
  TIMEOUT: 'HARDENED_TIMEOUT',
} as const;

/** Ops that may legitimately take minutes (web approval round-trip). */
export const LONG_RUNNING_OPS = new Set(['approval']);

export type WireMsg = Record<string, any>;

/** True if a parsed message has the minimum request shape. */
export function isRequest(m: any): m is { id: number; op: string } & WireMsg {
  return !!m && typeof m === 'object' && m.t === 'req'
    && Number.isInteger(m.id) && m.id >= 0
    && typeof m.op === 'string' && OPS.has(m.op)
    && (m.agent === undefined || typeof m.agent === 'string');
}

/** Encode one message as a wire line. */
export function encode(m: WireMsg): string {
  return JSON.stringify(m) + '\n';
}

/**
 * Incremental line decoder — feed chunks, get complete parsed messages.
 * Oversized buffers (> MAX_MSG_BYTES with no newline) are surfaced as an
 * error via `overflow()`, never silently truncated.
 */
export class LineDecoder {
  private buf = '';
  private overflowed = false;
  feed(chunk: string | Buffer): WireMsg[] {
    if (this.overflowed) return [];
    this.buf += chunk.toString('utf8');
    if (this.buf.length > MAX_MSG_BYTES && !this.buf.includes('\n')) {
      this.overflowed = true;
      return [];
    }
    const out: WireMsg[] = [];
    let i: number;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      // Per-line cap — a newline-terminated line > MAX_MSG_BYTES is a
      // completed message, so the whole-buffer overflow check alone would
      // accept it. Reject it like any other oversize input.
      if (i > MAX_MSG_BYTES) { this.overflowed = true; this.buf = ''; return []; }
      const line = this.buf.slice(0, i);
      this.buf = this.buf.slice(i + 1);
      if (!line.trim()) continue;
      try { out.push(JSON.parse(line)); } catch { out.push({ t: '__parse_error__' }); }
    }
    return out;
  }
  overflow(): boolean { return this.overflowed; }
}
