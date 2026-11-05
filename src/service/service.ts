// Credential Service daemon — the isolated credential principal.
//
// Run as a DEDICATED OS account (provisioning: tools/setup-hardened.*):
//   Windows — a service account / scheduled task under its own user
//   POSIX   — a dedicated uid via systemd unit (PR-11 installs these)
//
// Environment contract:
//   KEEPASS_AGENT_CONFIG   absolute path of the operator's config.toml — the
//                          service reads databases/policy from it (read-only
//                          in most deployments; db create needs write).
//   HOME / USERPROFILE     the SERVICE account's home — SESSION_DIR and the
//                          DPAPI/localCrypt key material live there, so
//                          sessions are owned by the service principal and
//                          unreadable by agents by construction.
//   KEEPASS_AGENT_SERVICE_SELFTEST   test/dev hook — skips the startup ACL
//                          self-check (same-principal runs can't satisfy the
//                          cross-account checks). Never set outside tests.
//
// CLI flags:
//   --endpoint <path|pipe-name>   override cfg.hardened.endpoint
//   --state <dir>                 service state dir (socket/token default root)
//   --token-file <path>           capability-token file to (over)write
//
// Startup is fail-closed: config unreadable, endpoint unbindable, or the
// ACL self-check unmet → non-zero exit, nothing is served.

import { loadConfig, fileExists, SESSION_DIR, type AppConfig } from '../config/config.ts';
import { startServiceServer } from './server.ts';
import { newToken, writeTokenFile } from './auth.ts';
import { serviceSelfCheck, posixPermCheck } from './acl.ts';
import { resolveEndpoint, resolveTokenFile, serviceStateDir } from './mode.ts';
import { AUDIT_MAX_BYTES_DEFAULT } from '../policy/audit.ts';
import { join, dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';

function argOf(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

function die(code: string, detail?: string): never {
  process.stderr.write(JSON.stringify({ event: 'fatal', code, detail }) + '\n');
  process.exit(1);
}

async function main() {
  let cfg: AppConfig;
  try { cfg = loadConfig(); } catch { die('CONFIG_NOT_FOUND', 'set KEEPASS_AGENT_CONFIG to the operator config.toml'); return; }

  // --state overrides the service state dir for this run (tests/dev); the
  // config value is authoritative when the flag is absent.
  if (argOf('--state')) cfg = { ...cfg, hardened: { ...cfg.hardened, state_dir: argOf('--state') } };
  const endpoint = argOf('--endpoint')
    ? (process.platform === 'win32' ? `\\\\.\\pipe\\${argOf('--endpoint')}` : argOf('--endpoint')!)
    : resolveEndpoint(cfg);
  const tokenPath = argOf('--token-file') || resolveTokenFile(cfg);

  // Footgun guard (F9): strict peer verification with an empty allow-list
  // would silently reject nothing or everything depending on the layer —
  // refuse to start with an explicit error instead.
  if (cfg.hardened.peer_verify === 'strict' && !cfg.hardened.allowed_uids?.length)
    die('HARDENED_CONFIG_INVALID', 'hardened.peer_verify=strict requires hardened.allowed_uids');

  // POSIX: the socket's parent dir is the connect-permission boundary —
  // create it 0750 and verify before binding (skipped in SELFTEST).
  if (process.platform !== 'win32') {
    const dir = dirname(endpoint);
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    try { chmodSync(dir, 0o750); } catch {}
    if (!process.env.KEEPASS_AGENT_SERVICE_SELFTEST) {
      const d = posixPermCheck(dir, { what: 'socket_dir' });
      if (!d.ok) die('HARDENED_ACL_UNMET', `socket_dir:${d.detail}`);
    }
  }

  const token = newToken();
  try { writeTokenFile(tokenPath, token); }
  catch (e) { die('TOKEN_WRITE_FAILED', String((e as any)?.message || e).slice(0, 200)); }

  const kpscript = cfg.keepass.kpscript && fileExists(cfg.keepass.kpscript) ? cfg.keepass.kpscript : '';
  const auditMaxBytes = cfg.policy.audit_max_bytes ?? AUDIT_MAX_BYTES_DEFAULT;

  if (process.env.KEEPASS_AGENT_SERVICE_SELFTEST)
    process.stderr.write('kp-service: warning: SELFTEST mode — startup ACL self-check skipped (test hook)\n');

  let svc;
  try {
    svc = await startServiceServer({
      endpoint, token, cfg,
      ctx: { kpscript, auditMaxBytes },
    });
  } catch (e) { die('SERVICE_BIND_FAILED', String((e as any)?.message || e).slice(0, 200)); return; }

  // Self-check the service side of the boundary — fail closed if the files
  // this process just created are not service-private.
  const socketPath = process.platform === 'win32' ? undefined : endpoint;
  const failed = serviceSelfCheck(cfg, { tokenPath, socketPath, sessionDir: SESSION_DIR });
  if (failed.length) {
    await svc.close();
    die('HARDENED_ACL_UNMET', failed.map((f) => `${f.check}:${f.detail}`).join(','));
  }

  process.stdout.write(JSON.stringify({
    event: 'ready',
    endpoint,
    token_file: tokenPath,
    state_dir: serviceStateDir(cfg),
    pid: process.pid,
    uid: typeof process.getuid === 'function' ? process.getuid() : undefined,
    selftest: !!process.env.KEEPASS_AGENT_SERVICE_SELFTEST,
  }) + '\n');

  const shutdown = async () => { await svc.close(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => die('INTERNAL_ERROR', String((e as any)?.message || e).slice(0, 200)));
