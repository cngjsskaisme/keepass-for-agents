#!/usr/bin/env node
// write-hardened-config.mjs — provisioning helper: writes operator-managed
// [hardened] keys into a config.toml through the real config.ts path
// (normalize + validate + atomic save, schema_version stamped).
//
// `kp config set hardened.*` is deliberately rejected (CONFIG_KEY_READONLY —
// a same-UID caller must not be able to flip isolation). Provisioning tools
// (setup-hardened.sh / .ps1) run as the operator/root and call this instead.
//
// Usage:
//   node tools/lib/write-hardened-config.mjs --config <config.toml> \
//     [--enabled true|false] [--endpoint <path|pipe-name>] \
//     [--token-file <path>] [--state-dir <dir>] [--service-uid <int>] \
//     [--peer-verify auto|strict|off] [--allowed-uids <json-array>] \
//     [--allowed-sids <json-array>]
//
// Prints the resulting [hardened] section as JSON. Exit 1 + stderr on error.

import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function argOf(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}
function die(msg) { process.stderr.write(`write-hardened-config: ${msg}\n`); process.exit(1); }

const configPath = argOf('--config');
if (!configPath) die('--config <path> required');
process.env.KEEPASS_AGENT_CONFIG = resolve(configPath);

const { loadConfig, saveConfig, validateConfig, fileExists } =
  await import('../../src/config/config.ts');

let cfg;
try { cfg = loadConfig(); }
catch { die(`config not found/unparseable at ${configPath} — run 'kp config init' first`); }

const h = cfg.hardened;
const enabled = argOf('--enabled');
if (enabled != null) {
  if (!/^(true|false)$/.test(enabled)) die('--enabled must be true|false');
  h.enabled = enabled === 'true';
}
const endpoint = argOf('--endpoint'); if (endpoint) h.endpoint = endpoint;
const tokenFile = argOf('--token-file'); if (tokenFile) h.token_file = tokenFile;
const stateDir = argOf('--state-dir'); if (stateDir) h.state_dir = stateDir;
const uid = argOf('--service-uid');
if (uid != null) {
  const n = Number(uid);
  if (!Number.isInteger(n) || n < 0) die('--service-uid must be a non-negative integer');
  h.service_uid = n;
}
const pv = argOf('--peer-verify');
if (pv != null) {
  if (!['auto', 'strict', 'off'].includes(pv)) die('--peer-verify must be auto|strict|off');
  h.peer_verify = pv;
}
const uids = argOf('--allowed-uids');
if (uids != null) {
  let a; try { a = JSON.parse(uids); } catch { die('--allowed-uids must be a JSON array'); }
  if (!Array.isArray(a) || a.some((x) => !Number.isInteger(x) || x < 0)) die('--allowed-uids must be a JSON array of non-negative integers');
  h.allowed_uids = a;
}
const sids = argOf('--allowed-sids');
if (sids != null) {
  let a; try { a = JSON.parse(sids); } catch { die('--allowed-sids must be a JSON array'); }
  if (!Array.isArray(a) || a.some((x) => typeof x !== 'string' || !x.length)) die('--allowed-sids must be a JSON array of strings');
  h.allowed_sids = a;
}

const errs = validateConfig(cfg);
if (errs.length) die(`validation failed: ${errs.join('; ')}`);

// Preserve the file's owner — provisioning often runs as root/Administrator
// and a tmp+rename save would otherwise take the operator's config away.
let owner = null;
try { owner = statSync(configPath); } catch {}
saveConfig(cfg);
if (owner && process.platform !== 'win32') {
  try {
    const st = statSync(configPath);
    if (st.uid !== owner.uid || st.gid !== owner.gid) {
      const { chownSync } = await import('node:fs');
      chownSync(configPath, owner.uid, owner.gid);
    }
  } catch { /* best-effort — POSIX only */ }
}
console.log(JSON.stringify({ success: true, path: configPath, hardened: h }, null, 0));
