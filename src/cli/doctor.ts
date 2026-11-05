// kp doctor — read-only dependency/environment diagnostics.
//
// Reports one line item per check with a status of ok | warn | fail plus a
// remediation hint. NEVER mutates the system: every probe is stat/spawn-only
// (no writes, no installs). Used by `kp doctor` after install and by
// operators validating a hardened deployment. Tests inject `spawnImpl` /
// `probeServiceImpl` to exercise present/absent scenarios deterministically.

import { existsSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONFIG_PATH, SESSION_DIR, configExists, loadConfig, validateConfig,
  readSchemaVersion, CONFIG_SCHEMA_VERSION, fileExists, type AppConfig,
} from '../config/config.ts';
import { hardenedEnabled, resolveEndpoint, resolveTokenFile } from '../service/mode.ts';
import { verifyHardenedEnvironment } from '../service/acl.ts';
import { probeService } from '../service/client.ts';

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const VENV_PY = process.platform === 'win32'
  ? join(APP_DIR, '.venv', 'Scripts', 'python.exe')
  : join(APP_DIR, '.venv', 'bin', 'python');
const BUNDLED_KPSCRIPT = join(APP_DIR, 'tools', 'keepass', 'KPScript.exe');
const BUNDLED_KEEPASS = join(APP_DIR, 'tools', 'keepass', 'KeePass.exe');
const DEFAULT_KEEPASS_EXE = 'C:/Program Files/KeePass Password Safe 2/KeePass.exe';

export type CheckStatus = 'ok' | 'warn' | 'fail';
export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail?: string;
  hint?: string;
}
export interface DoctorReport {
  success: boolean;
  platform: string;
  checks: DoctorCheck[];
  summary: { ok: number; warn: number; fail: number; total: number };
}

/** Narrowed spawnSync shape so tests can inject a fake process table. */
export type SpawnProbe = (
  cmd: string,
  args: string[],
) => { status: number | null; stdout: string; stderr?: string; error?: unknown };

const defaultSpawn: SpawnProbe = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 15_000, windowsHide: true });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', error: r.error };
};

/** engines field contract: >=22.18 || >=23.6 (22.x needs .18+, 23.x needs .6+, 24+ always ok). */
export function nodeVersionOk(v: string): boolean {
  const m = v.match(/^v?(\d+)\.(\d+)/);
  if (!m) return false;
  const maj = Number(m[1]), min = Number(m[2]);
  return maj >= 24 || (maj === 23 && min >= 6) || (maj === 22 && min >= 18);
}

interface PythonProbeResult {
  exe?: string;
  version?: string;
  pykeepass?: boolean;
  pykeepassVersion?: string;
  /** First interpreter found that was too old (diagnostics only). */
  sawOld?: string;
}

/**
 * Locate a usable Python ≥3.10 + pykeepass: repo .venv first, then PATH
 * interpreters. `py -3` is not probed — its argument contract differs and
 * `python` covers the same installs on most setups.
 */
function probePython(spawnImpl: SpawnProbe): PythonProbeResult {
  let sawOld: string | undefined;
  for (const exe of [VENV_PY, 'python3', 'python']) {
    const isPath = exe.includes('/') || exe.includes('\\');
    if (isPath && !existsSync(exe)) continue;
    let r;
    try { r = spawnImpl(exe, ['-c', 'import sys;print("%d.%d" % sys.version_info[:2])']); }
    catch { continue; }
    if (r.error || r.status !== 0) continue;
    const ver = r.stdout.trim();
    const m = ver.match(/^(\d+)\.(\d+)/);
    if (!m) continue;
    const okVer = Number(m[1]) > 3 || (Number(m[1]) === 3 && Number(m[2]) >= 10);
    if (!okVer) { sawOld = sawOld ?? `${exe} (${ver})`; continue; }
    const pk = spawnImpl(exe, ['-c', 'import pykeepass;print(getattr(pykeepass, "__version__", "installed"))']);
    if (pk.error || pk.status !== 0)
      return { exe, version: ver, pykeepass: false, sawOld };
    return { exe, version: ver, pykeepass: true, pykeepassVersion: pk.stdout.trim() };
  }
  return { sawOld };
}

function checkSessionDir(): DoctorCheck {
  const name = 'session.dir';
  let st;
  try { st = statSync(SESSION_DIR); } catch {
    return { name, status: 'ok', detail: `${SESSION_DIR} not created yet (first unlock creates it)` };
  }
  if (!st.isDirectory())
    return { name, status: 'fail', detail: `${SESSION_DIR} exists but is not a directory`, hint: 'move it aside and re-run kp doctor' };
  if (process.platform !== 'win32' && (st.mode & 0o077))
    return {
      name, status: 'warn',
      detail: `${SESSION_DIR} mode ${(st.mode & 0o777).toString(8)} grants group/other access`,
      hint: `chmod 700 ${SESSION_DIR} — session payloads are encrypted, but the dir should be user-only`,
    };
  return { name, status: 'ok', detail: SESSION_DIR };
}

export async function runDoctor(deps: {
  spawnImpl?: SpawnProbe;
  probeServiceImpl?: (cfg: AppConfig) => Promise<{ down: boolean; code?: string; info?: Record<string, any> }>;
} = {}): Promise<DoctorReport> {
  const spawnImpl = deps.spawnImpl ?? defaultSpawn;
  const checks: DoctorCheck[] = [];
  const add = (c: DoctorCheck) => { checks.push(c); return c; };

  // --- runtime ---
  {
    const v = process.version;
    add(nodeVersionOk(v)
      ? { name: 'node.version', status: 'ok', detail: v }
      : { name: 'node.version', status: 'fail', detail: `${v} — requires >=22.18 || >=23.6 (native TS type stripping)`, hint: 'install a supported Node.js (nodejs.org / nvm)' });
  }

  // --- config ---
  let cfg: AppConfig | null = null;
  if (!configExists()) {
    add({ name: 'config', status: 'fail', detail: `not found: ${CONFIG_PATH}`, hint: 'run: kp config init' });
  } else {
    try {
      cfg = loadConfig();
      const errs = validateConfig(cfg);
      if (errs.length)
        add({ name: 'config', status: 'fail', detail: errs.join('; '), hint: 'fix config.toml, then kp config validate' });
      else
        add({ name: 'config', status: 'ok', detail: CONFIG_PATH });
      if (cfg.migrations_applied?.length)
        add({
          name: 'config.schema', status: 'warn',
          detail: `on-disk schema is older than v${CONFIG_SCHEMA_VERSION} — migrated in memory: ${cfg.migrations_applied.join(' | ')}`,
          hint: 'run: kp config migrate (persists the upgrade)',
        });
      else {
        const diskV = readSchemaVersion();
        if (diskV != null && diskV > CONFIG_SCHEMA_VERSION)
          add({ name: 'config.schema', status: 'warn', detail: `config declares schema v${diskV} > v${CONFIG_SCHEMA_VERSION} supported by this build`, hint: 'upgrade keepass-agent or downgrade the config file' });
        else
          add({ name: 'config.schema', status: 'ok', detail: `v${CONFIG_SCHEMA_VERSION}` });
      }
      // deny-by-default: an upgraded install with no [agents.*] section
      // rejects every gated command — surface that explicitly.
      if (!Object.keys(cfg.agents).length)
        add({
          name: 'policy.agents', status: 'warn',
          detail: 'no [agents.*] sections — policy is deny-by-default, so every agent command will fail POLICY_DENIED',
          hint: 'add grants: kp config set agents.<name>.allowed "search,db.list,status" (or edit config.toml)',
        });
      else
        add({ name: 'policy.agents', status: 'ok', detail: `${Object.keys(cfg.agents).length} agent polic${Object.keys(cfg.agents).length === 1 ? 'y' : 'ies'} configured` });
    } catch {
      add({ name: 'config', status: 'fail', detail: `unparseable: ${CONFIG_PATH}`, hint: 'fix or regenerate config.toml (backup first), then kp config validate' });
    }
  }

  // --- KeePass / KPScript (Windows read-path backend; not vendored — GPL) ---
  if (process.platform === 'win32') {
    const ks = cfg?.keepass.kpscript || '';
    if (ks && fileExists(ks))
      add({ name: 'keepass.kpscript', status: 'ok', detail: ks });
    else if (ks)
      add({ name: 'keepass.kpscript', status: 'fail', detail: `configured path missing: ${ks}`, hint: 'fix keepass.kpscript in config.toml or reinstall KPScript — see tools/keepass/README.md' });
    else if (fileExists(BUNDLED_KPSCRIPT))
      add({ name: 'keepass.kpscript', status: 'warn', detail: `found at ${BUNDLED_KPSCRIPT} but not configured`, hint: `kp config set keepass.kpscript "${BUNDLED_KPSCRIPT.replaceAll('\\', '/')}"` });
    else
      add({
        name: 'keepass.kpscript', status: 'fail',
        detail: 'KPScript.exe not found — required on Windows for unlock/list/get',
        hint: 'install KeePass 2.x + KPScript into tools/keepass/ (GPL — not vendored; see tools/keepass/README.md), then kp config set keepass.kpscript <path>',
      });
    const kpe = cfg?.keepass.executable || '';
    if (kpe && fileExists(kpe))
      add({ name: 'keepass.executable', status: 'ok', detail: kpe });
    else if (kpe)
      add({ name: 'keepass.executable', status: 'warn', detail: `configured path missing: ${kpe}`, hint: 'only needed for unlock_method=keepass-gui / master change — fix keepass.executable or ignore' });
    else if (fileExists(BUNDLED_KEEPASS) || fileExists(DEFAULT_KEEPASS_EXE))
      add({ name: 'keepass.executable', status: 'warn', detail: 'KeePass.exe found but not configured', hint: 'kp config set keepass.executable "<path>" (needed for KeePass-GUI unlocks / master key rotation)' });
    else
      add({ name: 'keepass.executable', status: 'warn', detail: 'KeePass.exe not found', hint: 'optional — only needed for unlock_method=keepass-gui and master change; see tools/keepass/README.md' });
  } else {
    add(cfg?.keepass.kpscript && !fileExists(cfg.keepass.kpscript)
      ? { name: 'keepass.kpscript', status: 'warn', detail: `configured but missing: ${cfg.keepass.kpscript}`, hint: 'POSIX uses the pykeepass backend — clear or fix keepass.kpscript' }
      : { name: 'keepass.kpscript', status: 'ok', detail: 'not required on this platform (pykeepass backend)' });
  }

  // --- Python + pykeepass (POSIX backend; Windows write path) ---
  {
    const py = probePython(spawnImpl);
    const missingPykeepassSeverity: CheckStatus = process.platform === 'win32' ? 'warn' : 'fail';
    const venvHint = process.platform === 'win32'
      ? 'python -m venv .venv && .venv\\Scripts\\python -m pip install -r requirements.txt'
      : 'python3 -m venv .venv && .venv/bin/pip install -r requirements.txt';
    if (!py.exe) {
      add({
        name: 'python.pykeepass', status: missingPykeepassSeverity,
        detail: py.sawOld
          ? `no Python >=3.10 found (${py.sawOld} is too old)`
          : 'no Python interpreter found (checked .venv, python3, python)',
        hint: `install Python >=3.10, then: ${venvHint}`,
      });
    } else if (!py.pykeepass) {
      add({
        name: 'python.pykeepass', status: missingPykeepassSeverity,
        detail: `${py.exe} ${py.version} — pykeepass not installed`,
        hint: venvHint,
      });
    } else {
      add({ name: 'python.pykeepass', status: 'ok', detail: `${py.exe} ${py.version}, pykeepass ${py.pykeepassVersion}` });
    }
  }

  // --- session store ---
  add(checkSessionDir());

  // --- registered KDBX paths ---
  if (cfg) {
    const missing = Object.entries(cfg.databases).filter(([, d]) => !fileExists(d.path)).map(([a]) => a);
    add(missing.length
      ? { name: 'kdbx.paths', status: 'warn', detail: `missing KDBX for: ${missing.join(', ')}`, hint: 'fix databases.*.path in config.toml or kp db remove <alias>' }
      : { name: 'kdbx.paths', status: 'ok', detail: `${Object.keys(cfg.databases).length} registered` });
  }

  // --- hardened mode ---
  if (cfg && hardenedEnabled(cfg)) {
    const tokenPath = resolveTokenFile(cfg);
    const endpoint = resolveEndpoint(cfg);
    const kdbxPaths = Object.values(cfg.databases).map((d) => d.path).filter((p) => fileExists(p));
    const fails = verifyHardenedEnvironment(cfg, {
      tokenPath,
      kdbxPaths,
      socketPath: process.platform === 'win32' ? undefined : endpoint,
    });
    add(fails.length
      ? {
        name: 'hardened.isolation', status: 'fail',
        detail: fails.map((f) => `${f.check}:${f.detail ?? 'unmet'}`).join('; '),
        hint: 're-run tools/setup-hardened provisioning — see docs/operations.md',
      }
      : { name: 'hardened.isolation', status: 'ok', detail: `endpoint ${endpoint}, token ${tokenPath}` });
    const probe = await (deps.probeServiceImpl ?? probeService)(cfg);
    add(probe.down
      ? { name: 'hardened.service', status: 'fail', detail: `service unreachable (${probe.code ?? 'down'})`, hint: 'start the Credential Service — see docs/operations.md' }
      : { name: 'hardened.service', status: 'ok', detail: `up at ${endpoint}` });
  } else {
    add({ name: 'hardened.mode', status: 'ok', detail: 'standard mode (hardened.enabled not set)' });
  }

  const summary = {
    ok: checks.filter((c) => c.status === 'ok').length,
    warn: checks.filter((c) => c.status === 'warn').length,
    fail: checks.filter((c) => c.status === 'fail').length,
    total: checks.length,
  };
  return { success: summary.fail === 0, platform: process.platform, checks, summary };
}
