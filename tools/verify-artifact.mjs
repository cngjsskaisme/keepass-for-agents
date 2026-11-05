#!/usr/bin/env node
// verify-artifact.mjs — release-artifact integrity check.
//
// Verifies the npm package file list against the distribution contract:
//   REQUIRED  — LICENSE, README.md, package.json, the CLI entry point, and
//               the bin launchers must all be inside the package.
//   FORBIDDEN — node_modules/, tests/, tmp/, .venv/, .git/, .env*, *.kdbx,
//               key files, logs, and other dev/local-only content.
//   GPL honeypot — KeePass/KPScript binaries (KeePass*.exe, KPScript.exe,
//               KeePassLibN*.dll) are GPL and must NEVER ship in the package;
//               users install them separately (tools/keepass/README.md).
//
// Usage:
//   node tools/verify-artifact.mjs                  pack the repo (npm pack) and verify
//   node tools/verify-artifact.mjs --tarball f.tgz  verify an existing tarball
//   node tools/verify-artifact.mjs --list f.txt     verify a newline-separated file list
//
// Exit: 0 clean, 1 contract violation, 2 tooling error. JSON report on stdout.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const REQUIRED = [
  [/^package\/LICENSE$/, 'LICENSE'],
  [/^package\/README\.md$/, 'README.md'],
  [/^package\/package\.json$/, 'package.json'],
  [/^package\/src\/cli\/kp\.ts$/, 'src/cli/kp.ts'],
  [/^package\/bin\/kp$/, 'bin/kp'],
];

const FORBIDDEN = [
  [/^package\/node_modules(\/|$)/, 'node_modules/ must not ship'],
  [/^package\/tests(\/|$)/, 'tests/ must not ship'],
  [/^package\/tmp(\/|$)/, 'tmp/ must not ship'],
  [/^package\/\.venv(\/|$)/, '.venv/ must not ship'],
  [/^package\/\.git(\/|$)/, '.git/ must not ship'],
  [/^package\/\.github(\/|$)/, '.github/ must not ship'],
  [/^package\/test-data(\/|$)/, 'test-data/ must not ship'],
  // dotenv at ANY depth — not just the package root (docs/.env,
  // tools/.env.production, … must all fail)
  [/\.env($|\.)/, '.env files must not ship (any depth)'],
  [/\.kdbx$/i, 'KDBX vault files must never ship'],
  // key material of every flavor — extension-based AND the extensionless
  // ssh private-key names
  [/\.(pem|pfx|p12|key|keyx|asc|jks|keystore)$/i, 'key material must never ship'],
  [/\/id_(rsa|ed25519|dsa|ecdsa)$/i, 'ssh private keys must never ship'],
  [/\.log$/i, 'log files must not ship'],
  [/\.py[co]$/i, 'python bytecode must not ship'],
  [/__pycache__(\/|$)/i, '__pycache__ must not ship'],
  [/^package\/audit\.log$/i, 'audit log must not ship'],
];

/**
 * GPL/binary honeypot — ANY native executable fails the artifact
 * unconditionally. KeePass 2.x and KPScript are GPL-2.0+ and user-installed
 * (tools/keepass/README.md explains it); a name-prefix match would miss a
 * renamed binary, so every .exe/.dll/.so/.dylib/.sys is rejected outright.
 * Text files under tools/keepass/ (README, .config stubs) are unaffected.
 */
const BINARY_HONEYPOT = /\.(exe|dll|so|dylib|sys)$/i;

/**
 * Check a package file list (npm-pack entry names, `package/…` prefix).
 * Pure function — unit tests feed crafted lists through it.
 * @returns {{ok:boolean, errors:string[], warnings:string[]}}
 */
export function checkFileList(names) {
  const errors = [];
  const warnings = [];
  const set = new Set(names);
  for (const [re, label] of REQUIRED)
    if (!names.some((n) => re.test(n))) errors.push(`missing required file: ${label}`);
  for (const n of set) {
    for (const [re, why] of FORBIDDEN)
      if (re.test(n)) { errors.push(`forbidden file shipped: ${n} (${why})`); break; }
    if (BINARY_HONEYPOT.test(n))
      errors.push(`GPL/binary honeypot hit: ${n} — no executable binaries ship; KeePass/KPScript are GPL and user-installed only`);
  }
  if (!names.some((n) => n === 'package/tools/keepass/README.md'))
    warnings.push('tools/keepass/README.md not shipped — users lose the KeePass install guide');
  return { ok: errors.length === 0, errors, warnings };
}

/**
 * List entry names in a .tar buffer (ustar + GNU longname + pax `path=`
 * override). Minimal reader — release tooling only, not a general tar lib.
 */
export function listTarEntries(buf) {
  const names = [];
  let off = 0;
  let paxPath = null;
  let gnuName = null;
  while (off + 512 <= buf.length) {
    const block = buf.subarray(off, off + 512);
    if (block.every((b) => b === 0)) break;
    const rawName = block.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const sizeOct = block.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeOct || '0', 8) || 0;
    const type = String.fromCharCode(block[156]);
    const prefix = block.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const data = buf.subarray(off + 512, off + 512 + size);
    if (type === 'L') {
      gnuName = data.toString('utf8').replace(/\0.*$/, '');
    } else if (type === 'x' || type === 'g') {
      const text = data.toString('utf8');
      for (const rec of text.matchAll(/\d+ path=([^\n]+)\n/g)) paxPath = rec[1];
    } else if (type !== 'V' && type !== 'X') {
      let name = rawName;
      if (prefix) name = `${prefix}/${name}`;
      if (gnuName) { name = gnuName; gnuName = null; }
      if (paxPath) { name = paxPath; paxPath = null; }
      if (type !== '5' && name) names.push(name); // skip dir entries
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return names;
}

/** Entry names inside a .tgz file. */
export function listTarball(path) {
  return listTarEntries(gunzipSync(readFileSync(path)));
}

function npmPack() {
  const outDir = mkdtempSync(join(tmpdir(), 'kp-pack-'));
  try {
    // shell:true on Windows — npm is a .cmd shim and execFile cannot spawn
    // batch files directly (EINVAL). Args are fixed literals, no injection risk.
    execFileSync('npm', ['pack', '--pack-destination', outDir], {
      cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'inherit'], shell: process.platform === 'win32',
    });
    const tgz = readdirSync(outDir).find((f) => f.endsWith('.tgz'));
    if (!tgz) throw new Error('npm pack produced no tarball');
    return { outDir, tgz: join(outDir, tgz) };
  } catch (e) {
    rmSync(outDir, { recursive: true, force: true });
    throw e;
  }
}

function argOf(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}

async function main() {
  let names;
  let source;
  // The pack scratch dir is cleaned whether verification passes, fails, or
  // the read throws — no kp-pack-* leftovers.
  let packDir = null;
  try {
    const listFile = argOf('--list');
    const tgzArg = argOf('--tarball');
    if (listFile) {
      source = `list:${listFile}`;
      names = readFileSync(listFile, 'utf8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    } else if (tgzArg) {
      source = `tarball:${tgzArg}`;
      names = listTarball(tgzArg);
    } else {
      const p = npmPack();
      packDir = p.outDir;
      source = `tarball:${p.tgz}`;
      names = listTarball(p.tgz);
    }
  } finally {
    if (packDir) rmSync(packDir, { recursive: true, force: true });
  }
  const result = checkFileList(names);
  console.log(JSON.stringify({
    success: result.ok,
    source,
    files: names.length,
    errors: result.errors,
    warnings: result.warnings,
  }));
  process.exit(result.ok ? 0 : 1);
}

const invokedAsScript = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) main().catch((e) => {
  console.log(JSON.stringify({ success: false, code: 'VERIFY_TOOLING_ERROR', detail: String(e?.message || e) }));
  process.exit(2);
});
