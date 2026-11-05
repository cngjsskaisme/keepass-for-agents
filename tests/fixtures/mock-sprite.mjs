// Mock `sprite` CLI for tests — emulates `sprite exec -s <name> ... -- <cmd>`
// against a local fake remote FS and local HTTP for curl.
//
// argv shape (matches src/cli/kp.ts + tools/relay-unlock.mjs):
//   exec -s <name> [--no-stdin|--stdin] [--dir=<d>] [--file <local>:<remote>] -- <cmd> <args...>
//
// Environment:
//   MOCK_REMOTE_ROOT   remote filesystem root — remote paths map under here
//   MOCK_SPRITE_LOG    if set, every invocation's argv is appended as a JSON
//                      line so tests can assert argv-only (no `sh -c`) usage
//   MOCK_B64_CORRUPT   if set, `base64` emits corrupted payload (pull-integrity test)
//
// Supported remote commands: md5sum, stat -c %Y, base64, true, echo, curl
// (curl performs a real local HTTP request — stands in for remote curl).

import { appendFileSync, readFileSync, writeFileSync, statSync, existsSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { request as httpRequest } from 'node:http';

const args = process.argv.slice(2);
if (process.env.MOCK_SPRITE_LOG) {
  try { appendFileSync(process.env.MOCK_SPRITE_LOG, JSON.stringify(args) + '\n'); } catch {}
}

const dd = args.indexOf('--');
const execArgs = dd >= 0 ? args.slice(0, dd) : args;
const cmd = dd >= 0 ? args.slice(dd + 1) : [];

const fail = (msg, code = 1) => { console.error(msg); process.exit(code); };

function remotePath(p) {
  const root = process.env.MOCK_REMOTE_ROOT;
  if (!root) fail('mock-sprite: MOCK_REMOTE_ROOT unset', 2);
  const abs = resolve(root, ...String(p).split('/').filter(Boolean));
  if (!abs.startsWith(resolve(root))) fail('mock-sprite: remote path escapes root', 2);
  return abs;
}

// --file <local>:<remote> — first ':' separates local from remote
// (local basenames and the validated remote charset never contain ':').
const fi = execArgs.indexOf('--file');
if (fi >= 0 && execArgs[fi + 1]) {
  const spec = execArgs[fi + 1];
  const sep = spec.indexOf(':');
  const local = spec.slice(0, sep), remote = spec.slice(sep + 1);
  const dst = remotePath(remote);
  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, readFileSync(resolve(process.cwd(), local)));
}

const [bin, ...rest] = cmd;

if (bin === 'md5sum') {
  const p = remotePath(rest[0]);
  if (!existsSync(p)) fail(`md5sum: ${rest[0]}: No such file or directory`);
  const md5 = createHash('md5').update(readFileSync(p)).digest('hex');
  process.stdout.write(`${md5}  ${rest[0]}\n`);
  process.exit(0);
}

if (bin === 'stat' && rest[0] === '-c' && rest[1] === '%Y') {
  const p = remotePath(rest[2]);
  if (!existsSync(p)) fail(`stat: cannot stat '${rest[2]}': No such file or directory`);
  process.stdout.write(`${Math.floor(statSync(p).mtimeMs / 1000)}\n`);
  process.exit(0);
}

if (bin === 'base64') {
  const p = remotePath(rest[0]);
  if (!existsSync(p)) fail(`base64: ${rest[0]}: No such file or directory`);
  const data = process.env.MOCK_B64_CORRUPT ? Buffer.from('corrupted-download-payload') : readFileSync(p);
  const b64 = data.toString('base64');
  for (let i = 0; i < b64.length; i += 76) process.stdout.write(b64.slice(i, i + 76) + '\n');
  process.exit(0);
}

if (bin === 'true') process.exit(0);
if (bin === 'echo') { process.stdout.write(rest.join(' ') + '\n'); process.exit(0); }

if (bin === 'curl') {
  // curl subset: -sS/--max-time/-w ignored, -X, -H, --data-binary @-, URL
  let method = 'GET', headers = {}, readStdin = false, url = '';
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '-s' || a === '-S' || a === '-sS') continue;
    if (a === '--max-time' || a === '-w') { i++; continue; }
    if (a === '-X') { method = rest[++i]; continue; }
    if (a === '-H') { const h = rest[++i]; const ci = h.indexOf(':'); headers[h.slice(0, ci).trim().toLowerCase()] = h.slice(ci + 1).trim(); continue; }
    if (a === '--data-binary' || a === '-d') { if (rest[++i] === '@-') readStdin = true; continue; }
    if (!a.startsWith('-')) url = a;
  }
  let body = '';
  const send = () => {
    const r = httpRequest(url, { method, headers }, (resp) => {
      let out = '';
      resp.on('data', (c) => (out += c));
      resp.on('end', () => { process.stdout.write(out + '\n' + resp.statusCode); process.exit(0); });
    });
    r.on('error', (e) => fail(`curl: (7) ${e.message}`, 7));
    if (body) r.write(body);
    r.end();
  };
  if (readStdin) process.stdin.on('data', (c) => (body += c)).on('end', send);
  else send();
} else if (!bin) {
  process.exit(0);
} else {
  // Unknown remote command — succeed quietly like a benign shell builtin.
  process.exit(0);
}
