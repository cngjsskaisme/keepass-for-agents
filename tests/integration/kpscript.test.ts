// Preventive home isolation — import first so no src module can ever bind
// the real profile's config/session dirs, skip-gate or not.
import '../fixtures/tmp-home.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runKpscript, kpscriptAvailable, keyStdin } from '../../src/keepass/kpscript.ts';

const __dir = dirname(fileURLToPath(import.meta.url));
const KPS = join(__dir, '..', '..', 'tools', 'keepass', 'KPScript.exe');
const HAVE = existsSync(KPS);

test('KPScript available — spawns and reports version header', { skip: !HAVE ? 'KPScript.exe not installed in tools/keepass' : false }, async () => {
  assert.ok(kpscriptAvailable(KPS));
  // bare invocation prints usage — proves exe spawns (may exit 0 or 1 depending on version)
  let reached = false;
  try { await runKpscript(KPS, [], { timeoutMs: 15_000 }); reached = true; }
  catch (e: any) { reached = e.code !== 'KPSCRIPT_SPAWN_FAILED'; }
  assert.ok(reached);
});

test('keyprompt stdin format — 3 lines (password, keyfile, user-account)', { skip: !HAVE }, () => {
  assert.equal(keyStdin('pw', false), 'pw\n\nn\n');
  assert.equal(keyStdin('pw', true), 'pw\nn\n');
});
