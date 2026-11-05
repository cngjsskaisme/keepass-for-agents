// Test fixture — redirect HOME/USERPROFILE to a private mkdtemp directory.
//
// config.ts binds CONFIG_DIR/SESSION_DIR from os.homedir() at module-eval
// time, and os.homedir() consults the environment (USERPROFILE on Windows,
// HOME on POSIX). Importing this file FIRST in a test module guarantees the
// env is set before any src module evaluates, so session/config writes can
// never leak into the real user profile.
//
// Each test file runs in its own node --test child process, so every file
// gets an isolated directory. Cleanup is registered here via after().

import { after } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const TEST_HOME = mkdtempSync(join(tmpdir(), 'kp-test-home-'));

process.env.USERPROFILE = TEST_HOME;
process.env.HOME = TEST_HOME;

after(() => {
  try { rmSync(TEST_HOME, { recursive: true, force: true }); } catch {}
});
