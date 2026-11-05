// Mock PyKeePass helper — speaks the kdbx_helper.py protocol so POSIX CI can
// exercise the non-Windows path (getSecretPy/listEntriesPy/verifyKeyPy)
// without pykeepass or a real kdbx.
//
// stdin JSON: {"cmd":"verify"|"list"|"get","path","keyFile","master","uuid"?,"field"?}
// master must be 'rightkey' — anything else is INVALID_MASTER_KEY.

let d = '';
process.stdin.on('data', (c) => { d += c; });
process.stdin.on('end', () => {
  let j = {};
  try { j = JSON.parse(d); } catch { /* fall through to EMPTY_MASTER_KEY */ }
  if (j.master !== 'rightkey') {
    process.stdout.write(JSON.stringify({ ok: false, code: 'INVALID_MASTER_KEY' }));
    process.exit(1);
  }
  if (j.cmd === 'verify') {
    process.stdout.write(JSON.stringify({ ok: true }));
  } else if (j.cmd === 'list') {
    process.stdout.write(JSON.stringify({
      ok: true,
      entries: [{ id: 'UUID-1', title: 'GitHub Work', username: 'u@x.com', url: 'https://github.com/login' }],
    }));
  } else if (j.cmd === 'get') {
    process.stdout.write(JSON.stringify({ ok: true, secret: 's3cr3t' }));
  } else {
    process.stdout.write(JSON.stringify({ ok: false, code: 'UNKNOWN_CMD' }));
    process.exit(1);
  }
});
