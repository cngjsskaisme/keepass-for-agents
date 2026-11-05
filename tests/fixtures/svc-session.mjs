// Test helper — write an encrypted session file into the SERVICE home.
// Spawned with HOME/USERPROFILE pointed at the service account's home, so
// saveSession() binds the same SESSION_DIR the running service uses.
// argv: <dpapi-file-url> <alias> <masterKey> [ttlSec]
const [url, alias, key, ttl] = process.argv.slice(2);
const m = await import(url);
await m.saveSession(alias, key, Number(ttl || 300));
process.stdout.write('ok');
