// Standalone login endpoint for E2E tests — must run in its own process:
// spawnSync-based kp() calls block the test's event loop, so an in-process
// server can never answer the worker's fetch (POSIX login test hung 20s).
import { createServer } from 'node:http';

const server = createServer((req, res) => {
  let b = '';
  req.on('data', (c) => (b += c));
  req.on('end', () => {
    const p = new URLSearchParams(b);
    const ok = p.get('password') === 's3cr3t' && p.get('username') === 'agent1';
    res.writeHead(ok ? 200 : 403, { 'content-type': 'text/plain' });
    res.end(ok ? 'welcome' : 'invalid credentials');
  });
});
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(String(server.address().port));
});
