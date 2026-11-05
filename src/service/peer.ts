// Peer-credential verification (POSIX best-effort layer).
//
// Node core exposes neither SO_PEERCRED nor SCM_CREDENTIALS, so a fully
// kernel-verified peer uid needs a native addon (PR-11+ seam). What pure
// Node CAN do on Linux:
//   1. accepted socket → its fd via the libuv handle → /proc/self/fd → inode
//   2. `ss -xp` lists unix sockets with peer inodes and owning pids
//   3. /proc/<pid>/status → real uid
// That yields a genuine kernel-sourced peer identity on Linux systems with
// iproute2 — used by hardened.peer_verify='strict' (reject when the uid is
// not in hardened.allowed_uids, or when verification is unavailable).
// 'auto' attempts and reports but never rejects on mechanism absence;
// 'off' skips entirely. Windows has no equivalent pure-Node API — the
// capability-token ACL is the sole caller boundary there (documented).
//
// Everything kernel-touching is isolated behind peerIdentity(); the ss
// output parser is a pure function so the format is unit-testable.

import { spawnSync } from 'node:child_process';
import { readFileSync, readlinkSync } from 'node:fs';
import type { Socket } from 'node:net';

export interface PeerIdentity {
  ok: boolean;
  pid?: number;
  uid?: number;
  /** 'ss-procfs' | 'unavailable' | 'unsupported-platform' */
  mechanism: string;
  detail?: string;
}

/** Accepted-socket fd → inode via /proc/self/fd (Linux). */
function socketInode(socket: Socket): string | null {
  try {
    const fd = (socket as any)._handle?.fd;
    if (fd == null || fd < 0) return null;
    const link = readlinkSync(`/proc/self/fd/${fd}`);
    return link.match(/^socket:\[(\d+)\]$/)?.[1] ?? null;
  } catch { return null; }
}

/**
 * `ss -xp` parser — find the pid of the process whose unix socket is paired
 * with OUR inode (i.e. the client end of an accepted connection).
 * Line shape (iproute2):
 *   u_str ESTAB 0 0 * 12345 * 67890 users:(("node",pid=100,fd=21))
 * Peer pairing: an entry whose LAST inode (peer column) equals our inode has
 * the client's pid in its users:(()) clause — verified by also requiring its
 * own inode to be the one our socket's peer points at. To keep the parser
 * robust we collect every entry, then pick the one whose `peer` field == our
 * inode; its own `ino` is the client's socket inode, its users clause the pid.
 */
export function parseSsPeerPid(ssOutput: string, ourInode: string): number | null {
  for (const line of ssOutput.split('\n')) {
    if (!line.includes('ino:') && !line.includes(' * ')) {
      // Older/newer ss formats differ; parse generously below.
    }
    // Columns: Netid State Recv-Q Send-Q Local Peer  (followed by users clause)
    const users = line.match(/users:\(\([^)]*pid=(\d+)/);
    const nums = [...line.matchAll(/\bino[=:](\d+)\b/g)].map((m) => m[1]);
    if (!users || !nums.length) continue;
    // Format A: `ino:` key=value fields — first ino is local, second is peer.
    if (nums.length >= 2 && nums[1] === ourInode) return Number(users[1]);
  }
  // Format B (common default): bare inode columns after the address fields —
  // `u_str ESTAB 0 0 /path 111 * 222 users:(...)`: local=111 peer=222.
  for (const line of ssOutput.split('\n')) {
    const users = line.match(/users:\(\([^)]*pid=(\d+)/);
    if (!users) continue;
    const m = line.match(/\s(\d+)\s+\*\s+(\d+)\s+users:/);
    if (m && m[2] === ourInode) return Number(users[1]);
    const m2 = line.match(/\*\s+(\d+)\s+(\d+)\s+users:/);
    if (m2 && m2[2] === ourInode) return Number(users[1]);
  }
  return null;
}

function uidOfPid(pid: number): number | null {
  try {
    const st = readFileSync(`/proc/${pid}/status`, 'utf8');
    const m = st.match(/^Uid:\s*(\d+)/m);
    return m ? Number(m[1]) : null;
  } catch { return null; }
}

/**
 * Resolve the peer identity of an accepted unix-socket connection.
 * win32/other → unsupported (capability token remains the boundary).
 */
export function peerIdentity(socket: Socket): PeerIdentity {
  if (process.platform !== 'linux')
    return { ok: false, mechanism: 'unsupported-platform' };
  const inode = socketInode(socket);
  if (!inode) return { ok: false, mechanism: 'unavailable', detail: 'fd_or_inode_unresolved' };
  const r = spawnSync('ss', ['-xp'], { encoding: 'utf8', timeout: 5_000, windowsHide: true });
  if (r.error || r.status !== 0)
    return { ok: false, mechanism: 'unavailable', detail: 'ss_unavailable' };
  const pid = parseSsPeerPid(r.stdout, inode);
  if (pid == null) return { ok: false, mechanism: 'ss-procfs', detail: 'peer_not_matched' };
  const uid = uidOfPid(pid);
  if (uid == null) return { ok: false, mechanism: 'ss-procfs', detail: `uid_unresolved:${pid}` };
  return { ok: true, pid, uid, mechanism: 'ss-procfs' };
}

/**
 * Policy applied to a resolved/unresolved peer identity.
 * Returns null when the caller may proceed, else a reject reason.
 */
export function peerVerifyDecision(
  tier: 'auto' | 'strict' | 'off' | undefined,
  id: PeerIdentity,
  allowedUids?: number[],
): { reject: boolean; reason?: string } {
  const t = tier ?? 'auto';
  if (t === 'off') return { reject: false };
  if (!id.ok) return t === 'strict' ? { reject: true, reason: `peer_verify_unavailable:${id.detail ?? id.mechanism}` } : { reject: false };
  if (allowedUids?.length && !allowedUids.includes(id.uid!))
    return { reject: true, reason: `peer_uid_${id.uid}_not_allowed` };
  return { reject: false };
}
