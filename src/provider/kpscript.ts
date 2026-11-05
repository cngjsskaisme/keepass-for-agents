// KPScript provider — Windows backend. Implements the CredentialProvider read
// operations (verifyKey/listEntries/getSecret) through KPScript.exe; write
// operations (createDb/addEntry/updateEntryFields) are PyKeePass-based on every
// platform, so this provider inherits them from PyKeePassProvider.
// Master keys travel -keyprompt stdin only (keyStdin); secrets are validated
// before they ever reach a caller.

import { runKpscript, dbArgs, keyStdin, validateSecretOutput, KpsError } from '../keepass/kpscript.ts';
import type { DbConfig } from '../config/config.ts';
import type { Entry, ProviderResult } from './provider.ts';
import { kpscriptParts } from './provider.ts';
import { PyKeePassProvider } from './pykeepass.ts';

/**
 * Parse ListEntries output. KPScript 2.61 emits per-entry blocks:
 *   UUID: <hex> / GRPU:.. / S: <Field> = <value> / TC:.. / EXP:..
 * Fall back to TSV rows (UUID\tTitle\tUserName\tURL) for other emitters.
 */
function parseEntries(out: string): Entry[] {
  const rows: Entry[] = [];
  // The key prompt runs into the first line ("...User Account (Y/N): UUID: <hex>")
  // — UUID is not anchored to line start for the first entry.
  if (/UUID:\s*[0-9A-Fa-f]{32}/.test(out)) {
    let cur: Entry | null = null;
    for (const line of out.split(/\r?\n/)) {
      const mu = line.match(/(?:^|[^A-Za-z])UUID:\s*([0-9A-Fa-f]{32})/);
      if (mu) { cur = { id: mu[1], title: '', username: '', url: '' }; rows.push(cur); continue; }
      if (!cur) continue;
      const ms = line.match(/^S:\s*([^=]+?)\s*=\s*(.*)$/);
      if (!ms) continue;
      const name = ms[1].trim();
      if (name === 'Title') cur.title = ms[2];
      else if (name === 'UserName') cur.username = ms[2];
      else if (name === 'URL') cur.url = ms[2];
    }
    return rows;
  }
  for (const line of out.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const cols = line.split('\t');
    if (cols.length < 4) continue;
    rows.push({ id: cols[0].trim(), title: cols[1], username: cols[2], url: cols[3] });
  }
  return rows;
}

export class KpscriptProvider extends PyKeePassProvider {
  readonly kind: 'kpscript' | 'pykeepass' = 'kpscript';
  private readonly exe: string;
  private readonly prefix: string[];

  constructor(kpscript: string | string[]) {
    super(kpscript);
    const { exe, prefix } = kpscriptParts(kpscript);
    this.exe = exe;
    this.prefix = prefix;
  }

  /** Verify a master key — open the DB with ListEntries. */
  async verifyKey(db: DbConfig, masterKey: string): Promise<ProviderResult> {
    try {
      const args = this.prefix.concat(['-c:ListEntries', ...dbArgs(db.path, db.key_file)]);
      await runKpscript(this.exe, args, { stdin: keyStdin(masterKey, !!db.key_file), timeoutMs: 20_000 });
      return { ok: true };
    } catch (e: any) {
      return { ok: false, code: e instanceof KpsError ? e.code : 'INTERNAL_ERROR' };
    }
  }

  async listEntries(db: DbConfig, masterKey: string): Promise<ProviderResult<{ entries: Entry[] }>> {
    try {
      const args = this.prefix.concat([
        '-c:ListEntries', ...dbArgs(db.path, db.key_file),
        '-refx-Group:', '-refx-Title:', '-refx-UserName:', '-refx-Url:',
        '-refx-CreationTime:', '-refx-LastModTime:', '-refx-ExpiryTime:',
        '-refx-Notes:', '-refx-Password:', '-refx-Uuid:',
        '-Field:Uuid', '-Field:Title', '-Field:UserName', '-Field:Url',
        '-FailIfNoEntry',
      ]);
      const r = await runKpscript(this.exe, args, { stdin: keyStdin(masterKey, !!db.key_file), timeoutMs: 30_000 });
      return { ok: true, entries: parseEntries(r.stdout) };
    } catch (e: any) {
      return { ok: false, code: e instanceof KpsError ? e.code : 'INTERNAL_ERROR' };
    }
  }

  /** Fetch the password field from an entry — validated before it can pipe out. */
  async getSecret(db: DbConfig, masterKey: string, uuid: string): Promise<ProviderResult<{ secret: string }>> {
    try {
      const args = this.prefix.concat(['-c:GetEntryString', ...dbArgs(db.path, db.key_file), `-refx-UUID:${uuid}`, '-Field:Password', '-FailIfNoEntry']);
      const r = await runKpscript(this.exe, args, { stdin: keyStdin(masterKey, !!db.key_file), timeoutMs: 30_000 });
      const v = validateSecretOutput(r.stdout);
      if (!v.ok) return { ok: false, code: 'SECRET_OUTPUT_INVALID', detail: v.reason };
      return { ok: true, secret: v.value! };
    } catch (e: any) {
      return { ok: false, code: e instanceof KpsError ? e.code : 'INTERNAL_ERROR' };
    }
  }
}
