"""PyKeePass read/verify helper — replaces KPScript on non-Windows platforms.

stdin JSON: {"cmd": "verify"|"list"|"get", "path": ..., "keyFile": ...,
             "master": ..., "uuid"?: ..., "field"?: ...}
- verify → {"ok": true} | INVALID_MASTER_KEY
- list   → {"ok": true, "entries": [{"id","title","username","url"}]}
- get    → {"ok": true, "secret": <field value>}  (uuid entry, field name)
Secrets arrive only via stdin. Only status/metadata goes to stdout — except
`get`, which intentionally returns the requested secret for worker piping.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"ok": False, "code": code}))
    return 1


def norm_uuid(u: object) -> str:
    return str(u or "").replace("-", "").lower()


def main() -> int:
    master = ""
    try:
        data = json.loads(sys.stdin.buffer.read(256 * 1024 + 1).decode("utf-8"))
        master = data.get("master")
        cmd = data.get("cmd")
        path_value = str(data.get("path") or "")
        key_value = data.get("keyFile")
        if not isinstance(master, str) or not master:
            return fail("EMPTY_MASTER_KEY")
        if not Path(path_value).is_file():
            return fail("DATABASE_NOT_FOUND")
        key_file = str(key_value) if key_value else None
        if key_file and not Path(key_file).is_file():
            return fail("KEYFILE_NOT_FOUND")
        try:
            kp = PyKeePass(path_value, password=master, keyfile=key_file)
        except CredentialsError:
            return fail("INVALID_MASTER_KEY")
        except Exception:
            return fail("DB_OPEN_FAILED")

        if cmd == "verify":
            sys.stdout.write(json.dumps({"ok": True}))
            return 0
        if cmd == "list":
            entries = [
                {
                    "id": norm_uuid(e.uuid).upper(),
                    "title": e.title or "",
                    "username": e.username or "",
                    "url": e.url or "",
                }
                for e in kp.entries
            ]
            sys.stdout.write(json.dumps({"ok": True, "entries": entries}))
            return 0
        if cmd == "get":
            entry = next((e for e in kp.entries if norm_uuid(e.uuid) == norm_uuid(data.get("uuid"))), None)
            if entry is None:
                return fail("ENTRY_NOT_FOUND")
            field = str(data.get("field") or "password")
            value = entry.get_custom_property(field) if field.startswith("KPH: ") else getattr(entry, field, None)
            if value is None:
                return fail("FIELD_NOT_FOUND")
            sys.stdout.write(json.dumps({"ok": True, "secret": str(value)}))
            return 0
        return fail("UNKNOWN_CMD")
    except Exception:
        return fail("HELPER_FAILED")
    finally:
        master = ""


if __name__ == "__main__":
    raise SystemExit(main())
