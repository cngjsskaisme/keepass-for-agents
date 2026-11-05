"""Add one entry to an existing KDBX from a JSON stdin request.

Secrets arrive only on stdin. Output is a small status JSON; no password,
entry content, or exception text is printed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"success": False, "code": code}))
    return 1


def text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


def main() -> int:
    master = ""
    try:
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            return fail("REQUEST_TOO_LARGE")
        data = json.loads(raw.decode("utf-8"))
        raw = b""
        path_value = str(data.get("path") or "")
        master = data.get("master")
        key_value = data.get("keyFile")
        title = text(data.get("title"), 512).strip()
        username = text(data.get("username"), 512)
        password = text(data.get("password"), 4096)
        url = text(data.get("url"), 2048)
        notes = text(data.get("notes"), 8192)
        if not isinstance(master, str) or not master:
            return fail("EMPTY_MASTER_KEY")
        target = Path(path_value)
        if not target.is_file():
            return fail("DATABASE_NOT_FOUND")
        key_file = str(key_value) if key_value else None
        if key_file and not Path(key_file).is_file():
            return fail("KEYFILE_NOT_FOUND")
        if not title:
            return fail("TITLE_REQUIRED")

        try:
            kp = PyKeePass(str(target), password=master, keyfile=key_file)
        except CredentialsError:
            return fail("INVALID_MASTER_KEY")
        except Exception:
            return fail("DB_OPEN_FAILED")

        entry = kp.add_entry(
            kp.root_group, title, username, password,
            url=url or None, notes=notes or None,
        )
        try:
            kp.save()
        except Exception:
            return fail("DB_SAVE_FAILED")
        sys.stdout.write(json.dumps({"success": True, "uuid": str(entry.uuid)}))
        return 0
    except Exception:
        return fail("ENTRY_ADD_FAILED")
    finally:
        master = ""


if __name__ == "__main__":
    raise SystemExit(main())
