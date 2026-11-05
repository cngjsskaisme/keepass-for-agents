"""Set custom string fields on an existing KDBX entry from a JSON stdin request.

Secrets arrive only on stdin. Output is a small status JSON; no field values
or exception text is printed.
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


def norm_uuid(u: object) -> str:
    return str(u or "").replace("-", "").lower()


def main() -> int:
    master = ""
    try:
        raw = sys.stdin.buffer.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            return fail("REQUEST_TOO_LARGE")
        data = json.loads(raw.decode("utf-8"))
        raw = b""
        path_value = str(data.get("path") or "")
        master = data.get("master")
        key_value = data.get("keyFile")
        uuid_value = str(data.get("uuid") or "")
        fields = data.get("fields")
        if not isinstance(master, str) or not master:
            return fail("EMPTY_MASTER_KEY")
        if not isinstance(fields, dict) or not fields:
            return fail("NO_FIELDS")
        for k, v in fields.items():
            if not isinstance(k, str) or not isinstance(v, str) or len(v) > 65536:
                return fail("INVALID_FIELD")
        target = Path(path_value)
        if not target.is_file():
            return fail("DATABASE_NOT_FOUND")
        key_file = str(key_value) if key_value else None
        if key_file and not Path(key_file).is_file():
            return fail("KEYFILE_NOT_FOUND")

        try:
            kp = PyKeePass(str(target), password=master, keyfile=key_file)
        except CredentialsError:
            return fail("INVALID_MASTER_KEY")
        except Exception:
            return fail("DB_OPEN_FAILED")

        entry = next((e for e in kp.entries if norm_uuid(e.uuid) == norm_uuid(uuid_value)), None)
        if entry is None:
            return fail("ENTRY_NOT_FOUND")
        standard = {"_username": "username", "_password": "password", "_title": "title", "_url": "url", "_notes": "notes"}
        for k, v in fields.items():
            if k in standard:
                setattr(entry, standard[k], v)
            else:
                entry.set_custom_property(k, v)
        try:
            kp.save()
        except Exception:
            return fail("DB_SAVE_FAILED")
        sys.stdout.write(json.dumps({"success": True, "fields": sorted(fields.keys())}))
        return 0
    except Exception:
        return fail("ENTRY_UPDATE_FAILED")
    finally:
        master = ""


if __name__ == "__main__":
    raise SystemExit(main())
