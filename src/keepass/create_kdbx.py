"""Create and verify one KDBX from a JSON stdin request.

Input contains secrets only on stdin. Output is a small status JSON; no
password, KPScript output, or exception text is printed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from pykeepass import PyKeePass, create_database


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"success": False, "code": code}))
    return 1


def main() -> int:
    temp_path: Path | None = None
    password = ""
    try:
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            return fail("REQUEST_TOO_LARGE")
        data = json.loads(raw.decode("utf-8"))
        raw = b""
        path_value = str(data.get("path") or "")
        password = data.get("password")
        key_value = data.get("keyFile")
        kpscript_value = str(data.get("kpscript") or "")
        if not isinstance(password, str) or not password:
            return fail("EMPTY_PASSWORD")
        if password != password.strip():
            return fail("PASSWORD_EDGE_WHITESPACE_UNSUPPORTED")
        try:
            encoded_password = password.encode("cp949", errors="strict")
        except UnicodeEncodeError:
            return fail("PASSWORD_ENCODING_UNSUPPORTED")
        if encoded_password.decode("cp949") != password:
            return fail("PASSWORD_ENCODING_UNSUPPORTED")

        target = Path(path_value)
        if not target.is_absolute() or ".." in target.parts or target.suffix.lower() != ".kdbx":
            return fail("INVALID_PATH")
        if target.exists():
            return fail("DATABASE_ALREADY_EXISTS")
        if not Path(kpscript_value).is_file():
            return fail("KPSCRIPT_NOT_FOUND")
        key_file = str(key_value) if key_value else None
        if key_file and not Path(key_file).is_file():
            return fail("KEYFILE_NOT_FOUND")

        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{target.stem}.", suffix=".tmp.kdbx", dir=str(target.parent))
        os.close(fd)
        temp_path = Path(name)

        create_database(str(temp_path), password=password, keyfile=key_file)
        # Validate the file format independently before installing it at its final path.
        PyKeePass(str(temp_path), password=password, keyfile=key_file)

        args = [kpscript_value, "-c:ListEntries", str(temp_path), "-keyprompt"]
        if key_file:
            args.append(f"-keyfile:{key_file}")
            prompt = password + "\nn\n"
        else:
            prompt = password + "\n\nn\n"
        verified = subprocess.run(
            args,
            input=prompt.encode("cp949"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if verified.returncode != 0:
            return fail("KEEPASS_VERIFY_FAILED")

        # Same-directory hard-link install is atomic and never overwrites an existing DB.
        os.link(temp_path, target)
        temp_path.unlink()
        temp_path = None
        sys.stdout.write(json.dumps({"success": True}))
        return 0
    except FileExistsError:
        return fail("DATABASE_ALREADY_EXISTS")
    except subprocess.TimeoutExpired:
        return fail("KEEPASS_VERIFY_TIMEOUT")
    except Exception:
        return fail("KDBX_CREATE_FAILED")
    finally:
        password = ""
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
