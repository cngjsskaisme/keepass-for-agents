#!/bin/bash
# Deploy keepass-agent to a Sprite (Linux). OPERATOR-ONLY tool — run it from a
# maintainer shell, never from an agent or CI on untrusted input. Usage:
#   MSYS2_ARG_CONV_EXCL='*' ./tools/deploy-sprite.sh <sprite-name> [remote-dir]
set -euo pipefail

SPRITE=${1:-hub-test}
DIR=${2:-/home/sprite/keepass-agent}

# Inputs are interpolated into remote `sh -c` strings below — they must be
# validated to a metacharacter-free charset first. Anything else is refused.
if [[ ! "$SPRITE" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  echo "deploy-sprite: invalid sprite name '$SPRITE'" >&2; exit 1
fi
if [[ ! "$DIR" =~ ^/[A-Za-z0-9._/-]{1,255}$ || "$DIR" == *..* || "$DIR" == *//* ]]; then
  echo "deploy-sprite: invalid remote dir '$DIR' (absolute POSIX path, no .. or metacharacters)" >&2; exit 1
fi

cd "$(dirname "$0")/.."
tar czf /tmp/ka.tgz --exclude=node_modules --exclude=.venv src web package.json package-lock.json README.md
sprite exec -s "$SPRITE" --no-stdin -- mkdir -p "$DIR"
# $DIR is validated above (strict charset) — still quoted inside the remote sh -c.
sprite exec -s "$SPRITE" --no-stdin --file "/tmp/ka.tgz:$DIR/ka.tgz" -- sh -c "cd \"$DIR\" && tar xzf ka.tgz && rm ka.tgz"
# python env
sprite exec -s "$SPRITE" --no-stdin --dir="$DIR" -- sh -c "python3 -m venv .venv 2>/dev/null; .venv/bin/pip install -q pykeepass"
# register db if kdbx already synced
sprite exec -s "$SPRITE" --no-stdin --dir="$DIR" -- sh -c "test -f /root/.config/keepass-agent/agent.kdbx && node src/cli/kp.ts db add personal --path /root/.config/keepass-agent/agent.kdbx || true"
echo "deployed -> sprite exec -s $SPRITE --dir=$DIR -- node src/cli/kp.ts db list"
