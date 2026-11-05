#!/usr/bin/env bash
# install.sh — keepass-agent installer (Linux/POSIX).
#
# Verifies the runtime contract and bootstraps the gateway:
#   1. Node.js >= 22.18 || >= 23.6 (native TS type stripping — no build)
#   2. npm ci
#   3. Python >= 3.10 + pykeepass — offers .venv + pip install (the POSIX
#      credential backend, so this is REQUIRED on Linux)
#   4. PATH guidance (bin/kp launcher; --add-path appends an export line to
#      ~/.profile after confirmation)
#   5. kp config init bootstrap → recommends kp doctor
#   6. --systemd installs a user-level systemd unit SKELETON for the
#      Credential Service (dev orientation only — real Hardened isolation
#      needs the system unit provisioned by tools/setup-hardened.sh)
#
# KeePass/KPScript are not required on Linux (pykeepass backend) and are
# never downloaded — they are GPL.
#
# Flags:
#   --yes / -y        answer yes to confirmations
#   --dry-run         print the plan, change nothing
#   --no-deps         skip npm ci
#   --skip-python     skip python/pykeepass verification
#   --add-path        append 'export PATH=.../bin:$PATH' to ~/.profile
#   --systemd         install a user systemd unit skeleton (~/.config/systemd/user/)
#   --uninstall       remove PATH line + user unit; guided config removal
#   -h|--help         usage
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# config.ts resolves ~/.config/keepass-agent (homedir-derived, not XDG-aware).
CONFIG_DIR="$HOME/.config/keepass-agent"
CONFIG_PATH="$CONFIG_DIR/config.toml"
BIN_DIR="$REPO_ROOT/bin"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_FILE="$UNIT_DIR/kp-credential.service"

YES=0; DRY=0; NO_DEPS=0; SKIP_PY=0; ADD_PATH=0; SYSTEMD=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;; --dry-run) DRY=1 ;; --no-deps) NO_DEPS=1 ;;
    --skip-python) SKIP_PY=1 ;; --add-path) ADD_PATH=1 ;;
    --systemd) SYSTEMD=1 ;; --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "install.sh: unknown flag $a" >&2; exit 64 ;;
  esac
done

info() { echo "[install] $*"; }
warn() { echo "[install] WARNING: $*" >&2; }
step() { printf '\n=== %s ===\n' "$*"; }
confirm() {
  [ "$YES" = 1 ] && return 0
  local r; read -r -p "$* [y/N] " r || true
  case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
node_version_ok() { # >=22.18 || >=23.6
  local v="$1" maj min
  [[ "$v" =~ v?([0-9]+)\.([0-9]+) ]] || return 1
  maj=${BASH_REMATCH[1]}; min=${BASH_REMATCH[2]}
  [ "$maj" -ge 24 ] || { [ "$maj" -eq 23 ] && [ "$min" -ge 6 ]; } || { [ "$maj" -eq 22 ] && [ "$min" -ge 18 ]; }
}
backup_config() {
  [ -d "$CONFIG_DIR" ] || return 0
  local dst="$CONFIG_DIR.bak-$(date +%Y%m%d-%H%M%S)"
  if [ "$DRY" = 1 ]; then info "DRY-RUN would back up $CONFIG_DIR -> $dst"; return 0; fi
  cp -a "$CONFIG_DIR" "$dst"
  info "existing config backed up to $dst"
}
kp() { node "$REPO_ROOT/src/cli/kp.ts" "$@"; }

# ------------------------------------------------------------------ uninstall
if [ "$UNINSTALL" = 1 ]; then
  step "Uninstall keepass-agent (confirm each step)"
  # PATH line
  for rc in "$HOME/.profile" "$HOME/.bashrc"; do
    if [ -f "$rc" ] && grep -qF "$BIN_DIR" "$rc"; then
      warn "$rc references $BIN_DIR"
      if confirm "remove the PATH line from $rc?"; then
        if [ "$DRY" = 0 ]; then grep -vF "$BIN_DIR" "$rc" > "$rc.tmp" && mv "$rc.tmp" "$rc"; info "removed from $rc"; fi
      fi
    fi
  done
  # npm link global shim
  if command -v kp >/dev/null 2>&1; then
    kpbin="$(command -v kp)"
    case "$kpbin" in
      "$BIN_DIR"*) : ;; # repo-local launcher — removed with the checkout
      *) warn "'kp' resolves to $kpbin — if this repo was 'npm link'ed, run: npm unlink -g keepass-agent" ;;
    esac
  fi
  # user systemd unit
  if [ -f "$UNIT_FILE" ]; then
    warn "user systemd unit $UNIT_FILE exists"
    if confirm "disable and remove it?"; then
      if [ "$DRY" = 0 ]; then
        systemctl --user disable --now kp-credential.service 2>/dev/null || true
        rm -f "$UNIT_FILE"; systemctl --user daemon-reload 2>/dev/null || true
        info "unit removed"
      fi
    fi
  fi
  # config dir — never silently
  if [ -d "$CONFIG_DIR" ]; then
    warn "config dir $CONFIG_DIR still exists (audit log, policy, sessions)"
    if confirm "back it up and remove it?"; then
      backup_config
      [ "$DRY" = 0 ] && rm -rf "$CONFIG_DIR" && info "config dir removed"
    fi
  fi
  # hardened leftovers (system-level — manual)
  if systemctl list-unit-files 2>/dev/null | grep -q '^kp-credential\.service'; then
    warn "system service 'kp-credential.service' is still installed (Hardened Mode)"
    warn "remove via docs/operations.md rollback: systemctl disable --now kp-credential; userdel kpa-svc; rm -rf /var/lib/keepass-agent"
  fi
  info "uninstall done. KDBX vault files were never touched."
  exit 0
fi

# ---------------------------------------------------------------------- plan
step "keepass-agent install plan"
info "repo:       $REPO_ROOT"
info "config dir: $CONFIG_DIR"
info "mode:       $([ "$DRY" = 1 ] && echo 'DRY-RUN (no changes)' || echo install)"
cat <<'PLAN'
Steps:
  1. Backup existing config (if any)
  2. Verify Node.js >=22.18 || >=23.6
  3. npm ci
  4. Verify Python >=3.10 + pykeepass (offer .venv setup)
  5. PATH registration (optional)
  6. Optional: user systemd unit skeleton (--systemd)
  7. kp config init
PLAN
if [ "$DRY" = 1 ]; then info "dry-run complete — re-run without --dry-run to apply"; exit 0; fi

# --------------------------------------------------------------- 1. backup
if [ -f "$CONFIG_PATH" ] && confirm "existing config.toml found — back up $CONFIG_DIR first?"; then
  backup_config
fi

# ------------------------------------------------------------------ 2. node
step "Node.js"
if ! command -v node >/dev/null 2>&1; then
  warn "node not found on PATH"
  warn "install Node.js >=22.18 or >=23.6 — https://nodejs.org, nvm, or your distro (e.g. 'sudo apt install nodejs' may be too old — check 'node --version')"
  exit 3
fi
NV="$(node --version)"
info "node $NV at $(command -v node)"
node_version_ok "$NV" || { warn "node $NV below required >=22.18 || >=23.6 (native TS type stripping)"; exit 3; }

# ----------------------------------------------------------------- 3. npm ci
if [ "$NO_DEPS" = 0 ]; then
  step "npm ci"
  (cd "$REPO_ROOT" && npm ci) || { warn "npm ci failed"; exit 4; }
else
  info "npm ci skipped (--no-deps)"
fi

# ------------------------------------------------------------------ 4. python
EXIT_CODE=0
if [ "$SKIP_PY" = 0 ]; then
  step "Python + pykeepass"
  PY=""
  if [ -x "$REPO_ROOT/.venv/bin/python" ]; then PY="$REPO_ROOT/.venv/bin/python";
  else
    for c in python3 python; do
      if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
    done
  fi
  if [ -z "$PY" ]; then
    warn "no Python interpreter found — pykeepass is the POSIX credential backend (required)"
    warn "install Python >=3.10 ('sudo apt install python3 python3-venv' / pyenv), then re-run"
    EXIT_CODE=2
  else
    PV="$("$PY" -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    if [ -z "$PV" ] || ! "$PY" -c 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
      warn "$PY reports '${PV:-?}' — Python >= 3.10 required"
      EXIT_CODE=2
    else
      info "python $PV at $PY"
      if ! "$PY" -c 'import pykeepass' 2>/dev/null; then
        warn "pykeepass not installed for $PY"
        if confirm "create .venv in $REPO_ROOT and pip install -r requirements.txt?"; then
          [ -x "$REPO_ROOT/.venv/bin/python" ] || "$PY" -m venv "$REPO_ROOT/.venv"
          "$REPO_ROOT/.venv/bin/pip" install -r "$REPO_ROOT/requirements.txt" \
            && info "pykeepass installed into .venv" \
            || { warn "pip install failed — retry: .venv/bin/pip install -r requirements.txt"; EXIT_CODE=2; }
        else
          warn "pykeepass required on Linux — all credential paths will fail without it"
          EXIT_CODE=2
        fi
      else
        info "pykeepass importable"
      fi
    fi
  fi
else
  info "python check skipped (--skip-python)"
fi

# ------------------------------------------------------- 5. KeePass note + PATH
step "KeePass / PATH"
info "KeePass/KPScript are not required on Linux (pykeepass backend)"
if [ "$ADD_PATH" = 1 ]; then
  LINE="export PATH=\"$BIN_DIR:\$PATH\""
  if grep -qF "$BIN_DIR" "$HOME/.profile" 2>/dev/null; then
    info "$BIN_DIR already in ~/.profile"
  elif confirm "append '$LINE' to ~/.profile?"; then
    echo "$LINE" >> "$HOME/.profile"
    info "appended — new shells pick it up (or: source ~/.profile)"
  fi
else
  info "to run 'kp' anywhere: re-run with --add-path, 'npm link', or call $BIN_DIR/kp directly"
fi

# ------------------------------------------------------------- 6. systemd unit
if [ "$SYSTEMD" = 1 ]; then
  step "systemd user unit (skeleton)"
  if [ "$DRY" = 0 ]; then
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=keepass-agent credential service (USER skeleton — dev orientation)
# NOTE: same-principal user units provide NO privilege isolation. Real
# Hardened Mode needs a dedicated service account + system unit — provision
# with: sudo tools/setup-hardened.sh

[Service]
Type=simple
Environment=KEEPASS_AGENT_CONFIG=$CONFIG_PATH
Environment=KEEPASS_AGENT_SERVICE_SELFTEST=1
ExecStart=$(command -v node) $REPO_ROOT/src/service/service.ts
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
    info "wrote $UNIT_FILE (NOT enabled — 'systemctl --user enable --now kp-credential' to start)"
  fi
else
  info "user systemd skeleton: re-run with --systemd (production hardened → sudo tools/setup-hardened.sh)"
fi

# ------------------------------------------------------------ 7. config init
step "config bootstrap"
if [ -f "$CONFIG_PATH" ]; then
  info "config exists: $CONFIG_PATH"
else
  kp config init >/dev/null
  info "config initialized: $CONFIG_PATH"
fi

# --------------------------------------------------------------------- done
step "install complete"
if [ "$EXIT_CODE" != 0 ]; then
  warn "some dependencies are missing — fix them, then run: kp doctor"
else
  info "next steps:"
fi
info "  kp doctor                      # verify every dependency"
info "  kp db add personal --path <kdbx>"
info "  kp unlock --db personal"
exit "$EXIT_CODE"
