#!/usr/bin/env bash
# setup-hardened.sh — Hardened Mode provisioning (Linux/systemd). Run as root.
#
# Provisions the full isolation contract verified by src/service/acl.ts:
#   1. Dedicated service account ($SERVICE_USER) + agent group ($AGENT_GROUP)
#   2. State dir $STATE_DIR — owner svc:agents, 0750 (socket/token live inside);
#      $STATE_DIR/home — service-only HOME for the isolated session store
#   3. Registered KDBX files → owner $SERVICE_USER, no 'other' bits
#   4. Service can read the operator config.toml (group or setfacl fallback)
#   5. systemd unit running src/service/service.ts as the service account
#   6. config.toml [hardened] written via tools/lib/write-hardened-config.mjs
#
# Safety: prints a full PLAN then requires confirmation (operator typo
# protection). --dry-run shows the plan without any change; --yes skips the
# prompt. On failure the script prints a rollback block.
#
# Flags:  --dry-run | --yes | --no-start | --no-kdbx-acl
# Env:    SERVICE_USER AGENT_GROUP AGENT_USERS STATE_DIR CONFIG_PATH
#         REPO_DIR KDBX_MODE PEER_VERIFY
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-kpa-svc}"
AGENT_GROUP="${AGENT_GROUP:-kpa-agents}"
AGENT_USERS="${AGENT_USERS:-}"                 # space/comma list of agent uids allowed to call the service
STATE_DIR="${STATE_DIR:-/var/lib/keepass-agent}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG_PATH="${CONFIG_PATH:-$HOME/.config/keepass-agent/config.toml}"
KDBX_MODE="${KDBX_MODE:-0600}"                 # 0600 = service-only; 0640 lets agent-group read the vault file (NOT recommended)
PEER_VERIFY="${PEER_VERIFY:-auto}"

DRY=0; YES=0; NO_START=0; NO_KDBX_ACL=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;; --yes|-y) YES=1 ;; --no-start) NO_START=1 ;;
    --no-kdbx-acl) NO_KDBX_ACL=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "setup-hardened: unknown flag $a" >&2; exit 64 ;;
  esac
done

info() { echo "[setup] $*"; }
warn() { echo "[setup] WARNING: $*" >&2; }
step() { printf '\n=== %s ===\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then echo "  DRY-RUN: $*"; else eval "$@"; fi; }

# Commands below are eval'd with single-quoted interpolations — constrain the
# operator-provided values to metacharacter-free charsets so a bad env var
# can't become a shell injection. Paths disallow quotes/backticks entirely.
for pair in "SERVICE_USER:$SERVICE_USER" "AGENT_GROUP:$AGENT_GROUP" "PEER_VERIFY:$PEER_VERIFY"; do
  n=${pair%%:*}; v=${pair#*:}
  [[ "$v" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "setup-hardened: $n '$v' invalid ([A-Za-z0-9._-]{1,64})" >&2; exit 1; }
done
for pair in "STATE_DIR:$STATE_DIR" "CONFIG_PATH:$CONFIG_PATH" "REPO_DIR:$REPO_DIR" "KDBX_MODE:$KDBX_MODE"; do
  n=${pair%%:*}; v=${pair#*:}
  [[ "$v" =~ ^[A-Za-z0-9._/:~-]{1,255}$ ]] || { echo "setup-hardened: $n '$v' contains unsafe characters" >&2; exit 1; }
done
confirm() {
  [ "$YES" = 1 ] && return 0
  local r; read -r -p "$* [y/N] " r || true
  case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ------------------------------------------------------------------ preflight
if [ "$(id -u)" != 0 ]; then
  if [ "$DRY" = 1 ]; then warn "not root — dry-run plan only"; else
    echo "setup-hardened: must run as root (use sudo, or --dry-run to preview)" >&2; exit 1
  fi
fi
NODE="$(command -v node || true)"
[ -n "$NODE" ] || { echo "setup-hardened: node not found on PATH" >&2; exit 1; }
if [ ! -f "$CONFIG_PATH" ]; then
  warn "config.toml not found at $CONFIG_PATH"
  warn "run 'kp config init' as the operator first, or set CONFIG_PATH="
  [ "$DRY" = 1 ] || exit 1
fi

# Registered KDBX paths from the operator config (via the real CLI).
KDBX_PATHS=()
if [ -f "$CONFIG_PATH" ]; then
  while IFS= read -r p; do [ -n "$p" ] && KDBX_PATHS+=("$p"); done < <(
    KEEPASS_AGENT_CONFIG="$CONFIG_PATH" node "$REPO_DIR/src/cli/kp.ts" config show 2>/dev/null \
      | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{const j=JSON.parse(d);for(const db of Object.values(j.config.databases||{}))console.log(db.path)}catch{}})'
  )
  # KDBX paths land inside eval'd commands — drop any carrying shell-active
  # characters rather than quoting around them (a hostile config.toml could
  # otherwise inject into the provisioning run).
  SAFE=()
  for p in ${KDBX_PATHS[@]+"${KDBX_PATHS[@]}"}; do
    case "$p" in
      # shell-active chars break eval quoting; whitespace/control chars would
      # split systemd ReadWritePaths and the plan output — both are rejected.
      *"'"*|*'`'*|*'$'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*[[:space:]]*|*[[:cntrl:]]*)
        warn "kdbx path with shell-active/whitespace characters skipped: $p" ;;
      *) SAFE+=("$p") ;;
    esac
  done
  KDBX_PATHS=(${SAFE[@]+"${SAFE[@]}"})
fi

AGENT_UIDS=()
for u in ${AGENT_USERS//,/ }; do
  # POSIX login-name charset — an eval'd `usermod -aG` consumes this value.
  if [[ ! "$u" =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
    warn "agent user '$u' is not a valid login name — skipped"; continue
  fi
  if id -u "$u" >/dev/null 2>&1; then AGENT_UIDS+=("$(id -u "$u")"); else warn "agent user '$u' does not exist — skipped"; fi
done
# Footgun guard mirroring service.ts: peer_verify=strict with an empty
# allowed_uids list makes the service refuse to start — catch it in the plan.
if [ "$PEER_VERIFY" = strict ] && [ ${#AGENT_UIDS[@]} -eq 0 ]; then
  warn "PEER_VERIFY=strict but no valid AGENT_USERS — the service would refuse to start"
  warn "  (strict + empty allowed_uids). Set AGENT_USERS or use PEER_VERIFY=auto."
fi

# ---------------------------------------------------------------------- plan
step "Hardened Mode provisioning plan"
cat <<PLAN
  service account : $SERVICE_USER $(id -u "$SERVICE_USER" >/dev/null 2>&1 && echo '(exists)' || echo '(will create)')
  agent group     : $AGENT_GROUP $(getent group "$AGENT_GROUP" >/dev/null 2>&1 && echo '(exists)' || echo '(will create)')
  agent members   : ${AGENT_USERS:-<none — add later: usermod -aG $AGENT_GROUP <user>>}
  state dir       : $STATE_DIR   (svc:agents 0750; $STATE_DIR/home svc 0700)
  config          : $CONFIG_PATH (service read access via group/setfacl)
  kdbx files      : ${#KDBX_PATHS[@]} registered → chown $SERVICE_USER, chmod $KDBX_MODE $( [ "$NO_KDBX_ACL" = 1 ] && echo '(SKIPPED --no-kdbx-acl)' )
$(for p in ${KDBX_PATHS[@]+"${KDBX_PATHS[@]}"}; do echo "                    - $p"; done)
  systemd unit    : /etc/systemd/system/kp-credential.service $( [ "$NO_START" = 1 ] && echo '(enable only, --no-start)' || echo '(enable + start)' )
  endpoint        : $STATE_DIR/svc.sock
  token file      : $STATE_DIR/ipc-token (written by service, mode 0640 svc:agents)
  config write    : [hardened] enabled=true endpoint/token_file/state_dir/service_uid/peer_verify=$PEER_VERIFY $( [ ${#AGENT_UIDS[@]} -gt 0 ] && echo "allowed_uids=[${AGENT_UIDS[*]}]" )
PLAN
if [ "$DRY" = 1 ]; then info "dry-run complete — nothing changed"; exit 0; fi
confirm "Apply this plan?" || { info "aborted — nothing changed"; exit 0; }

DONE_STEPS=()
rollback_hint() {
  cat <<UNDO >&2

--- rollback guide (partial state may exist) ---
systemctl disable --now kp-credential 2>/dev/null; rm -f /etc/systemd/system/kp-credential.service; systemctl daemon-reload
userdel $SERVICE_USER; groupdel $AGENT_GROUP
rm -rf $STATE_DIR
# restore kdbx ownership/perms manually if changed (files were chown'd to $SERVICE_USER)
# remove the [hardened] section from $CONFIG_PATH
UNDO
}
trap 'warn "failed at step: ${DONE_STEPS[-1]:-preflight}"; rollback_hint' ERR

# --------------------------------------------------------------- 1. accounts
step "accounts"
if ! getent group "$AGENT_GROUP" >/dev/null; then run "groupadd --system '$AGENT_GROUP'"; fi
DONE_STEPS+=("group")
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  run "useradd --system --shell /usr/sbin/nologin --home-dir '$STATE_DIR/home' --gid '$AGENT_GROUP' '$SERVICE_USER'"
fi
DONE_STEPS+=("user")
for u in ${AGENT_USERS//,/ }; do
  id -u "$u" >/dev/null 2>&1 && run "usermod -aG '$AGENT_GROUP' '$u'"
done
DONE_STEPS+=("members")

# --------------------------------------------------------------- 2. state dir
step "state dir"
run "install -d -o '$SERVICE_USER' -g '$AGENT_GROUP' -m 0750 '$STATE_DIR'"
run "install -d -o '$SERVICE_USER' -g '$AGENT_GROUP' -m 0700 '$STATE_DIR/home'"
DONE_STEPS+=("statedir")

# ----------------------------------------------------------------- 3. KDBX ACL
step "KDBX isolation"
if [ "$NO_KDBX_ACL" = 0 ]; then
  for p in ${KDBX_PATHS[@]+"${KDBX_PATHS[@]}"}; do
    if [ -f "$p" ]; then
      run "chown '$SERVICE_USER:$AGENT_GROUP' '$p'"
      run "chmod '$KDBX_MODE' '$p'"
    else
      warn "registered KDBX missing: $p — skipped (fix databases.*.path or create it first)"
    fi
  done
else
  info "skipped (--no-kdbx-acl)"
fi
DONE_STEPS+=("kdbx")

# -------------------------------------------------------- 4. config access
step "config.toml access for the service"
# The service must READ the operator config (and write it only for
# service-side `db create` registration). Group read via $AGENT_GROUP keeps
# every agent-group caller able to load it; agents get read — not write.
run "chgrp '$AGENT_GROUP' '$(dirname "$CONFIG_PATH")'"
run "chmod 0750 '$(dirname "$CONFIG_PATH")'"
run "chgrp '$AGENT_GROUP' '$CONFIG_PATH'"
run "chmod 0640 '$CONFIG_PATH'"
if command -v setfacl >/dev/null 2>&1; then
  # Service-side db create writes config.toml — grant the service account
  # explicit rwX on the config dir/file WITHOUT widening group access
  # (group write would let every agent flip hardened.enabled off).
  run "setfacl -m 'u:$SERVICE_USER:rwX' '$(dirname "$CONFIG_PATH")'"
  run "setfacl -m 'u:$SERVICE_USER:rw' '$CONFIG_PATH'"
else
  warn "setfacl unavailable — service can read but NOT write config.toml;"
  warn "  'db create' will fail at registration. Create KDBX files externally"
  warn "  and register with 'kp db add' as the operator instead."
fi
# Path traversal: every ancestor of CONFIG_PATH must be searchable by the
# service account. setfacl preferred; o+x fallback reveals existence only.
p="$(dirname "$CONFIG_PATH")"
while [ "$p" != "/" ] && [ -n "$p" ]; do
  if ! sudo -u "$SERVICE_USER" test -x "$p" 2>/dev/null; then
    if command -v setfacl >/dev/null 2>&1; then
      warn "granting $SERVICE_USER traverse (+x) on $p"
      run "setfacl -m 'u:$SERVICE_USER:--x' '$p'"
    else
      warn "granting o+x on $p so the service can traverse to its config"
      run "chmod o+x '$p'"
    fi
  fi
  p="$(dirname "$p")"
done
DONE_STEPS+=("configacl")

# ----------------------------------------------------------- 5. systemd unit
step "systemd unit"
KDBX_DIRS="$(for p in ${KDBX_PATHS[@]+"${KDBX_PATHS[@]}"}; do dirname "$p"; done | sort -u | tr '\n' ' ')"
if [ "$DRY" = 0 ]; then
  cat > /etc/systemd/system/kp-credential.service <<UNIT
# generated by tools/setup-hardened.sh — regenerate by re-running it
[Unit]
Description=keepass-agent credential service (Hardened Mode)
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$AGENT_GROUP
Environment=KEEPASS_AGENT_CONFIG=$CONFIG_PATH
Environment=HOME=$STATE_DIR/home
ExecStart=$NODE $REPO_DIR/src/service/service.ts
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
ReadWritePaths=$STATE_DIR $KDBX_DIRS

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  if [ "$NO_START" = 1 ]; then
    systemctl enable kp-credential.service
    info "enabled (not started — 'systemctl start kp-credential' when ready)"
  else
    systemctl enable --now kp-credential.service
    info "service enabled + started"
  fi
fi
DONE_STEPS+=("systemd")

# ---------------------------------------------------- 6. config [hardened]
step "config.toml [hardened]"
SVC_UID="$(id -u "$SERVICE_USER")"
ALLOWED_ARG=""
if [ ${#AGENT_UIDS[@]} -gt 0 ]; then
  ALLOWED_ARG="--allowed-uids '[$(IFS=,; echo "${AGENT_UIDS[*]}")]'"
fi
run "node '$REPO_DIR/tools/lib/write-hardened-config.mjs' --config '$CONFIG_PATH' \
  --enabled true --endpoint '$STATE_DIR/svc.sock' --token-file '$STATE_DIR/ipc-token' \
  --state-dir '$STATE_DIR' --service-uid '$SVC_UID' --peer-verify '$PEER_VERIFY' $ALLOWED_ARG"
DONE_STEPS+=("config")

# --------------------------------------------------------------------- done
trap - ERR
step "provisioning complete"
cat <<DONE
verify (as an agent/operator user in group $AGENT_GROUP):
  kp status    → mode 'hardened', isolation.ok true, service up
  kp doctor    → hardened.isolation + hardened.service ok

rollback (full undo):
  systemctl disable --now kp-credential; rm /etc/systemd/system/kp-credential.service; systemctl daemon-reload
  userdel $SERVICE_USER; groupdel $AGENT_GROUP; rm -rf $STATE_DIR
  edit $CONFIG_PATH — remove the [hardened] section (or set enabled = false)

notes:
  - token file $STATE_DIR/ipc-token is written by the service at startup
    (0640 $SERVICE_USER:$AGENT_GROUP) — it IS the caller-authorization boundary.
  - service-side 'db create' writes config.toml — requires the setfacl grant
    applied above; without setfacl, create KDBX externally + 'kp db add'.
  - kdbx files are now owned by $SERVICE_USER ($KDBX_MODE) — KeePass GUI access
    from the operator account needs its own grant (see docs/operations.md).
DONE
