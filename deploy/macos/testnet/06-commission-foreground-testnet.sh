#!/bin/sh
set -eu
umask 077

# This is a foreground canary layout. It deliberately does not depend on the
# APFS quota volumes and never installs or starts launchd jobs.
PYTHON=/opt/trading-desk/runtime/python-3.11.16/bin/python3.11
EXECUTOR_PYTHON=/opt/trading-desk/current/executor/.venv/bin/python
PROFILE=/etc/trading-desk/testnet-foreground-profile.json
CONFIG=/etc/trading-desk/testnet-executor.toml
PREINIT_RECEIPT=/etc/trading-desk/testnet-foreground-preinit.receipt
POSTINIT_RECEIPT=/etc/trading-desk/testnet-foreground-postinit.receipt
COLLECTOR_IDENTITY_RECEIPT=/etc/trading-desk/testnet-foreground-collector-identity.receipt
ROUTER_IDENTITY_RECEIPT=/etc/trading-desk/testnet-foreground-router-identity.receipt

DB_ANCESTOR=/private/var/db
FOREGROUND_ROOT=/private/var/db/trading-desk-testnet-foreground
EXECUTION=$FOREGROUND_ROOT/execution
NONCE=$FOREGROUND_ROOT/nonce
DAILY_LOSS=$FOREGROUND_ROOT/daily-loss
LEARNING=$FOREGROUND_ROOT/learning
EXECUTOR_SOCKET=$FOREGROUND_ROOT/executor-socket

TRADING_DB_ROOT=/private/var/db/trading-desk
CONTROL_PRIVATE=/private/var/db/trading-desk/control-private
CHAT_STATE=/private/var/db/trading-desk/control-private/chat-approval
CHAT_DATABASE=/private/var/db/trading-desk/control-private/chat-approval/chat-approval.sqlite3
CHAT_GENERATIONS=/private/var/db/trading-desk/control-private/chat-approval/broker-generations
CHAT_SOCKET_PARENT=/private/var/run/trading-desk

HANDOFF_ROOT=/private/var/db/trading-desk-testnet-chat-handoffs
READY_ROOT=/private/var/db/trading-desk-testnet-chat-ready
PRESENTATION_ROOT=/private/var/db/trading-desk-testnet-chat-presentations
EVIDENCE_ROOT=/private/var/db/trading-desk-testnet-chat-issuance-evidence
QUOTE_ROOT=/private/var/db/trading-desk-testnet-chat-account-quotes
REGISTRATION_ROOT=/private/var/db/trading-desk-testnet-chat-executor-registration
ROUTE_ROOT=/private/var/db/trading-desk-testnet-route-health
REMOTE_ROUTE_ROOT=/private/var/db/trading-desk-testnet-remote-vpn-health
LIMA_HOME=/private/var/db/trading-desk-lima

RENDERER=
CHAT_STORE_INIT_HELPER=
CHAT_STORE_INIT_HELPER_SHA256=
TEMP_ROOT=
LOCK_DIRECTORY=$DB_ANCESTOR/.trading-desk-testnet-foreground-commission.lock
LOCK_HELD=0
POSTINIT_CHANGED=0
POSTINIT_COMMITTED=0
POSTINIT_EXPECTED_RECEIPT=
EXECUTION_ACL_BACKUP=
LEARNING_ACL_BACKUP=

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no identity, path, ACL, config, database, credential, network, service, or venue state changed'
  /bin/echo 'Foreground TESTNET canary phases:'
  /bin/echo '  --apply-identity  create/adopt only exact disabled UID/GID 453'
  /bin/echo '  --apply-router-identity  create/adopt only exact disabled UID/GID 454 and its private Lima home'
  /bin/echo '  --apply-preinit   render public config and create empty final-path layout/ACLs'
  /bin/echo '  --apply-postinit  verify initialized databases and convert only future sidecar ACL inheritance'
  /bin/echo "Public profile must already be root:wheel 0400 and ACL-free at $PROFILE"
  /bin/echo "State root: $FOREGROUND_ROOT (ordinary APFS; no quota/reserve claim)"
  /bin/echo 'No phase runs executor init, initializes chat SQLite, provisions Keychain, changes routing/PF/WireGuard, starts launchd, or calls Hyperliquid.'
  /bin/echo 'The sealed no-argument init-foreground-chat-store.py performs the separate UID-452 SQLite checkpoint.'
}

cleanup() {
  if [ "$POSTINIT_CHANGED" = 1 ] && [ "$POSTINIT_COMMITTED" = 0 ]; then
    safe_to_restore=1
    if [ -e "$POSTINIT_RECEIPT" ] || [ -L "$POSTINIT_RECEIPT" ]; then
      if [ -n "$POSTINIT_EXPECTED_RECEIPT" ] && \
         [ -f "$POSTINIT_RECEIPT" ] && [ ! -L "$POSTINIT_RECEIPT" ] && \
         [ "$(/usr/bin/stat -f %u "$POSTINIT_RECEIPT")" = 0 ] && \
         [ "$(/usr/bin/stat -f %g "$POSTINIT_RECEIPT")" = 0 ] && \
         [ "$(/usr/bin/stat -f %Lp "$POSTINIT_RECEIPT")" = 400 ] && \
         [ "$(/usr/bin/stat -f %l "$POSTINIT_RECEIPT")" = 1 ] && \
         [ -z "$(acl_entries "$POSTINIT_RECEIPT")" ] && \
         /usr/bin/cmp -s "$POSTINIT_RECEIPT" "$POSTINIT_EXPECTED_RECEIPT"; then
        /bin/rm -f "$POSTINIT_RECEIPT" || safe_to_restore=0
      else
        safe_to_restore=0
      fi
    fi
    restored=$safe_to_restore
    if [ "$safe_to_restore" = 1 ]; then
      [ -n "$EXECUTION_ACL_BACKUP" ] && /bin/chmod -E "$EXECUTION" < "$EXECUTION_ACL_BACKUP" || restored=0
      [ -n "$LEARNING_ACL_BACKUP" ] && /bin/chmod -E "$LEARNING" < "$LEARNING_ACL_BACKUP" || restored=0
    fi
    if [ "$restored" = 0 ]; then
      /bin/echo 'CRITICAL: foreground post-init ACL rollback failed; stop for root review' >&2
    fi
  fi
  if [ -n "$TEMP_ROOT" ] && [ -d "$TEMP_ROOT" ]; then
    /bin/rm -f "$TEMP_ROOT"/* 2>/dev/null || true
    /bin/rmdir "$TEMP_ROOT" 2>/dev/null || true
  fi
  if [ "$LOCK_HELD" = 1 ]; then
    /bin/rmdir "$LOCK_DIRECTORY" 2>/dev/null || true
  fi
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

acl_entries() {
  /bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p'
}

acl_export() {
  acl_entries "$1" | /usr/bin/sed -E 's/^[[:space:]]*[0-9][0-9]*:[[:space:]]*//'
}

assert_no_acl() {
  [ -z "$(acl_entries "$1")" ] || die "unexpected named ACL: $1"
}

assert_acl_exact() {
  path=$1
  expected=$2
  actual=$TEMP_ROOT/acl-actual
  normalized=$TEMP_ROOT/acl-expected-normalized
  expected_sorted=$TEMP_ROOT/acl-expected-sorted
  actual_sorted=$TEMP_ROOT/acl-actual-sorted
  probe=$TEMP_ROOT/acl-normalization-probe
  if [ -d "$path" ]; then
    /bin/mkdir -m 0700 "$probe"
  else
    /usr/bin/touch "$probe"
    /bin/chmod 0600 "$probe"
  fi
  /bin/chmod -E "$probe" < "$expected"
  acl_export "$probe" > "$normalized"
  acl_export "$path" > "$actual"
  /usr/bin/sort "$normalized" > "$expected_sorted"
  /usr/bin/sort "$actual" > "$actual_sorted"
  /usr/bin/cmp -s "$expected_sorted" "$actual_sorted" || die "named ACL differs: $path"
  /bin/chmod -C "$path" || die "named ACL is non-canonical: $path"
  /bin/chmod -N "$probe"
  if [ -d "$probe" ]; then
    /bin/rmdir "$probe"
  else
    /bin/rm -f "$probe"
  fi
}

assert_acl_export_exact() {
  path=$1
  expected=$2
  actual=$TEMP_ROOT/acl-export-actual
  expected_sorted=$TEMP_ROOT/acl-export-expected-sorted
  actual_sorted=$TEMP_ROOT/acl-export-actual-sorted
  acl_export "$path" > "$actual"
  /usr/bin/sort "$expected" > "$expected_sorted"
  /usr/bin/sort "$actual" > "$actual_sorted"
  /usr/bin/cmp -s "$expected_sorted" "$actual_sorted" || die "exported named ACL differs: $path"
  /bin/chmod -C "$path" || die "named ACL is non-canonical: $path"
}

set_or_assert_acl() {
  path=$1
  expected=$2
  current=$TEMP_ROOT/acl-current
  acl_export "$path" > "$current"
  if [ ! -s "$current" ]; then
    /bin/chmod -E "$path" < "$expected"
  fi
  assert_acl_exact "$path" "$expected"
}

assert_directory() {
  path=$1
  uid=$2
  gid=$3
  mode=$4
  [ -d "$path" ] && [ ! -L "$path" ] || die "missing or linked directory: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = "$uid" ] || die "directory owner differs: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = "$gid" ] || die "directory group differs: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = "$mode" ] || die "directory mode differs: $path"
}

ensure_directory() {
  path=$1
  uid=$2
  gid=$3
  mode=$4
  acl_file=$5
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    /bin/mkdir -m "$mode" "$path"
    /usr/sbin/chown "$uid:$gid" "$path"
  fi
  assert_directory "$path" "$uid" "$gid" "$mode"
  if [ "$acl_file" = NONE ]; then
    assert_no_acl "$path"
  else
    set_or_assert_acl "$path" "$acl_file"
  fi
}

assert_regular() {
  path=$1
  uid=$2
  gid=$3
  mode=$4
  [ -f "$path" ] && [ ! -L "$path" ] || die "missing or linked regular file: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = "$uid" ] || die "file owner differs: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = "$gid" ] || die "file group differs: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = "$mode" ] || die "file mode differs: $path"
  [ "$(/usr/bin/stat -f %l "$path")" = 1 ] || die "hard-linked file rejected: $path"
}

assert_empty() {
  first=$(/usr/bin/find "$1" -mindepth 1 -maxdepth 1 -print -quit)
  [ -z "$first" ] || die "directory must be empty before init: $first"
}

fullsync_paths() {
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$PYTHON" -B -I -c '
import fcntl, os, stat, sys
for path in sys.argv[1:]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    metadata = os.lstat(path)
    if stat.S_ISDIR(metadata.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        fcntl.fcntl(descriptor, 51)
    finally:
        os.close(descriptor)
' "$@"
}

write_identity_receipt() {
  target=$1
  role=$2
  account=$3
  uid=$4
  gid=$5
  home=$6
  assert_directory /etc/trading-desk 0 0 700
  pending=$TEMP_ROOT/$role-identity.receipt
  {
    /bin/echo 'schema_version=1'
    /bin/echo "role=$role"
    /bin/echo "account=$account"
    /bin/echo "uid=$uid"
    /bin/echo "gid=$gid"
    /bin/echo "home=$home"
    /bin/echo 'shell=/usr/bin/false'
    /bin/echo 'authentication=disabled'
    /bin/echo 'supplementary_groups=none'
    /bin/echo 'credential_loaded=false'
    /bin/echo 'network_changed=false'
    /bin/echo 'service_started=false'
    /bin/echo 'venue_write_attempted=false'
    /bin/echo 'mainnet_authorized=false'
  } > "$pending"
  /usr/sbin/chown root:wheel "$pending"
  /bin/chmod 0400 "$pending"
  fullsync_paths "$pending"
  if [ -e "$target" ] || [ -L "$target" ]; then
    assert_regular "$target" 0 0 400
    assert_no_acl "$target"
    /usr/bin/cmp -s "$target" "$pending" || die "identity receipt differs: $target"
  else
    /bin/mv "$pending" "$target"
  fi
  assert_regular "$target" 0 0 400
  assert_no_acl "$target"
  fullsync_paths "$target" /etc/trading-desk
}

assert_identity() {
  name=$1
  uid=$2
  gid=$3
  [ "$(/usr/bin/id -u "$name")" = "$uid" ] || die "$name UID drift"
  [ "$(/usr/bin/id -g "$name")" = "$gid" ] || die "$name primary GID drift"
}

assert_fixed_identities() {
  assert_identity trading-research 450 450
  assert_identity trading-executor 451 451
  assert_identity trading-control 452 452
  assert_identity trading-public-collector 453 453
  [ "$(/usr/bin/id -u jawndiego)" = 501 ] || die "attended Codex bridge UID drift"
}

dscl_value() {
  node=$1
  attribute=$2
  /usr/bin/dscl . -read "$node" "$attribute" 2>/dev/null | \
    /usr/bin/sed -n "s/^$attribute: //p"
}

assert_directory_id_singleton() {
  node=$1
  attribute=$2
  numeric_id=$3
  expected_name=$4
  results=$(/usr/bin/dscl . -search "$node" "$attribute" "$numeric_id" 2>/dev/null) || die "$node $attribute search failed"
  count=$(/bin/echo "$results" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" = 1 ] || die "$node $attribute $numeric_id is not unique"
  [ "$(/bin/echo "$results" | /usr/bin/awk 'NF {print $1}')" = "$expected_name" ] || die "$node $attribute $numeric_id belongs to another name"
  [ "$(/bin/echo "$results" | /usr/bin/awk 'NF {print $2}')" = "$numeric_id" ] || die "$node $attribute search value differs"
  [ "$(/bin/echo "$results" | /usr/bin/awk 'NF {print NF}')" = 2 ] || die "$node $attribute search result is ambiguous"
}

assert_directory_id_unused() {
  node=$1
  attribute=$2
  numeric_id=$3
  results=$(/usr/bin/dscl . -search "$node" "$attribute" "$numeric_id" 2>/dev/null) || die "$node $attribute collision search failed"
  count=$(/bin/echo "$results" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" = 0 ] || die "$node $attribute $numeric_id is already assigned: $results"
}

assert_collector_identity_exact() {
  assert_directory_id_singleton /Users UniqueID 453 trading-public-collector
  assert_directory_id_singleton /Groups PrimaryGroupID 453 trading-public-collector
  assert_identity trading-public-collector 453 453
  [ "$(dscl_value /Users/trading-public-collector UniqueID)" = 453 ] || die 'collector UniqueID drift'
  [ "$(dscl_value /Users/trading-public-collector PrimaryGroupID)" = 453 ] || die 'collector PrimaryGroupID drift'
  [ "$(dscl_value /Users/trading-public-collector NFSHomeDirectory)" = /var/empty ] || die 'collector home drift'
  [ "$(dscl_value /Users/trading-public-collector UserShell)" = /usr/bin/false ] || die 'collector shell drift'
  [ "$(dscl_value /Users/trading-public-collector IsHidden)" = 1 ] || die 'collector hidden flag drift'
  [ "$(dscl_value /Users/trading-public-collector AuthenticationAuthority)" = ';DisabledUser;' ] || die 'collector authentication is not disabled'
  [ "$(dscl_value /Groups/trading-public-collector PrimaryGroupID)" = 453 ] || die 'collector group ID drift'
  if /usr/bin/dscl . -read /Groups/trading-public-collector GroupMembership >/dev/null 2>&1; then
    die 'collector group has explicit members'
  fi
  group_ids=$(/usr/bin/id -G trading-public-collector)
  [ "$group_ids" = 453 ] || die 'collector has unexpected supplementary groups'
}

assert_router_identity_exact() {
  assert_directory_id_singleton /Users UniqueID 454 trading-router-operator
  assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator
  assert_identity trading-router-operator 454 454
  [ "$(dscl_value /Users/trading-router-operator UniqueID)" = 454 ] || die 'router operator UniqueID drift'
  [ "$(dscl_value /Users/trading-router-operator PrimaryGroupID)" = 454 ] || die 'router operator PrimaryGroupID drift'
  [ "$(dscl_value /Users/trading-router-operator NFSHomeDirectory)" = "$LIMA_HOME" ] || die 'router operator home drift'
  [ "$(dscl_value /Users/trading-router-operator UserShell)" = /usr/bin/false ] || die 'router operator shell drift'
  [ "$(dscl_value /Users/trading-router-operator IsHidden)" = 1 ] || die 'router operator hidden flag drift'
  [ "$(dscl_value /Users/trading-router-operator AuthenticationAuthority)" = ';DisabledUser;' ] || die 'router operator authentication is not disabled'
  [ "$(dscl_value /Groups/trading-router-operator PrimaryGroupID)" = 454 ] || die 'router operator group ID drift'
  if /usr/bin/dscl . -read /Groups/trading-router-operator GroupMembership >/dev/null 2>&1; then
    die 'router operator group has explicit members'
  fi
  group_ids=$(/usr/bin/id -G trading-router-operator)
  [ "$group_ids" = 454 ] || die 'router operator has unexpected supplementary groups'
}

assert_root_apply() {
  [ "$(/usr/bin/uname -s)" = Darwin ] || die 'apply phases are macOS-only'
  [ "$(/usr/bin/id -u)" = 0 ] || die 'apply phases require root'
  script_path=$(/bin/realpath "$0")
  [ "$script_path" = "$0" ] || die 'commissioner path must be canonical and absolute'
  script_dir=$(/usr/bin/dirname "$script_path")
  cursor=$script_dir
  while :; do
    [ -d "$cursor" ] && [ ! -L "$cursor" ] || die "commissioner ancestor is unsafe: $cursor"
    [ "$(/bin/realpath "$cursor")" = "$cursor" ] || die "commissioner ancestor is non-canonical: $cursor"
    [ "$(/usr/bin/stat -f %u "$cursor")" = 0 ] || die "commissioner ancestor is not root-owned: $cursor"
    [ "$(/usr/bin/stat -f %g "$cursor")" = 0 ] || die "commissioner ancestor group is not wheel: $cursor"
    [ -z "$(/usr/bin/find "$cursor" -maxdepth 0 -perm +022 -print -quit)" ] || die "commissioner ancestor is group/world writable: $cursor"
    assert_no_acl "$cursor"
    [ "$cursor" = / ] && break
    cursor=$(/usr/bin/dirname "$cursor")
  done
  assert_regular "$script_path" 0 0 "$(/usr/bin/stat -f %Lp "$script_path")"
  [ -z "$(/usr/bin/find "$script_path" -maxdepth 0 -perm +022 -print -quit)" ] || die 'commissioner is group/world writable'
  assert_no_acl "$script_path"
  RENDERER=$script_dir/render-foreground-executor-config.py
  [ "$(/bin/realpath "$RENDERER")" = "$RENDERER" ] || die 'config renderer path is non-canonical'
  assert_regular "$RENDERER" 0 0 "$(/usr/bin/stat -f %Lp "$RENDERER")"
  [ -x "$RENDERER" ] || die 'config renderer is not executable'
  [ -z "$(/usr/bin/find "$RENDERER" -maxdepth 0 -perm +022 -print -quit)" ] || die 'config renderer is group/world writable'
  assert_no_acl "$RENDERER"
  CHAT_STORE_INIT_HELPER=$script_dir/init-foreground-chat-store.py
  [ "$(/bin/realpath "$CHAT_STORE_INIT_HELPER")" = "$CHAT_STORE_INIT_HELPER" ] || die 'chat-store initializer path is non-canonical'
  assert_regular "$CHAT_STORE_INIT_HELPER" 0 0 "$(/usr/bin/stat -f %Lp "$CHAT_STORE_INIT_HELPER")"
  [ -x "$CHAT_STORE_INIT_HELPER" ] || die 'chat-store initializer is not executable'
  [ -z "$(/usr/bin/find "$CHAT_STORE_INIT_HELPER" -maxdepth 0 -perm +022 -print -quit)" ] || die 'chat-store initializer is group/world writable'
  assert_no_acl "$CHAT_STORE_INIT_HELPER"
  CHAT_STORE_INIT_HELPER_SHA256=$(/usr/bin/openssl dgst -sha256 "$CHAT_STORE_INIT_HELPER" | /usr/bin/awk '{print $2}')
  [ -x "$PYTHON" ] || die "sealed admin Python is unavailable: $PYTHON"
  [ "$(/usr/bin/stat -f %u "$PYTHON")" = 0 ] || die 'admin Python is not root-owned'
}

assert_executor_python() {
  [ -x "$EXECUTOR_PYTHON" ] || die "installed executor Python is unavailable: $EXECUTOR_PYTHON"
  [ "$(/usr/bin/stat -f %u "$EXECUTOR_PYTHON")" = 0 ] || die 'executor Python is not root-owned'
  [ -z "$(/usr/bin/find "$EXECUTOR_PYTHON" -maxdepth 0 -perm +022 -print -quit)" ] || die 'executor Python is group/world writable'
}

acquire_lock() {
  [ ! -e "$LOCK_DIRECTORY" ] && [ ! -L "$LOCK_DIRECTORY" ] || die "commission lock requires review: $LOCK_DIRECTORY"
  /bin/mkdir -m 0700 "$LOCK_DIRECTORY"
  /usr/sbin/chown root:wheel "$LOCK_DIRECTORY"
  LOCK_HELD=1
  TEMP_ROOT=$(/usr/bin/mktemp -d /private/tmp/trading-desk-foreground.XXXXXX)
  /usr/sbin/chown root:wheel "$TEMP_ROOT"
  /bin/chmod 0700 "$TEMP_ROOT"
}

apply_identity() {
  assert_root_apply
  assert_identity trading-research 450 450
  assert_identity trading-executor 451 451
  assert_identity trading-control 452 452
  assert_system_db_ancestors
  acquire_lock
  if /usr/bin/id -u trading-public-collector >/dev/null 2>&1; then
    assert_collector_identity_exact
  else
    assert_directory_id_unused /Users UniqueID 453
    if /usr/bin/dscl . -read /Groups/trading-public-collector >/dev/null 2>&1; then
      [ "$(dscl_value /Groups/trading-public-collector PrimaryGroupID)" = 453 ] || die 'partial collector group differs'
      assert_directory_id_singleton /Groups PrimaryGroupID 453 trading-public-collector
    else
      assert_directory_id_unused /Groups PrimaryGroupID 453
      /usr/bin/dscl . -create /Groups/trading-public-collector
      /usr/bin/dscl . -create /Groups/trading-public-collector PrimaryGroupID 453
      /usr/bin/dscl . -create /Groups/trading-public-collector RealName 'Trading Desk Public Collector'
    fi
    /usr/bin/dscl . -create /Users/trading-public-collector
    /usr/bin/dscl . -create /Users/trading-public-collector UniqueID 453
    /usr/bin/dscl . -create /Users/trading-public-collector PrimaryGroupID 453
    /usr/bin/dscl . -create /Users/trading-public-collector NFSHomeDirectory /var/empty
    /usr/bin/dscl . -create /Users/trading-public-collector UserShell /usr/bin/false
    /usr/bin/dscl . -create /Users/trading-public-collector RealName 'Trading Desk Public Collector'
    /usr/bin/dscl . -create /Users/trading-public-collector IsHidden 1
    /usr/bin/dscl . -create /Users/trading-public-collector AuthenticationAuthority ';DisabledUser;'
    /usr/bin/dscl . -create /Users/trading-public-collector Password '*'
    /usr/bin/dscacheutil -flushcache
    assert_collector_identity_exact
  fi
  assert_collector_identity_exact
  write_identity_receipt "$COLLECTOR_IDENTITY_RECEIPT" collector trading-public-collector 453 453 /var/empty
  /bin/echo 'IDENTITY_COMPLETE exact disabled, hidden, no-home UID/GID 453'
}

apply_router_identity() {
  assert_root_apply
  assert_identity trading-research 450 450
  assert_identity trading-executor 451 451
  assert_identity trading-control 452 452
  assert_system_db_ancestors
  acquire_lock
  if /usr/bin/id -u trading-router-operator >/dev/null 2>&1; then
    assert_router_identity_exact
  else
    assert_directory_id_unused /Users UniqueID 454
    if /usr/bin/dscl . -read /Groups/trading-router-operator >/dev/null 2>&1; then
      [ "$(dscl_value /Groups/trading-router-operator PrimaryGroupID)" = 454 ] || die 'partial router operator group differs'
      assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator
    else
      assert_directory_id_unused /Groups PrimaryGroupID 454
      /usr/bin/dscl . -create /Groups/trading-router-operator
      /usr/bin/dscl . -create /Groups/trading-router-operator PrimaryGroupID 454
      /usr/bin/dscl . -create /Groups/trading-router-operator RealName 'Trading Desk Router Operator'
    fi
    /usr/bin/dscl . -create /Users/trading-router-operator
    /usr/bin/dscl . -create /Users/trading-router-operator UniqueID 454
    /usr/bin/dscl . -create /Users/trading-router-operator PrimaryGroupID 454
    /usr/bin/dscl . -create /Users/trading-router-operator NFSHomeDirectory "$LIMA_HOME"
    /usr/bin/dscl . -create /Users/trading-router-operator UserShell /usr/bin/false
    /usr/bin/dscl . -create /Users/trading-router-operator RealName 'Trading Desk Router Operator'
    /usr/bin/dscl . -create /Users/trading-router-operator IsHidden 1
    /usr/bin/dscl . -create /Users/trading-router-operator AuthenticationAuthority ';DisabledUser;'
    /usr/bin/dscl . -create /Users/trading-router-operator Password '*'
    /usr/bin/dscacheutil -flushcache
    assert_router_identity_exact
  fi
  assert_router_identity_exact
  ensure_directory "$LIMA_HOME" 454 454 700 NONE
  fullsync_paths "$LIMA_HOME" /private/var/db
  write_identity_receipt "$ROUTER_IDENTITY_RECEIPT" router trading-router-operator 454 454 "$LIMA_HOME"
  /bin/echo "ROUTER_IDENTITY_COMPLETE exact disabled UID/GID 454 lima_home=$LIMA_HOME"
}

write_acl_templates() {
  ACL_TRADING_ROOT=$TEMP_ROOT/acl-trading-root
  ACL_CONTROL_TRAVERSE=$TEMP_ROOT/acl-control-traverse
  ACL_FOREGROUND_ROOT=$TEMP_ROOT/acl-foreground-root
  ACL_CONFIG_PARENT=$TEMP_ROOT/acl-config-parent
  ACL_CONFIG_FILE=$TEMP_ROOT/acl-config-file
  ACL_EXECUTION_PRE=$TEMP_ROOT/acl-execution-pre
  ACL_EXECUTION_POST=$TEMP_ROOT/acl-execution-post
  ACL_EXECUTION_MAIN=$TEMP_ROOT/acl-execution-main
  ACL_LEARNING_PRE=$TEMP_ROOT/acl-learning-pre
  ACL_LEARNING_POST=$TEMP_ROOT/acl-learning-post
  ACL_LEARNING_MAIN=$TEMP_ROOT/acl-learning-main
  ACL_SOCKET_PARENT=$TEMP_ROOT/acl-socket-parent
  ACL_HANDOFF=$TEMP_ROOT/acl-handoff
  ACL_READY=$TEMP_ROOT/acl-ready
  ACL_PRESENTATION_ROOT=$TEMP_ROOT/acl-presentation-root
  ACL_PRESENTATION_CONFIG=$TEMP_ROOT/acl-presentation-config
  ACL_EVIDENCE=$TEMP_ROOT/acl-evidence
  ACL_QUOTE=$TEMP_ROOT/acl-quote
  ACL_REGISTRATION=$TEMP_ROOT/acl-registration
  {
    /bin/echo 'user:trading-executor allow search'
    /bin/echo 'user:trading-control allow search'
  } > "$ACL_TRADING_ROOT"
  /bin/echo 'user:trading-control allow search' > "$ACL_CONTROL_TRAVERSE"
  {
    /bin/echo 'user:trading-executor allow search'
    /bin/echo 'user:trading-control allow search'
    /bin/echo 'user:trading-research allow search'
  } > "$ACL_FOREGROUND_ROOT"
  {
    /bin/echo 'user:trading-research allow search'
    /bin/echo 'user:trading-executor allow search'
    /bin/echo 'user:trading-control allow search'
    /bin/echo 'user:trading-public-collector allow search'
  } > "$ACL_CONFIG_PARENT"
  {
    /bin/echo 'user:trading-research allow read'
    /bin/echo 'user:trading-executor allow read'
    /bin/echo 'user:trading-control allow read'
    /bin/echo 'user:trading-public-collector allow read'
  } > "$ACL_CONFIG_FILE"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
  } > "$ACL_EXECUTION_PRE"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
  } > "$ACL_EXECUTION_POST"
  {
    /bin/echo 'user:trading-control inherited allow read,write,readattr'
    /bin/echo 'user:trading-executor inherited allow read,write,readattr'
  } > "$ACL_EXECUTION_MAIN"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-research allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-research allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-research allow delete,directory_inherit,only_inherit'
  } > "$ACL_LEARNING_PRE"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-research allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-research allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-research allow delete,directory_inherit,only_inherit'
  } > "$ACL_LEARNING_POST"
  {
    /bin/echo 'user:trading-control inherited allow read,write,readattr'
    /bin/echo 'user:trading-research inherited allow read,write,readattr'
    /bin/echo 'user:trading-executor inherited allow read,write,readattr'
  } > "$ACL_LEARNING_MAIN"
  /bin/echo 'user:jawndiego allow search' > "$ACL_SOCKET_PARENT"
  /bin/echo 'user:trading-executor allow search' > "$ACL_HANDOFF"
  /bin/echo 'user:trading-executor allow list,search' > "$ACL_READY"
  /bin/echo 'user:trading-research allow search' > "$ACL_PRESENTATION_ROOT"
  {
    /bin/echo 'user:trading-research allow search'
    /bin/echo 'user:trading-research allow read,file_inherit,only_inherit'
  } > "$ACL_PRESENTATION_CONFIG"
  /bin/echo 'user:trading-control allow search' > "$ACL_EVIDENCE"
  /bin/echo 'user:trading-research allow list,search' > "$ACL_QUOTE"
  /bin/echo 'user:trading-control allow search' > "$ACL_REGISTRATION"
}

render_config() {
  assert_regular "$PROFILE" 0 0 400
  assert_no_acl "$PROFILE"
  rendered=$TEMP_ROOT/testnet-executor.toml
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$PYTHON" -B -I "$RENDERER" --profile "$PROFILE" --render > "$rendered"
  CONFIG_HASH=$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$PYTHON" -B -I "$RENDERER" --profile "$PROFILE" --config-hash)
  /bin/echo "$CONFIG_HASH" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 'renderer returned an invalid config hash'
  [ -s "$rendered" ] || die 'renderer returned an empty executor config'
  /usr/sbin/chown root:wheel "$rendered"
  /bin/chmod 0400 "$rendered"
  if [ -e "$CONFIG" ] || [ -L "$CONFIG" ]; then
    assert_regular "$CONFIG" 0 0 400
    /usr/bin/cmp -s "$rendered" "$CONFIG" || die 'existing executor config differs from public profile'
    assert_acl_exact "$CONFIG" "$ACL_CONFIG_FILE"
  else
    /bin/mv "$rendered" "$CONFIG"
    /bin/chmod -E "$CONFIG" < "$ACL_CONFIG_FILE"
    assert_regular "$CONFIG" 0 0 400
    assert_acl_exact "$CONFIG" "$ACL_CONFIG_FILE"
  fi
  fullsync_paths "$CONFIG" /etc/trading-desk
  CONFIG_SHA256=$(/usr/bin/openssl dgst -sha256 "$CONFIG" | /usr/bin/awk '{print $2}')
  PROFILE_SHA256=$(/usr/bin/openssl dgst -sha256 "$PROFILE" | /usr/bin/awk '{print $2}')
}

write_receipt() {
  target=$1
  phase=$2
  mode=${3-publish}
  case "$mode" in publish|verify-only) ;; *) die 'receipt mode is invalid' ;; esac
  pending=$TEMP_ROOT/$phase.receipt
  {
    /bin/echo 'schema_version=1'
    /bin/echo "phase=$phase"
    /bin/echo "config_hash=$CONFIG_HASH"
    /bin/echo "profile_sha256=$PROFILE_SHA256"
    /bin/echo "config_sha256=$CONFIG_SHA256"
    /bin/echo "chat_store_init_helper_sha256=$CHAT_STORE_INIT_HELPER_SHA256"
    /bin/echo "state_root=$FOREGROUND_ROOT"
    /bin/echo 'apfs_quota_required=false'
    /bin/echo 'launchd_installed=false'
    /bin/echo 'credential_loaded=false'
    /bin/echo 'network_changed=false'
    /bin/echo 'venue_write_attempted=false'
    /bin/echo 'mainnet_authorized=false'
  } > "$pending"
  /usr/sbin/chown root:wheel "$pending"
  /bin/chmod 0400 "$pending"
  fullsync_paths "$pending"
  if [ "$phase" = postinit ]; then
    POSTINIT_EXPECTED_RECEIPT=$TEMP_ROOT/postinit-receipt.expected
    /bin/cp "$pending" "$POSTINIT_EXPECTED_RECEIPT"
    /usr/sbin/chown root:wheel "$POSTINIT_EXPECTED_RECEIPT"
    /bin/chmod 0400 "$POSTINIT_EXPECTED_RECEIPT"
  fi
  if [ "$mode" = verify-only ]; then
    [ -e "$target" ] && [ ! -L "$target" ] || die "required receipt is missing: $target"
    assert_regular "$target" 0 0 400
    assert_no_acl "$target"
    /usr/bin/cmp -s "$target" "$pending" || die "existing receipt differs: $target"
    return
  fi
  if [ -e "$target" ] || [ -L "$target" ]; then
    assert_regular "$target" 0 0 400
    assert_no_acl "$target"
    /usr/bin/cmp -s "$target" "$pending" || die "existing receipt differs: $target"
  else
    /bin/mv "$pending" "$target"
    assert_regular "$target" 0 0 400
    assert_no_acl "$target"
  fi
  fullsync_paths "$target" /etc/trading-desk
}

assert_system_db_ancestors() {
  for path in /private /private/var /private/var/db; do
    assert_directory "$path" 0 0 755
    assert_no_acl "$path"
  done
  assert_directory /private/var/run 0 0 755
  assert_no_acl /private/var/run
}

apply_preinit() {
  assert_root_apply
  assert_fixed_identities
  acquire_lock
  write_acl_templates
  assert_system_db_ancestors

  assert_directory /etc/trading-desk 0 0 700
  set_or_assert_acl /etc/trading-desk "$ACL_CONFIG_PARENT"
  render_config
  [ ! -e "$PREINIT_RECEIPT" ] && [ ! -L "$PREINIT_RECEIPT" ] || die 'pre-init receipt already exists; do not replay the pre-init phase'

  ensure_directory "$FOREGROUND_ROOT" 0 0 700 "$ACL_FOREGROUND_ROOT"
  ensure_directory "$EXECUTION" 451 451 700 "$ACL_EXECUTION_PRE"
  ensure_directory "$NONCE" 451 451 700 NONE
  ensure_directory "$DAILY_LOSS" 451 451 700 NONE
  ensure_directory "$LEARNING" 451 451 700 "$ACL_LEARNING_PRE"
  ensure_directory "$EXECUTOR_SOCKET" 451 451 700 NONE
  for path in "$EXECUTION" "$NONCE" "$DAILY_LOSS" "$LEARNING" "$EXECUTOR_SOCKET"; do
    assert_empty "$path"
  done

  ensure_directory "$TRADING_DB_ROOT" 0 0 700 "$ACL_TRADING_ROOT"
  ensure_directory "$CONTROL_PRIVATE" 0 0 700 "$ACL_CONTROL_TRAVERSE"
  ensure_directory "$CHAT_STATE" 452 452 700 NONE
  ensure_directory "$CHAT_GENERATIONS" 452 452 700 NONE
  ensure_directory "$CHAT_SOCKET_PARENT" 452 452 700 "$ACL_SOCKET_PARENT"
  [ ! -e "$CHAT_SOCKET_PARENT/testnet-chat-approval.sock" ] && [ ! -L "$CHAT_SOCKET_PARENT/testnet-chat-approval.sock" ] || die 'stale chat socket exists'
  assert_empty "$CHAT_SOCKET_PARENT"
  [ ! -e "$CHAT_DATABASE" ] && [ ! -L "$CHAT_DATABASE" ] || die 'chat database exists before the documented init checkpoint'
  assert_empty "$CHAT_GENERATIONS"

  HANDOFF_CONFIG=$HANDOFF_ROOT/$CONFIG_HASH
  READY_CONFIG=$READY_ROOT/$CONFIG_HASH
  PRESENTATION_CONFIG=$PRESENTATION_ROOT/$CONFIG_HASH
  EVIDENCE_CONFIG=$EVIDENCE_ROOT/$CONFIG_HASH
  QUOTE_CONFIG=$QUOTE_ROOT/$CONFIG_HASH
  REGISTRATION_CONFIG=$REGISTRATION_ROOT/$CONFIG_HASH
  ROUTE_CONFIG=$ROUTE_ROOT/$CONFIG_HASH
  REMOTE_ROUTE_CONFIG=$REMOTE_ROUTE_ROOT/$CONFIG_HASH

  ensure_directory "$HANDOFF_ROOT" 452 452 700 "$ACL_HANDOFF"
  ensure_directory "$HANDOFF_CONFIG" 452 452 700 "$ACL_HANDOFF"
  ensure_directory "$READY_ROOT" 452 452 700 "$ACL_READY"
  ensure_directory "$READY_CONFIG" 452 452 700 "$ACL_READY"
  ensure_directory "$PRESENTATION_ROOT" 452 452 700 "$ACL_PRESENTATION_ROOT"
  ensure_directory "$PRESENTATION_CONFIG" 452 452 700 "$ACL_PRESENTATION_CONFIG"
  ensure_directory "$EVIDENCE_ROOT" 453 453 700 "$ACL_EVIDENCE"
  ensure_directory "$EVIDENCE_CONFIG" 453 453 700 "$ACL_EVIDENCE"
  ensure_directory "$QUOTE_ROOT" 453 453 700 "$ACL_QUOTE"
  ensure_directory "$QUOTE_CONFIG" 453 453 700 "$ACL_QUOTE"
  ensure_directory "$REGISTRATION_ROOT" 451 451 700 "$ACL_REGISTRATION"
  ensure_directory "$REGISTRATION_CONFIG" 451 451 700 "$ACL_REGISTRATION"
  ensure_directory "$ROUTE_ROOT" 0 0 755 NONE
  ensure_directory "$ROUTE_CONFIG" 0 0 755 NONE
  ensure_directory "$REMOTE_ROUTE_ROOT" 0 0 755 NONE
  ensure_directory "$REMOTE_ROUTE_CONFIG" 0 0 755 NONE

  for path in "$HANDOFF_CONFIG" "$READY_CONFIG" "$PRESENTATION_CONFIG" \
    "$EVIDENCE_CONFIG" "$QUOTE_CONFIG" "$REGISTRATION_CONFIG" \
    "$ROUTE_CONFIG" "$REMOTE_ROUTE_CONFIG"; do
    assert_empty "$path"
  done

  fullsync_paths "$EXECUTION" "$NONCE" "$DAILY_LOSS" "$LEARNING" \
    "$EXECUTOR_SOCKET" "$FOREGROUND_ROOT" "$CHAT_GENERATIONS" \
    "$CHAT_STATE" "$CONTROL_PRIVATE" "$TRADING_DB_ROOT" \
    "$CHAT_SOCKET_PARENT" /private/var/run "$HANDOFF_CONFIG" "$HANDOFF_ROOT" \
    "$READY_CONFIG" "$READY_ROOT" "$PRESENTATION_CONFIG" \
    "$PRESENTATION_ROOT" "$EVIDENCE_CONFIG" "$EVIDENCE_ROOT" \
    "$QUOTE_CONFIG" "$QUOTE_ROOT" "$REGISTRATION_CONFIG" \
    "$REGISTRATION_ROOT" "$ROUTE_CONFIG" "$ROUTE_ROOT" \
    "$REMOTE_ROUTE_CONFIG" "$REMOTE_ROUTE_ROOT" /private/var/db

  write_receipt "$PREINIT_RECEIPT" preinit
  /bin/echo "PREINIT_COMPLETE config_hash=$CONFIG_HASH"
  /bin/echo 'No database was initialized; run only the documented foreground init checkpoint, then --apply-postinit.'
}

assert_initialized_main_acl() {
  path=$1
  role=$2
  entries=$(acl_export "$path")
  case "$role" in
    private)
      [ -z "$entries" ] || die "private main has a named ACL: $path"
      ;;
    execution)
      assert_acl_export_exact "$path" "$ACL_EXECUTION_MAIN"
      ;;
    learning)
      assert_acl_export_exact "$path" "$ACL_LEARNING_MAIN"
      ;;
    *) die 'unknown initialized main role' ;;
  esac
}

snapshot_mains() {
  output=$1
  : > "$output"
  for path in "$EXECUTION/execution.sqlite3" "$NONCE/nonce.sqlite3" \
    "$DAILY_LOSS/daily-loss.sqlite3" "$LEARNING/learning.sqlite3" \
    "$LEARNING/staging.sqlite3" "$CHAT_DATABASE"; do
    /usr/bin/stat -f '%N|device=%d|inode=%i|owner=%u|group=%g|mode=%Lp|size=%z|links=%l' "$path" >> "$output"
    /usr/bin/openssl dgst -sha256 "$path" >> "$output"
    /bin/ls -led "$path" >> "$output"
  done
}

run_as() {
  identity=$1
  shift
  /usr/bin/sudo -n -u "$identity" -- "$@"
}

verify_initialized_layout() {
  for path in "$EXECUTION/execution.sqlite3" "$NONCE/nonce.sqlite3" \
    "$DAILY_LOSS/daily-loss.sqlite3" "$LEARNING/learning.sqlite3" \
    "$LEARNING/staging.sqlite3"; do
    assert_regular "$path" 451 451 600
    [ "$(/usr/bin/stat -f %z "$path")" -gt 0 ] || die "initialized database is empty: $path"
  done
  assert_initialized_main_acl "$EXECUTION/execution.sqlite3" execution
  assert_initialized_main_acl "$NONCE/nonce.sqlite3" private
  assert_initialized_main_acl "$DAILY_LOSS/daily-loss.sqlite3" private
  assert_initialized_main_acl "$LEARNING/learning.sqlite3" learning
  assert_initialized_main_acl "$LEARNING/staging.sqlite3" learning
  assert_regular "$CHAT_DATABASE" 452 452 600
  [ "$(/usr/bin/stat -f %z "$CHAT_DATABASE")" -gt 0 ] || die 'chat approval database is empty'
  assert_no_acl "$CHAT_DATABASE"
  for suffix in -wal -shm -journal; do
    path=$CHAT_DATABASE$suffix
    if [ -e "$path" ] || [ -L "$path" ]; then
      assert_regular "$path" 452 452 600
      assert_no_acl "$path"
    fi
  done
  run_as trading-control /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$EXECUTOR_PYTHON" -B -I -c \
    'from pathlib import Path; from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore; TestnetChatApprovalStore(Path("/private/var/db/trading-desk/control-private/chat-approval/chat-approval.sqlite3"), must_exist=True)'
  assert_regular "$CHAT_DATABASE" 452 452 600
  assert_no_acl "$CHAT_DATABASE"
  for suffix in -wal -shm -journal; do
    path=$CHAT_DATABASE$suffix
    if [ -e "$path" ] || [ -L "$path" ]; then
      assert_regular "$path" 452 452 600
      assert_no_acl "$path"
    fi
  done
}

apply_postinit() {
  assert_root_apply
  assert_fixed_identities
  acquire_lock
  write_acl_templates
  assert_system_db_ancestors
  assert_directory /etc/trading-desk 0 0 700
  assert_acl_exact /etc/trading-desk "$ACL_CONFIG_PARENT"
  render_config
  [ -e "$PREINIT_RECEIPT" ] && [ ! -L "$PREINIT_RECEIPT" ] || die 'pre-init receipt is missing; post-init cannot manufacture it'
  assert_regular "$PREINIT_RECEIPT" 0 0 400
  assert_no_acl "$PREINIT_RECEIPT"
  write_receipt "$PREINIT_RECEIPT" preinit verify-only

  assert_directory "$EXECUTION" 451 451 700
  assert_directory "$NONCE" 451 451 700
  assert_directory "$DAILY_LOSS" 451 451 700
  assert_directory "$LEARNING" 451 451 700
  assert_directory "$EXECUTOR_SOCKET" 451 451 700
  assert_acl_exact "$EXECUTION" "$ACL_EXECUTION_PRE"
  assert_acl_exact "$LEARNING" "$ACL_LEARNING_PRE"
  assert_no_acl "$NONCE"
  assert_no_acl "$DAILY_LOSS"
  assert_no_acl "$EXECUTOR_SOCKET"
  verify_initialized_layout
  [ ! -e "$POSTINIT_RECEIPT" ] && [ ! -L "$POSTINIT_RECEIPT" ] || die 'post-init receipt already exists; do not replay the conversion'

  before=$TEMP_ROOT/mains-before
  after=$TEMP_ROOT/mains-after
  EXECUTION_ACL_BACKUP=$TEMP_ROOT/execution-before.acl
  LEARNING_ACL_BACKUP=$TEMP_ROOT/learning-before.acl
  snapshot_mains "$before"
  acl_export "$EXECUTION" > "$EXECUTION_ACL_BACKUP"
  acl_export "$LEARNING" > "$LEARNING_ACL_BACKUP"

  POSTINIT_CHANGED=1
  /bin/chmod -E "$EXECUTION" < "$ACL_EXECUTION_POST"
  /bin/chmod -E "$LEARNING" < "$ACL_LEARNING_POST"
  assert_acl_exact "$EXECUTION" "$ACL_EXECUTION_POST"
  assert_acl_exact "$LEARNING" "$ACL_LEARNING_POST"
  if acl_export "$EXECUTION" | /usr/bin/grep -q delete_child; then
    die 'execution parent gained delete_child'
  fi
  if acl_export "$LEARNING" | /usr/bin/grep -q delete_child; then
    die 'learning parent gained delete_child'
  fi

  exec_probe=$EXECUTION/.foreground-postinit-sidecar
  learn_control_probe=$LEARNING/.foreground-postinit-control-sidecar
  learn_research_probe=$LEARNING/.foreground-postinit-research-sidecar
  run_as trading-executor /usr/bin/touch "$exec_probe"
  run_as trading-control /bin/rm "$exec_probe"
  run_as trading-control /usr/bin/touch "$learn_control_probe"
  run_as trading-executor /bin/rm "$learn_control_probe"
  run_as trading-research /usr/bin/touch "$learn_research_probe"
  run_as trading-executor /bin/rm "$learn_research_probe"
  fullsync_paths "$EXECUTION" "$LEARNING"

  snapshot_mains "$after"
  /usr/bin/cmp -s "$before" "$after" || die 'authoritative database bytes, inode, owner, mode, links, or ACL changed during post-init'
  verify_initialized_layout
  snapshot_mains "$after"
  /usr/bin/cmp -s "$before" "$after" || die 'authoritative database changed during final must-exist verification'
  write_receipt "$POSTINIT_RECEIPT" postinit
  POSTINIT_COMMITTED=1
  /bin/echo "POSTINIT_COMPLETE config_hash=$CONFIG_HASH"
  /bin/echo 'Foreground paths are commissioned; no service, credential, network, or venue action was performed.'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die 'plan takes no arguments'
    plan
    ;;
  --apply-identity)
    [ "$#" -eq 1 ] || die '--apply-identity takes no additional arguments'
    apply_identity
    ;;
  --apply-router-identity)
    [ "$#" -eq 1 ] || die '--apply-router-identity takes no additional arguments'
    apply_router_identity
    ;;
  --apply-preinit)
    [ "$#" -eq 1 ] || die '--apply-preinit takes no additional arguments'
    apply_preinit
    ;;
  --apply-postinit)
    [ "$#" -eq 1 ] || die '--apply-postinit takes no additional arguments'
    apply_postinit
    ;;
  *)
    die 'unknown phase; run with no arguments for the plan'
    ;;
esac
