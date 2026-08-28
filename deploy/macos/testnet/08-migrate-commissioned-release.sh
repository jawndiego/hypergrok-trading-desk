#!/bin/sh
set -eu
umask 077

# This wrapper upgrades only the exact foreground TESTNET commissioning.  The
# sibling v1 installer remains first-install-only and exclusively constructs
# the new immutable release while current is parked under a bound name.
NEW_COMMIT=9d5825f67519f41713f0f2002756fe8b303f79ee
NEW_RECEIPT_SHA256=0ad59c49bba4e6595bceee9dfc2781246fcdf4b4a3f52d6cbeaf1065753adbf8
EXPECTED_INSTALLER_SHA256=3d1ea2736bb302834715418e162534735f1d6e08a3961be6001d0e0710978594
REBIND_REQUIRED=0

OLD_COMMIT=579744653593d2e853d5f09c1fc6db5a13f40f97
OLD_RECEIPT_SHA256=537a96aa54d7c1f04a3d50b60efb5e769398e18fd01ff26c75368d7d76c1df64
PROFILE_SHA256=f859fc7a3f216bbc848cf152d72d482efb2208ab1bf4192ac5d8daafee807104
CONFIG_SHA256=458261ecc9d0a63334024167598d833f51ea95298c39c7615bbb207b4a68f6a5
PREINIT_RECEIPT_SHA256=62e2769a551b7d73f184585d81e3c78bfe61754a795a0e729fe2d1a357c48411
POSTINIT_RECEIPT_SHA256=35ea1608009791d7a6e48b55a310d8f74d8c18a750b82c939b6f0344204f996a
SIDECAR_ACL_RECEIPT_SHA256=04438f0c65933bd16e1db3bb5c5b52aa3417a35dca4cd979095b76f2ce247c64
CONFIG_HASH=1344975159f115718f5b5ac0f9d96c296d862542c75620bc8b52e4753eacd109

TRADING_ROOT=/opt/trading-desk
RELEASES_PARENT=$TRADING_ROOT/releases
OLD_RELEASE=$RELEASES_PARENT/$OLD_COMMIT
NEW_RELEASE=$RELEASES_PARENT/$NEW_COMMIT
CURRENT_LINK=$TRADING_ROOT/current
PARKED_LINK=$TRADING_ROOT/.commissioned-upgrade-old-$OLD_COMMIT-to-$NEW_COMMIT
RETAINED_OLD_LINK=$TRADING_ROOT/.commissioned-current-$OLD_COMMIT-before-$NEW_COMMIT
FAILED_NEW_LINK=$TRADING_ROOT/.failed-current-$NEW_COMMIT
ADMIN_PYTHON=$TRADING_ROOT/runtime/python-3.11.16/bin/python3.11
PROFILE=/private/etc/trading-desk/testnet-foreground-profile.json
CONFIG=/private/etc/trading-desk/testnet-executor.toml
PREINIT_RECEIPT=/private/etc/trading-desk/testnet-foreground-preinit.receipt
POSTINIT_RECEIPT=/private/etc/trading-desk/testnet-foreground-postinit.receipt
SIDECAR_ACL_RECEIPT=/private/etc/trading-desk/testnet-foreground-sidecar-acl-repair-v1.receipt
FOREGROUND_ROOT=/private/var/db/trading-desk-testnet-foreground
CHAT_ROOT=/private/var/db/trading-desk/control-private/chat-approval
INSTALLER=
SCRIPT_DIR=
SNAPSHOT_ROOT=

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no release, pointer, config, database, credential, service, process, network, or venue state changed'
  /bin/echo "old_commit=$OLD_COMMIT"
  /bin/echo "old_receipt_sha256=$OLD_RECEIPT_SHA256"
  /bin/echo "new_commit=$NEW_COMMIT"
  /bin/echo "new_receipt_sha256=$NEW_RECEIPT_SHA256"
  /bin/echo "expected_installer_sha256=$EXPECTED_INSTALLER_SHA256"
  /bin/echo "config_hash=$CONFIG_HASH"
  /bin/echo "rebind_required=$REBIND_REQUIRED"
  /bin/echo 'Apply: --apply ABSOLUTE_ROOT_OWNED_SEALED_MEDIA'
  /bin/echo 'Restore while current is absent: --restore-old'
  /bin/echo 'Rollback a new unqualified current: --rollback-new'
  /bin/echo 'Requalify the exact retained failed new release: --retry-failed'
  /bin/echo 'Quarantine an incomplete new release while current is absent: --quarantine-incomplete'
  /bin/echo 'The old release and pointer are retained; persistent TESTNET state is snapshot-compared before and after qualification.'
}

digest() {
  local path rendered value
  path=$1
  rendered=$(/usr/bin/openssl dgst -sha256 "$path") || die "SHA-256 read failed: $path"
  value=${rendered##* }
  /usr/bin/printf '%s\n' "$value" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die "SHA-256 output is invalid: $path"
  /usr/bin/printf '%s\n' "$value"
}

acl_entries() {
  local path rendered
  path=$1
  rendered=$(/bin/ls -led "$path") || die "ACL read failed: $path"
  /usr/bin/printf '%s\n' "$rendered" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p'
}

assert_no_acl() {
  local path
  path=$1
  [ -z "$(acl_entries "$path")" ] || die "unexpected named ACL: $path"
}

assert_absent() {
  local path
  path=$1
  [ ! -e "$path" ] && [ ! -L "$path" ] || die "path must be absent: $path"
}

assert_secure_directory() {
  local path mode
  path=$1
  mode=$2
  [ -d "$path" ] && [ ! -L "$path" ] || die "secure directory is unavailable: $path"
  [ "$(/bin/realpath "$path")" = "$path" ] || die "secure directory is non-canonical: $path"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$path")" = "0:0:$mode" ] || die "secure directory metadata differs: $path"
  assert_no_acl "$path"
}

assert_root_sealed_chain() {
  local cursor
  cursor=$1
  case "$cursor" in /*) ;; *) die "sealed path must be absolute: $cursor" ;; esac
  [ "$(/bin/realpath "$cursor")" = "$cursor" ] || die "sealed path is non-canonical: $cursor"
  while :; do
    [ -d "$cursor" ] && [ ! -L "$cursor" ] || die "sealed ancestor is unavailable: $cursor"
    [ "$(/usr/bin/stat -f %u "$cursor")" = 0 ] || die "sealed ancestor is not root-owned: $cursor"
    [ "$(/usr/bin/stat -f %g "$cursor")" = 0 ] || die "sealed ancestor group is not wheel: $cursor"
    [ -z "$(/usr/bin/find "$cursor" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed ancestor is group/world writable: $cursor"
    assert_no_acl "$cursor"
    [ "$cursor" = / ] && break
    cursor=$(/usr/bin/dirname "$cursor")
  done
}

assert_root_sealed_file() {
  local path
  path=$1
  [ -f "$path" ] && [ ! -L "$path" ] || die "sealed file is unavailable: $path"
  [ "$(/bin/realpath "$path")" = "$path" ] || die "sealed file is non-canonical: $path"
  [ "$(/usr/bin/stat -f '%u:%g:%l' "$path")" = 0:0:1 ] || die "sealed file metadata differs: $path"
  [ -z "$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed file is group/world writable: $path"
  assert_no_acl "$path"
}

assert_sealed_media() {
  local media first
  media=$1
  assert_root_sealed_chain "$media"
  first=$(/usr/bin/find "$media" ! -type d ! -type f -print -quit)
  [ -z "$first" ] || die "sealed media contains a special path: $first"
  first=$(/usr/bin/find "$media" ! -user root -print -quit)
  [ -z "$first" ] || die "sealed media contains a non-root path: $first"
  first=$(/usr/bin/find "$media" ! -group wheel -print -quit)
  [ -z "$first" ] || die "sealed media contains a non-wheel path: $first"
  first=$(/usr/bin/find "$media" -perm +022 -print -quit)
  [ -z "$first" ] || die "sealed media contains a group/world-writable path: $first"
  first=$(/usr/bin/find "$media" -type f -links +1 -print -quit)
  [ -z "$first" ] || die "sealed media contains a hard-linked file: $first"
  first=$(/usr/bin/find "$media" -acl -print -quit)
  [ -z "$first" ] || die "sealed media contains a named ACL: $first"
}

require_bound_release() {
  [ "$REBIND_REQUIRED" = 0 ] || die 'commissioned release binding is incomplete'
  for value in "$NEW_COMMIT" "$OLD_COMMIT"; do
    /bin/echo "$value" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' || die 'bound commit is invalid'
  done
  for value in "$NEW_RECEIPT_SHA256" "$OLD_RECEIPT_SHA256" \
    "$EXPECTED_INSTALLER_SHA256" "$PROFILE_SHA256" "$CONFIG_SHA256" \
    "$PREINIT_RECEIPT_SHA256" "$POSTINIT_RECEIPT_SHA256" \
    "$SIDECAR_ACL_RECEIPT_SHA256" "$CONFIG_HASH"; do
    /bin/echo "$value" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 'bound SHA-256 value is invalid'
  done
  [ "$NEW_COMMIT" != "$OLD_COMMIT" ] || die 'replacement commit must differ'
}

assert_sealed_programs() {
  [ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || die 'migration requires real/effective root'
  case "$0" in /*) ;; *) die 'migration apply requires an absolute script path' ;; esac
  [ ! -L "$0" ] && [ "$(/bin/realpath "$0")" = "$0" ] || die 'migration script is symlinked or non-canonical'
  SCRIPT_DIR=$(/usr/bin/dirname "$0")
  assert_root_sealed_chain "$SCRIPT_DIR"
  assert_root_sealed_file "$0"
  INSTALLER=$SCRIPT_DIR/04-install-merged-main.sh
  assert_root_sealed_file "$INSTALLER"
  [ "$(digest "$INSTALLER")" = "$EXPECTED_INSTALLER_SHA256" ] || die 'sibling installer SHA-256 differs'
  /usr/bin/grep -Fqx "EXPECTED_COMMIT=$NEW_COMMIT" "$INSTALLER" || die 'sibling installer commit differs'
  /usr/bin/grep -Fqx "EXPECTED_RELEASE_RECEIPT_SHA256=$NEW_RECEIPT_SHA256" "$INSTALLER" || die 'sibling installer receipt differs'
  assert_root_sealed_file "$SCRIPT_DIR/storage-headroom-guard.py"
  [ -x "$ADMIN_PYTHON" ] && [ ! -L "$ADMIN_PYTHON" ] || die 'sealed admin runtime is unavailable'
  assert_root_sealed_chain "$TRADING_ROOT/runtime/python-3.11.16"
  assert_root_sealed_file "$ADMIN_PYTHON"
}

assert_ready_receipt() {
  local release receipt ready
  release=$1
  receipt=$2
  assert_secure_directory "$release" 755
  ready=$release/.READY
  [ -f "$ready" ] && [ ! -L "$ready" ] || die "READY receipt is unavailable: $ready"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$ready")" = 0:0:444:1 ] || die "READY receipt metadata differs: $ready"
  assert_no_acl "$ready"
  [ "$(digest "$ready")" = "$receipt" ] || die "READY receipt hash differs: $ready"
}

assert_release_link() {
  local link commit receipt release
  link=$1
  commit=$2
  receipt=$3
  release=$RELEASES_PARENT/$commit
  [ -L "$link" ] || die "release link is unavailable: $link"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$link")" = 0:0:755:1 ] || die "release link metadata differs: $link"
  [ "$(/usr/bin/readlink "$link")" = "releases/$commit" ] || die "release link target differs: $link"
  [ "$(/bin/realpath "$link")" = "$release" ] || die "release link escapes its exact release: $link"
  assert_ready_receipt "$release" "$receipt"
}

assert_old_current() { assert_release_link "$CURRENT_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256"; }
assert_parked_old() { assert_release_link "$PARKED_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256"; }
assert_parked_new() { assert_release_link "$PARKED_LINK" "$NEW_COMMIT" "$NEW_RECEIPT_SHA256"; }
assert_new_current() { assert_release_link "$CURRENT_LINK" "$NEW_COMMIT" "$NEW_RECEIPT_SHA256"; }
assert_failed_new() { assert_release_link "$FAILED_NEW_LINK" "$NEW_COMMIT" "$NEW_RECEIPT_SHA256"; }

assert_exact_file() {
  local path uid gid mode sha
  path=$1
  uid=$2
  gid=$3
  mode=$4
  sha=$5
  [ -f "$path" ] && [ ! -L "$path" ] || die "required file is unavailable: $path"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$path")" = "$uid:$gid:$mode:1" ] || die "required file metadata differs: $path"
  [ "$(digest "$path")" = "$sha" ] || die "required file hash differs: $path"
}

assert_state_file() {
  local path uid gid
  path=$1
  uid=$2
  gid=$3
  [ -f "$path" ] && [ ! -L "$path" ] || die "state file is unavailable: $path"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$path")" = "$uid:$gid:600:1" ] || die "state file metadata differs: $path"
  [ "$(/usr/bin/stat -f %z "$path")" -gt 0 ] || die "state file is empty: $path"
}

assert_state_directory() {
  local path uid gid
  path=$1
  uid=$2
  gid=$3
  [ -d "$path" ] && [ ! -L "$path" ] || die "state directory is unavailable: $path"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$path")" = "$uid:$gid:700" ] || die "state directory metadata differs: $path"
}

assert_config_acl() {
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$OLD_RELEASE/executor/.venv/bin/python" -B -I -c '
from pathlib import Path
from trading_harness.darwin_acl import darwin_named_acl_lines
parent_expected = (
    "user:F142D892-254A-4D6A-AD46-642636A3779F:trading-research:450:allow:execute",
    "user:9A28F3AD-315C-4913-BBC8-5B95DED8588E:trading-executor:451:allow:execute",
    "user:43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88:trading-control:452:allow:execute",
    "user:7D2A0278-B9BB-4E53-AD03-166905CB081B:trading-public-collector:453:allow:execute",
)
file_expected = (
    "user:F142D892-254A-4D6A-AD46-642636A3779F:trading-research:450:allow:read",
    "user:9A28F3AD-315C-4913-BBC8-5B95DED8588E:trading-executor:451:allow:read",
    "user:43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88:trading-control:452:allow:read",
    "user:7D2A0278-B9BB-4E53-AD03-166905CB081B:trading-public-collector:453:allow:read",
)
parent_actual = darwin_named_acl_lines(Path("/private/etc/trading-desk"))
file_actual = darwin_named_acl_lines(Path("/private/etc/trading-desk/testnet-executor.toml"))
if len(parent_actual) != len(parent_expected) or frozenset(parent_actual) != frozenset(parent_expected):
    raise RuntimeError("executor config parent ACL differs")
if len(file_actual) != len(file_expected) or frozenset(file_actual) != frozenset(file_expected):
    raise RuntimeError("executor config ACL differs")
' || die 'executor config ACL differs'
}

assert_control_ancestors() {
  assert_state_directory /private/var/db/trading-desk 0 0
  assert_state_directory /private/var/db/trading-desk/control-private 0 0
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$OLD_RELEASE/executor/.venv/bin/python" -B -I -c '
from pathlib import Path
from trading_harness.darwin_acl import darwin_named_acl_lines
trading_root = (
    "user:9A28F3AD-315C-4913-BBC8-5B95DED8588E:trading-executor:451:allow:execute",
    "user:43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88:trading-control:452:allow:execute",
)
control_private = (
    "user:43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88:trading-control:452:allow:execute",
)
trading_actual = darwin_named_acl_lines(Path("/private/var/db/trading-desk"))
control_actual = darwin_named_acl_lines(Path("/private/var/db/trading-desk/control-private"))
if len(trading_actual) != len(trading_root) or frozenset(trading_actual) != frozenset(trading_root):
    raise RuntimeError("trading database root ACL differs")
if len(control_actual) != len(control_private) or frozenset(control_actual) != frozenset(control_private):
    raise RuntimeError("control-private ACL differs")
' || die 'control database ancestor ACL differs'
}

assert_commissioned() {
  local name numeric pair
  for pair in trading-research:450 trading-executor:451 trading-control:452 trading-public-collector:453 trading-router-operator:454; do
    name=${pair%:*}
    numeric=${pair#*:}
    [ "$(/usr/bin/id -u "$name")" = "$numeric" ] || die "commissioned UID differs: $name"
    [ "$(/usr/bin/id -g "$name")" = "$numeric" ] || die "commissioned GID differs: $name"
  done
  assert_state_directory /private/etc/trading-desk 0 0
  assert_exact_file "$PROFILE" 0 0 400 "$PROFILE_SHA256"
  assert_no_acl "$PROFILE"
  assert_exact_file "$CONFIG" 0 0 400 "$CONFIG_SHA256"
  assert_config_acl
  assert_exact_file "$PREINIT_RECEIPT" 0 0 400 "$PREINIT_RECEIPT_SHA256"
  assert_no_acl "$PREINIT_RECEIPT"
  assert_exact_file "$POSTINIT_RECEIPT" 0 0 400 "$POSTINIT_RECEIPT_SHA256"
  assert_no_acl "$POSTINIT_RECEIPT"
  /usr/bin/grep -Fqx "config_hash=$CONFIG_HASH" "$PREINIT_RECEIPT" || die 'pre-init config hash differs'
  /usr/bin/grep -Fqx "config_hash=$CONFIG_HASH" "$POSTINIT_RECEIPT" || die 'post-init config hash differs'

  assert_state_directory "$FOREGROUND_ROOT" 0 0
  assert_state_directory "$FOREGROUND_ROOT/execution" 451 451
  assert_state_directory "$FOREGROUND_ROOT/nonce" 451 451
  assert_state_directory "$FOREGROUND_ROOT/daily-loss" 451 451
  assert_state_directory "$FOREGROUND_ROOT/learning" 451 451
  assert_state_directory "$FOREGROUND_ROOT/executor-socket" 451 451
  assert_state_file "$FOREGROUND_ROOT/execution/execution.sqlite3" 451 451
  assert_state_file "$FOREGROUND_ROOT/nonce/nonce.sqlite3" 451 451
  assert_state_file "$FOREGROUND_ROOT/daily-loss/daily-loss.sqlite3" 451 451
  assert_state_file "$FOREGROUND_ROOT/learning/learning.sqlite3" 451 451
  assert_state_file "$FOREGROUND_ROOT/learning/staging.sqlite3" 451 451
  assert_state_directory "$CHAT_ROOT" 452 452
  assert_state_directory "$CHAT_ROOT/broker-generations" 452 452
  assert_state_file "$CHAT_ROOT/chat-approval.sqlite3" 452 452
  assert_no_acl "$CHAT_ROOT"
  assert_no_acl "$CHAT_ROOT/broker-generations"
  assert_no_acl "$CHAT_ROOT/chat-approval.sqlite3"
  assert_control_ancestors
}

assert_quiescent() {
  local plist label processes path lsof_output lsof_error lsof_status
  local launch_output launch_error launch_status grep_status
  for plist in \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-research.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-learning-mcp.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-chat-broker.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-chat-collector.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-remote-vpn-health-collector.plist; do
    assert_absent "$plist"
  done
  launch_output=$(/usr/bin/mktemp /private/tmp/trading-desk-upgrade-launch-output.XXXXXX)
  launch_error=$(/usr/bin/mktemp /private/tmp/trading-desk-upgrade-launch-error.XXXXXX)
  launch_status=0
  /bin/launchctl print system > "$launch_output" 2> "$launch_error" || launch_status=$?
  if [ "$launch_status" != 0 ] || [ -s "$launch_error" ]; then
    /bin/cat "$launch_error" >&2
    /bin/rm -f "$launch_output" "$launch_error"
    die 'launchd system-domain inventory failed'
  fi
  for label in \
    com.jawndiego.trading-desk-research \
    com.jawndiego.trading-desk-learning-mcp \
    com.jawndiego.trading-desk-testnet-executor \
    com.jawndiego.trading-desk-testnet-chat-broker \
    com.jawndiego.trading-desk-testnet-chat-collector \
    com.jawndiego.trading-desk-remote-vpn-health-collector; do
    grep_status=0
    /usr/bin/grep -Fq "$label" "$launch_output" || grep_status=$?
    if [ "$grep_status" = 0 ]; then
      /bin/rm -f "$launch_output" "$launch_error"
      die "launchd job is loaded: $label"
    fi
    if [ "$grep_status" != 1 ]; then
      /bin/rm -f "$launch_output" "$launch_error"
      die 'launchd inventory search failed'
    fi
  done
  /bin/rm -f "$launch_output" "$launch_error"
  processes=$(/bin/ps -wwaxo uid=,command=) || die 'process inventory is unavailable'
  if /usr/bin/printf '%s\n' "$processes" | /usr/bin/awk '$1 >= 450 && $1 <= 454 {found=1} END {exit(found ? 0 : 1)}'; then
    die 'an isolated trading role process is running'
  fi
  for path in "$OLD_RELEASE" "$FOREGROUND_ROOT" "$CHAT_ROOT"; do
    lsof_output=$(/usr/bin/mktemp /private/tmp/trading-desk-upgrade-lsof-output.XXXXXX)
    lsof_error=$(/usr/bin/mktemp /private/tmp/trading-desk-upgrade-lsof-error.XXXXXX)
    lsof_status=0
    /usr/sbin/lsof -n -P +D "$path" > "$lsof_output" 2> "$lsof_error" || lsof_status=$?
    if [ "$lsof_status" = 0 ] && [ -s "$lsof_output" ]; then
      /bin/rm -f "$lsof_output" "$lsof_error"
      die "a process has an open commissioned path: $path"
    fi
    if [ "$lsof_status" != 1 ] || [ -s "$lsof_output" ] || [ -s "$lsof_error" ]; then
      /bin/cat "$lsof_error" >&2
      /bin/rm -f "$lsof_output" "$lsof_error"
      die "open-file inventory failed: $path"
    fi
    /bin/rm -f "$lsof_output" "$lsof_error"
  done
}

snapshot_commissioned() {
  local output
  output=$1
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$OLD_RELEASE/executor/.venv/bin/python" -B -I -c '
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from trading_harness.darwin_acl import darwin_named_acl_lines

output = Path(sys.argv[1])
roots = tuple(Path(value) for value in sys.argv[2:])
records: dict[str, dict[str, object]] = {}
transient_shm = {
    "/private/var/db/trading-desk-testnet-foreground/execution/execution.sqlite3-shm",
    "/private/var/db/trading-desk-testnet-foreground/nonce/nonce.sqlite3-shm",
    "/private/var/db/trading-desk-testnet-foreground/daily-loss/daily-loss.sqlite3-shm",
    "/private/var/db/trading-desk-testnet-foreground/learning/learning.sqlite3-shm",
    "/private/var/db/trading-desk-testnet-foreground/learning/staging.sqlite3-shm",
    "/private/var/db/trading-desk/control-private/chat-approval/chat-approval.sqlite3-shm",
    }

def identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_dev), int(value.st_ino), int(value.st_mode),
        int(value.st_uid), int(value.st_gid), int(value.st_nlink),
        int(value.st_size),
    )

def visit(path: Path) -> None:
    key = str(path)
    if key in records:
        return
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise RuntimeError(f"snapshot symlink rejected: {path}")
    record: dict[str, object] = {
        "path": key,
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "uid": int(before.st_uid),
        "gid": int(before.st_gid),
        "mode": stat.S_IMODE(before.st_mode),
        "links": int(before.st_nlink),
        "acl": sorted(darwin_named_acl_lines(path)),
    }
    if stat.S_ISREG(before.st_mode):
        if before.st_nlink != 1:
            raise RuntimeError(f"snapshot hard link rejected: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if identity(opened) != identity(before):
                raise RuntimeError(f"snapshot file changed before read: {path}")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            record["size"] = int(opened.st_size)
            if key in transient_shm:
                record["transient_sqlite_shm"] = True
                record.pop("device")
                record.pop("inode")
            else:
                record["sha256"] = digest.hexdigest()
        finally:
            os.close(descriptor)
    elif stat.S_ISDIR(before.st_mode):
        children = sorted((Path(item.path) for item in os.scandir(path)), key=str)
        record["children"] = [str(child) for child in children]
        records[key] = record
        for child in children:
            visit(child)
        if identity(path.lstat()) != identity(before):
            raise RuntimeError(f"snapshot directory changed during traversal: {path}")
        return
    else:
        raise RuntimeError(f"snapshot special path rejected: {path}")
    if identity(path.lstat()) != identity(before):
        raise RuntimeError(f"snapshot file changed during read: {path}")
    records[key] = record

for root in roots:
    if not root.is_absolute() or Path(os.path.normpath(str(root))) != root:
        raise RuntimeError(f"snapshot root is non-canonical: {root}")
    visit(root)
payload = {"schema_version": 1, "records": [records[key] for key in sorted(records)]}
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
try:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("snapshot write made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
' "$output" \
    /private/etc/trading-desk \
    "$FOREGROUND_ROOT" \
    "$CHAT_ROOT" \
    /private/var/db/trading-desk-testnet-chat-socket \
    /private/var/db/trading-desk-testnet-chat-handoffs \
    /private/var/db/trading-desk-testnet-chat-ready \
    /private/var/db/trading-desk-testnet-chat-presentations \
    /private/var/db/trading-desk-testnet-chat-issuance-evidence \
    /private/var/db/trading-desk-testnet-chat-account-quotes \
    /private/var/db/trading-desk-testnet-chat-executor-registration \
    /private/var/db/trading-desk-testnet-route-health \
    /private/var/db/trading-desk-testnet-remote-vpn-health \
    /private/var/db/trading-desk-lima || die 'persistent commissioned snapshot failed'
}

report_snapshot_difference() {
  local before after
  before=$1
  after=$2
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$ADMIN_PYTHON" -B -I -c '
import json, sys
with open(sys.argv[1], "r", encoding="ascii") as stream:
    before = {row["path"]: row for row in json.load(stream)["records"]}
with open(sys.argv[2], "r", encoding="ascii") as stream:
    after = {row["path"]: row for row in json.load(stream)["records"]}
for path in sorted(set(before) | set(after)):
    if path not in before:
        print(f"SNAPSHOT_DIFF path={path} fields=added", file=sys.stderr)
    elif path not in after:
        print(f"SNAPSHOT_DIFF path={path} fields=removed", file=sys.stderr)
    elif before[path] != after[path]:
        fields = sorted(key for key in set(before[path]) | set(after[path]) if before[path].get(key) != after[path].get(key))
        print(f"SNAPSHOT_DIFF path={path} fields={','.join(fields)}", file=sys.stderr)
' "$before" "$after" || /bin/echo 'SNAPSHOT_DIFF report_failed=true' >&2
}

cleanup() {
  local status
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  case "$SNAPSHOT_ROOT" in
    /private/tmp/trading-desk-commissioned-upgrade.*)
      [ ! -L "$SNAPSHOT_ROOT" ] && /usr/bin/find "$SNAPSHOT_ROOT" -depth -delete 2>/dev/null
      ;;
  esac
  exit "$status"
}

prepare_snapshots() {
  [ -z "$SNAPSHOT_ROOT" ] || return 0
  SNAPSHOT_ROOT=$(/usr/bin/mktemp -d /private/tmp/trading-desk-commissioned-upgrade.XXXXXX)
  /usr/sbin/chown root:wheel "$SNAPSHOT_ROOT"
  /bin/chmod 0700 "$SNAPSHOT_ROOT"
}

atomic_rename_exclusive() {
  local source destination
  source=$1
  destination=$2
  [ -L "$source" ] || die "exclusive-rename source is not a symlink: $source"
  assert_absent "$destination"
  [ "$(/usr/bin/dirname "$source")" = "$TRADING_ROOT" ] || die 'exclusive-rename source parent differs'
  [ "$(/usr/bin/dirname "$destination")" = "$TRADING_ROOT" ] || die 'exclusive-rename destination parent differs'
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$ADMIN_PYTHON" -B -I -c '
import ctypes, fcntl, os, sys
source, destination, parent = sys.argv[1:]
RENAME_EXCL = 0x00000004
libc = ctypes.CDLL(None, use_errno=True)
rename = libc.renamex_np
rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rename.restype = ctypes.c_int
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(parent, flags)
try:
    if not os.path.islink(source) or os.path.lexists(destination):
        raise RuntimeError("exclusive symlink rename precondition changed")
    os.fsync(fd); fcntl.fcntl(fd, 51)
    if rename(os.fsencode(source), os.fsencode(destination), RENAME_EXCL) != 0:
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
    os.fsync(fd); fcntl.fcntl(fd, 51)
finally:
    os.close(fd)
' "$source" "$destination" "$TRADING_ROOT" || die 'exclusive durable symlink rename failed'
}

atomic_swap_symlinks() {
  local first second
  first=$1
  second=$2
  [ -L "$first" ] && [ -L "$second" ] || die 'swap requires two symlinks'
  [ "$(/usr/bin/dirname "$first")" = "$TRADING_ROOT" ] || die 'swap first parent differs'
  [ "$(/usr/bin/dirname "$second")" = "$TRADING_ROOT" ] || die 'swap second parent differs'
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$ADMIN_PYTHON" -B -I -c '
import ctypes, fcntl, os, sys
first, second, parent = sys.argv[1:]
RENAME_SWAP = 0x00000002
libc = ctypes.CDLL(None, use_errno=True)
rename = libc.renamex_np
rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rename.restype = ctypes.c_int
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(parent, flags)
try:
    if not os.path.islink(first) or not os.path.islink(second):
        raise RuntimeError("swap symlink precondition changed")
    os.fsync(fd); fcntl.fcntl(fd, 51)
    if rename(os.fsencode(first), os.fsencode(second), RENAME_SWAP) != 0:
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
    os.fsync(fd); fcntl.fcntl(fd, 51)
finally:
    os.close(fd)
' "$first" "$second" "$TRADING_ROOT" || die 'atomic durable symlink swap failed'
}

migration_state() {
  if [ -L "$CURRENT_LINK" ] && [ ! -e "$PARKED_LINK" ] && [ ! -L "$PARKED_LINK" ] && \
     [ ! -e "$RETAINED_OLD_LINK" ] && [ ! -L "$RETAINED_OLD_LINK" ] && \
     [ ! -e "$FAILED_NEW_LINK" ] && [ ! -L "$FAILED_NEW_LINK" ]; then
    assert_old_current
    /bin/echo old-current
  elif [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ] && [ -L "$PARKED_LINK" ]; then
    assert_parked_old
    /bin/echo parked-current-absent
  elif [ -L "$CURRENT_LINK" ] && [ -L "$PARKED_LINK" ]; then
    if [ "$(/usr/bin/readlink "$CURRENT_LINK")" = "releases/$NEW_COMMIT" ] && \
       [ "$(/usr/bin/readlink "$PARKED_LINK")" = "releases/$OLD_COMMIT" ]; then
      assert_new_current
      assert_parked_old
      /bin/echo new-current-pending
    elif [ "$(/usr/bin/readlink "$CURRENT_LINK")" = "releases/$OLD_COMMIT" ] && \
         [ "$(/usr/bin/readlink "$PARKED_LINK")" = "releases/$NEW_COMMIT" ]; then
      assert_old_current
      assert_parked_new
      /bin/echo rollback-swapped-pending
    else
      die 'current and parked release orientation is unrecognized'
    fi
  elif [ -L "$CURRENT_LINK" ] && [ -L "$RETAINED_OLD_LINK" ] && \
       [ ! -e "$PARKED_LINK" ] && [ ! -L "$PARKED_LINK" ]; then
    assert_new_current
    assert_release_link "$RETAINED_OLD_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256"
    /bin/echo complete
  elif [ -L "$CURRENT_LINK" ] && [ -L "$FAILED_NEW_LINK" ] && \
       [ ! -e "$PARKED_LINK" ] && [ ! -L "$PARKED_LINK" ] && \
       [ ! -e "$RETAINED_OLD_LINK" ] && [ ! -L "$RETAINED_OLD_LINK" ]; then
    assert_old_current
    assert_failed_new
    /bin/echo failed-new-ready
  else
    die 'commissioned release migration state is unrecognized'
  fi
}

reject_incomplete_replacement() {
  local bootstrap
  bootstrap=$RELEASES_PARENT/.bootstrap-$NEW_COMMIT
  if [ -e "$bootstrap" ] || [ -L "$bootstrap" ]; then
    die "replacement bootstrap is retained; use --quarantine-incomplete"
  fi
  if [ -e "$NEW_RELEASE" ] || [ -L "$NEW_RELEASE" ]; then
    if [ -f "$NEW_RELEASE/.INSTALLING" ] && [ ! -L "$NEW_RELEASE/.INSTALLING" ] && \
       [ ! -e "$NEW_RELEASE/.READY" ] && [ ! -L "$NEW_RELEASE/.READY" ]; then
      die "replacement release is retained incomplete; use --quarantine-incomplete"
    fi
    [ -f "$NEW_RELEASE/.READY" ] && [ ! -e "$NEW_RELEASE/.INSTALLING" ] || die 'replacement release state requires root review'
  fi
}

verify_command_output() {
  local kind path
  kind=$1
  path=$2
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$ADMIN_PYTHON" -B -I -c '
import json, sys
kind, path, config_hash = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("shared_learning_available") is not True:
    raise RuntimeError("shared learning is unavailable")
if value.get("entry_blocked_by_shared_learning") is not False:
    raise RuntimeError("shared learning entry gate differs")
if kind == "status":
    if value.get("runtime", {}).get("config_hash") != config_hash:
        raise RuntimeError("status config hash differs")
    if value.get("work", {}).get("compatible") is not True:
        raise RuntimeError("status work scan is incompatible")
elif kind == "dry-run":
    if value.get("dry_run") is not True or value.get("local_state_changed") is not False:
        raise RuntimeError("dry-run mutation flags differ")
    if value.get("venue_write_attempted") is not False:
        raise RuntimeError("dry-run attempted a venue write")
    if value.get("step") != "startup_reconcile":
        raise RuntimeError("fresh commissioned dry-run step differs")
else:
    raise RuntimeError("unknown qualification output")
' "$kind" "$path" "$CONFIG_HASH" || die "$kind output is not the exact credential-free qualification"
}

rollback_pending() {
  local current_target parked_target
  assert_absent "$FAILED_NEW_LINK"
  [ -L "$CURRENT_LINK" ] && [ -L "$PARKED_LINK" ] || die 'rollback requires current and parked symlinks'
  current_target=$(/usr/bin/readlink "$CURRENT_LINK")
  parked_target=$(/usr/bin/readlink "$PARKED_LINK")
  if [ "$current_target" = "releases/$NEW_COMMIT" ] && \
     [ "$parked_target" = "releases/$OLD_COMMIT" ]; then
    assert_new_current
    assert_parked_old
    atomic_swap_symlinks "$CURRENT_LINK" "$PARKED_LINK"
  elif [ "$current_target" = "releases/$OLD_COMMIT" ] && \
       [ "$parked_target" = "releases/$NEW_COMMIT" ]; then
    assert_old_current
    assert_parked_new
  else
    die 'rollback release orientation is unrecognized'
  fi
  assert_old_current
  assert_parked_new
  atomic_rename_exclusive "$PARKED_LINK" "$FAILED_NEW_LINK"
  assert_release_link "$FAILED_NEW_LINK" "$NEW_COMMIT" "$NEW_RECEIPT_SHA256"
  /bin/echo "COMMISSIONED_UPGRADE_ROLLED_BACK current=$OLD_RELEASE failed_new=$FAILED_NEW_LINK" >&2
}

qualify_new_current() {
  local before after status_output status_error dry_output dry_error command_status qualification_status
  before=$SNAPSHOT_ROOT/before
  after=$SNAPSHOT_ROOT/after
  status_output=$SNAPSHOT_ROOT/status.json
  status_error=$SNAPSHOT_ROOT/status.err
  dry_output=$SNAPSHOT_ROOT/dry-run.json
  dry_error=$SNAPSHOT_ROOT/dry-run.err
  qualification_status=0
  set +e
  (
    set -eu
    snapshot_commissioned "$before"
    if /usr/bin/sudo -n -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$NEW_RELEASE/executor/.venv/bin/trading-harness-executor" status --config /etc/trading-desk/testnet-executor.toml \
      > "$status_output" 2> "$status_error"; then
      :
    else
      command_status=$?
      /bin/cat "$status_error" >&2
      exit "$command_status"
    fi
    /bin/cat "$status_output"
    verify_command_output status "$status_output"
    if /usr/bin/sudo -n -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$NEW_RELEASE/executor/.venv/bin/trading-harness-executor" dry-run --config /etc/trading-desk/testnet-executor.toml \
      > "$dry_output" 2> "$dry_error"; then
      :
    else
      command_status=$?
      /bin/cat "$dry_error" >&2
      exit "$command_status"
    fi
    /bin/cat "$dry_output"
    verify_command_output dry-run "$dry_output"
    assert_new_current
    assert_parked_old
    assert_commissioned
    assert_quiescent
    snapshot_commissioned "$after"
    if ! /usr/bin/cmp -s "$before" "$after"; then
      report_snapshot_difference "$before" "$after"
      die 'persistent commissioned state changed during release qualification'
    fi
  )
  qualification_status=$?
  set -e
  if [ "$qualification_status" -ne 0 ]; then
    rollback_pending
    return "$qualification_status"
  fi
  atomic_rename_exclusive "$PARKED_LINK" "$RETAINED_OLD_LINK"
  assert_new_current
  assert_release_link "$RETAINED_OLD_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256"
}

apply_migration() {
  local media state before_install after_install installer_status
  media=$1
  case "$media" in /*) ;; *) die 'media path must be absolute' ;; esac
  require_bound_release
  assert_sealed_programs
  assert_secure_directory / 755
  assert_secure_directory /opt 755
  assert_secure_directory "$TRADING_ROOT" 755
  assert_secure_directory "$RELEASES_PARENT" 755
  assert_secure_directory /private 755
  assert_secure_directory /private/var 755
  assert_secure_directory /private/var/db 755
  assert_sealed_media "$media"
  assert_commissioned
  assert_quiescent
  prepare_snapshots
  trap cleanup EXIT HUP INT TERM
  before_install=$SNAPSHOT_ROOT/before-install
  after_install=$SNAPSHOT_ROOT/after-install
  snapshot_commissioned "$before_install"
  state=$(migration_state)
  case "$state" in
    old-current)
      assert_absent "$PARKED_LINK"
      assert_absent "$RETAINED_OLD_LINK"
      assert_absent "$FAILED_NEW_LINK"
      atomic_rename_exclusive "$CURRENT_LINK" "$PARKED_LINK"
      assert_absent "$CURRENT_LINK"
      assert_parked_old
      ;;
    parked-current-absent) ;;
    new-current-pending)
      qualify_new_current
      /bin/echo "COMMISSIONED_MIGRATION_COMPLETE current=$NEW_RELEASE retained_old=$RETAINED_OLD_LINK"
      return 0
      ;;
    rollback-swapped-pending)
      die 'rollback was interrupted after the atomic swap; run --rollback-new to retain the failed new link'
      ;;
    failed-new-ready)
      die 'the exact failed new release is retained; repair the blocker, then run --retry-failed'
      ;;
    complete)
      /bin/echo "COMMISSIONED_MIGRATION_COMPLETE current=$NEW_RELEASE retained_old=$RETAINED_OLD_LINK"
      return 0
      ;;
    *) die 'migration state changed unexpectedly' ;;
  esac
  reject_incomplete_replacement
  assert_sealed_programs
  assert_sealed_media "$media"
  if "$INSTALLER" --apply "$media"; then
    :
  else
    installer_status=$?
    if [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
      assert_parked_old
      /bin/echo 'Replacement install failed with current absent; run --restore-old after reviewing retained release state.' >&2
    else
      /bin/echo 'Replacement installer failed after current appeared; stop for exact root review.' >&2
    fi
    return "$installer_status"
  fi
  assert_new_current
  assert_parked_old
  assert_commissioned
  snapshot_commissioned "$after_install"
  if ! /usr/bin/cmp -s "$before_install" "$after_install"; then
    report_snapshot_difference "$before_install" "$after_install"
    rollback_pending
    die 'persistent commissioned state changed while the replacement release was built'
  fi
  qualify_new_current
  /bin/echo "COMMISSIONED_MIGRATION_COMPLETE current=$NEW_RELEASE retained_old=$RETAINED_OLD_LINK"
  /bin/echo 'No credential, service, network, venue, or authoritative database mutation was performed.'
}

restore_old() {
  require_bound_release
  assert_sealed_programs
  assert_commissioned
  assert_quiescent
  assert_absent "$CURRENT_LINK"
  assert_parked_old
  atomic_rename_exclusive "$PARKED_LINK" "$CURRENT_LINK"
  assert_old_current
  /bin/echo "OLD_CURRENT_RESTORED current=$OLD_RELEASE"
}

rollback_new() {
  require_bound_release
  assert_sealed_programs
  assert_commissioned
  assert_quiescent
  rollback_pending
}

retry_failed() {
  local state
  require_bound_release
  assert_sealed_programs
  assert_secure_directory /private 755
  assert_secure_directory /private/var 755
  assert_secure_directory /private/var/db 755
  assert_commissioned
  assert_exact_file "$SIDECAR_ACL_RECEIPT" 0 0 400 "$SIDECAR_ACL_RECEIPT_SHA256"
  assert_no_acl "$SIDECAR_ACL_RECEIPT"
  assert_quiescent
  state=$(migration_state)
  [ "$state" = failed-new-ready ] || die 'retry requires the exact old-current/failed-new state'
  prepare_snapshots
  trap cleanup EXIT HUP INT TERM
  assert_absent "$PARKED_LINK"
  atomic_rename_exclusive "$FAILED_NEW_LINK" "$PARKED_LINK"
  assert_old_current
  assert_parked_new
  atomic_swap_symlinks "$CURRENT_LINK" "$PARKED_LINK"
  assert_new_current
  assert_parked_old
  qualify_new_current
  /bin/echo "COMMISSIONED_MIGRATION_COMPLETE current=$NEW_RELEASE retained_old=$RETAINED_OLD_LINK"
  /bin/echo 'The retained release passed credential-free qualification; no venue operation was performed.'
}

quarantine_incomplete() {
  require_bound_release
  assert_sealed_programs
  assert_commissioned
  assert_quiescent
  assert_absent "$CURRENT_LINK"
  assert_parked_old
  "$INSTALLER" --quarantine-incomplete "$NEW_RECEIPT_SHA256"
  /bin/echo 'INCOMPLETE_REPLACEMENT_QUARANTINED old current remains parked; run --restore-old.'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die 'plan takes no arguments'
    plan
    ;;
  --apply)
    [ "$#" -eq 2 ] || die '--apply requires one absolute sealed media directory'
    apply_migration "$2"
    ;;
  --restore-old)
    [ "$#" -eq 1 ] || die '--restore-old takes no additional arguments'
    restore_old
    ;;
  --rollback-new)
    [ "$#" -eq 1 ] || die '--rollback-new takes no additional arguments'
    rollback_new
    ;;
  --retry-failed)
    [ "$#" -eq 1 ] || die '--retry-failed takes no additional arguments'
    retry_failed
    ;;
  --quarantine-incomplete)
    [ "$#" -eq 1 ] || die '--quarantine-incomplete takes no additional arguments'
    quarantine_incomplete
    ;;
  *)
    die 'unknown action; use plan, --apply MEDIA, --restore-old, --rollback-new, --retry-failed, or --quarantine-incomplete'
    ;;
esac
