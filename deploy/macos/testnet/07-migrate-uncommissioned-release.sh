#!/bin/sh
set -eu
umask 077

# These values bind the replacement application, release receipt and sibling
# installer. Mutation still requires an explicit attended root action.
NEW_COMMIT=9d5825f67519f41713f0f2002756fe8b303f79ee
NEW_RECEIPT_SHA256=0ad59c49bba4e6595bceee9dfc2781246fcdf4b4a3f52d6cbeaf1065753adbf8
EXPECTED_INSTALLER_SHA256=3d1ea2736bb302834715418e162534735f1d6e08a3961be6001d0e0710978594
REBIND_REQUIRED=0

OLD_COMMIT=a0f82d5928e57c43e511127a490ecbcf48110684
OLD_RECEIPT_SHA256=281b8829eddd4d75a340e0bd1894792904686e0276b84bc6415812e80a10fb9b
TRADING_ROOT=/opt/trading-desk
RELEASES_PARENT=$TRADING_ROOT/releases
OLD_RELEASE=$RELEASES_PARENT/$OLD_COMMIT
CURRENT_LINK=$TRADING_ROOT/current
PARKED_LINK=$TRADING_ROOT/.uncommissioned-current-$OLD_COMMIT
ADMIN_PYTHON=$TRADING_ROOT/runtime/python-3.11.16/bin/python3.11
INSTALLER=
NEW_RELEASE=
NEW_BOOTSTRAP=
NEW_CANDIDATE=

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no release, link, config, identity, state, service, credential, process, network, or venue state changed'
  /bin/echo "old_commit=$OLD_COMMIT"
  /bin/echo "old_receipt_sha256=$OLD_RECEIPT_SHA256"
  /bin/echo "parked_link=$PARKED_LINK"
  /bin/echo "new_commit=$NEW_COMMIT"
  /bin/echo "new_receipt_sha256=$NEW_RECEIPT_SHA256"
  /bin/echo "expected_installer_sha256=$EXPECTED_INSTALLER_SHA256"
  /bin/echo "rebind_required=$REBIND_REQUIRED"
  /bin/echo 'Bound usage: --apply ABSOLUTE_ROOT_OWNED_SEALED_MEDIA'
  /bin/echo 'Explicit rollback while current is absent: --restore-old'
  /bin/echo 'The migration moves only one exact symlink. Sibling 04 exclusively owns replacement release-file construction.'
}

digest() {
  /usr/bin/openssl dgst -sha256 "$1" | /usr/bin/awk '{print $2}'
}

acl_entries() {
  /bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p'
}

assert_no_acl() {
  [ -z "$(acl_entries "$1")" ] || die "unexpected named ACL: $1"
}

assert_absent() {
  [ ! -e "$1" ] && [ ! -L "$1" ] || die "uncommissioned path must be absent: $1"
}

assert_secure_directory() {
  secure_directory=$1
  secure_mode=$2
  [ -d "$secure_directory" ] && [ ! -L "$secure_directory" ] || die "secure directory is unavailable: $secure_directory"
  [ "$(/bin/realpath "$secure_directory")" = "$secure_directory" ] || die "secure directory is non-canonical: $secure_directory"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$secure_directory")" = "0:0:$secure_mode" ] || die "secure directory metadata differs: $secure_directory"
  assert_no_acl "$secure_directory"
}

assert_root_sealed_chain() {
  sealed_cursor=$1
  case "$sealed_cursor" in /*) ;; *) die "sealed path must be absolute: $sealed_cursor" ;; esac
  [ "$(/bin/realpath "$sealed_cursor")" = "$sealed_cursor" ] || die "sealed path is non-canonical: $sealed_cursor"
  while :
  do
    [ -d "$sealed_cursor" ] && [ ! -L "$sealed_cursor" ] || die "sealed ancestor is unavailable: $sealed_cursor"
    [ "$(/usr/bin/stat -f %u "$sealed_cursor")" = 0 ] || die "sealed ancestor is not root-owned: $sealed_cursor"
    [ "$(/usr/bin/stat -f %g "$sealed_cursor")" = 0 ] || die "sealed ancestor group is not wheel: $sealed_cursor"
    [ -z "$(/usr/bin/find "$sealed_cursor" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed ancestor is group/world writable: $sealed_cursor"
    assert_no_acl "$sealed_cursor"
    [ "$sealed_cursor" = / ] && break
    sealed_cursor=$(/usr/bin/dirname "$sealed_cursor")
  done
}

assert_root_sealed_file() {
  sealed_file=$1
  [ -f "$sealed_file" ] && [ ! -L "$sealed_file" ] || die "sealed file is unavailable: $sealed_file"
  [ "$(/bin/realpath "$sealed_file")" = "$sealed_file" ] || die "sealed file is non-canonical: $sealed_file"
  [ "$(/usr/bin/stat -f %u "$sealed_file")" = 0 ] || die "sealed file is not root-owned: $sealed_file"
  [ "$(/usr/bin/stat -f %g "$sealed_file")" = 0 ] || die "sealed file group is not wheel: $sealed_file"
  [ "$(/usr/bin/stat -f %l "$sealed_file")" = 1 ] || die "sealed file is hard-linked: $sealed_file"
  [ -z "$(/usr/bin/find "$sealed_file" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed file is group/world writable: $sealed_file"
  assert_no_acl "$sealed_file"
}

assert_sealed_media() {
  media=$1
  assert_root_sealed_chain "$media"
  first_special=$(/usr/bin/find "$media" ! -type d ! -type f -print -quit)
  [ -z "$first_special" ] || die "sealed media contains a special path: $first_special"
  first_nonroot=$(/usr/bin/find "$media" ! -user root -print -quit)
  [ -z "$first_nonroot" ] || die "sealed media contains a non-root path: $first_nonroot"
  first_nonwheel=$(/usr/bin/find "$media" ! -group wheel -print -quit)
  [ -z "$first_nonwheel" ] || die "sealed media contains a non-wheel path: $first_nonwheel"
  first_writable=$(/usr/bin/find "$media" -perm +022 -print -quit)
  [ -z "$first_writable" ] || die "sealed media contains a group/world-writable path: $first_writable"
  first_link=$(/usr/bin/find "$media" -type f -links +1 -print -quit)
  [ -z "$first_link" ] || die "sealed media contains a hard-linked file: $first_link"
  first_acl=$(/usr/bin/find "$media" -acl -print -quit)
  [ -z "$first_acl" ] || die "sealed media contains a named ACL: $first_acl"
}

require_bound_release() {
  [ "$REBIND_REQUIRED" = 0 ] || die 'replacement release binding is required; no deployment path was opened or changed'
  /bin/echo "$NEW_COMMIT" | /usr/bin/grep -Eq '^[0-9a-f]{40}$' || die 'bound replacement commit is invalid'
  /bin/echo "$NEW_RECEIPT_SHA256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 'bound replacement receipt is invalid'
  /bin/echo "$EXPECTED_INSTALLER_SHA256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 'bound sibling installer hash is invalid'
  [ "$NEW_COMMIT" != "$OLD_COMMIT" ] || die 'replacement commit must differ from the parked release'
  NEW_RELEASE=$RELEASES_PARENT/$NEW_COMMIT
  NEW_BOOTSTRAP=$RELEASES_PARENT/.bootstrap-$NEW_COMMIT
  NEW_CANDIDATE=$TRADING_ROOT/.current-$NEW_COMMIT
}

assert_sealed_programs() {
  [ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || die 'migration requires real/effective root'
  case "$0" in /*) ;; *) die 'migration apply/restore requires an absolute script path' ;; esac
  [ ! -L "$0" ] && [ "$(/bin/realpath "$0")" = "$0" ] || die 'migration script path is symlinked or non-canonical'
  script_dir=$(/usr/bin/dirname "$0")
  assert_root_sealed_chain "$script_dir"
  assert_root_sealed_file "$0"
  INSTALLER=$script_dir/04-install-merged-main.sh
  assert_root_sealed_file "$INSTALLER"
  [ "$(digest "$INSTALLER")" = "$EXPECTED_INSTALLER_SHA256" ] || die 'sibling installer SHA-256 differs'
  /usr/bin/grep -Fqx "EXPECTED_COMMIT=$NEW_COMMIT" "$INSTALLER" || die 'sibling installer commit differs'
  /usr/bin/grep -Fqx "EXPECTED_RELEASE_RECEIPT_SHA256=$NEW_RECEIPT_SHA256" "$INSTALLER" || die 'sibling installer receipt differs'
  assert_root_sealed_file "$script_dir/storage-headroom-guard.py"
  [ -x "$ADMIN_PYTHON" ] && [ ! -L "$ADMIN_PYTHON" ] || die 'sealed admin runtime is unavailable'
  assert_root_sealed_chain "$TRADING_ROOT/runtime/python-3.11.16"
  assert_root_sealed_file "$ADMIN_PYTHON"
}

assert_ready_receipt() {
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
  link=$1
  commit=$2
  receipt=$3
  mode=$4
  release=$RELEASES_PARENT/$commit
  [ -L "$link" ] || die "release link is unavailable: $link"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$link")" = "0:0:$mode:1" ] || die "release link metadata differs: $link"
  [ "$(/usr/bin/readlink "$link")" = "releases/$commit" ] || die "release link target differs: $link"
  [ "$(/bin/realpath "$link")" = "$release" ] || die "release link escapes its exact release: $link"
  assert_ready_receipt "$release" "$receipt"
}

assert_old_current() {
  assert_release_link "$CURRENT_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256" 700
}

assert_parked_old() {
  assert_release_link "$PARKED_LINK" "$OLD_COMMIT" "$OLD_RECEIPT_SHA256" 700
}

assert_new_current() {
  assert_release_link "$CURRENT_LINK" "$NEW_COMMIT" "$NEW_RECEIPT_SHA256" 755
}

assert_identity_absent() {
  identity_name=$1
  identity_id=$2
  if /usr/bin/dscl . -read "/Users/$identity_name" >/dev/null 2>&1; then
    die "uncommissioned user already exists: $identity_name"
  fi
  if /usr/bin/dscl . -read "/Groups/$identity_name" >/dev/null 2>&1; then
    die "uncommissioned group already exists: $identity_name"
  fi
  user_matches=$(/usr/bin/dscl . -search /Users UniqueID "$identity_id" 2>/dev/null) || die 'directory-service UID search failed'
  group_matches=$(/usr/bin/dscl . -search /Groups PrimaryGroupID "$identity_id" 2>/dev/null) || die 'directory-service GID search failed'
  [ -z "$user_matches" ] || die "uncommissioned UID is already assigned: $identity_id"
  [ -z "$group_matches" ] || die "uncommissioned GID is already assigned: $identity_id"
}

assert_uncommissioned() {
  assert_identity_absent trading-public-collector 453
  assert_identity_absent trading-router-operator 454

  for absent in \
    /etc/trading-desk/testnet-foreground-profile.json \
    /etc/trading-desk/testnet-executor.toml \
    /etc/trading-desk/testnet-foreground-preinit.receipt \
    /etc/trading-desk/testnet-foreground-postinit.receipt \
    /etc/trading-desk/testnet-foreground-collector-identity.receipt \
    /etc/trading-desk/testnet-foreground-router-identity.receipt \
    /etc/trading-desk/.testnet-foreground-collector-birth-v2 \
    /etc/trading-desk/.testnet-foreground-router-birth-v2 \
    /private/var/db/trading-desk-testnet-foreground \
    /private/var/db/trading-desk/control-private/chat-approval \
    /private/var/db/trading-desk-testnet-chat-socket \
    /private/var/run/trading-desk \
    /private/var/db/trading-desk-testnet-chat-handoffs \
    /private/var/db/trading-desk-testnet-chat-ready \
    /private/var/db/trading-desk-testnet-chat-presentations \
    /private/var/db/trading-desk-testnet-chat-issuance-evidence \
    /private/var/db/trading-desk-testnet-chat-account-quotes \
    /private/var/db/trading-desk-testnet-chat-executor-registration \
    /private/var/db/trading-desk-testnet-route-health \
    /private/var/db/trading-desk-testnet-remote-vpn-health \
    /private/var/run/trading-desk-testnet-remote-vpn-health.lock \
    /private/var/db/trading-desk-lima
  do
    assert_absent "$absent"
  done

  for plist in \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-research.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-learning-mcp.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-chat-broker.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-chat-collector.plist \
    /Library/LaunchDaemons/com.jawndiego.trading-desk-remote-vpn-health-collector.plist
  do
    assert_absent "$plist"
  done

  for label in \
    com.jawndiego.trading-desk-research \
    com.jawndiego.trading-desk-learning-mcp \
    com.jawndiego.trading-desk-testnet-executor \
    com.jawndiego.trading-desk-testnet-chat-broker \
    com.jawndiego.trading-desk-testnet-chat-collector \
    com.jawndiego.trading-desk-remote-vpn-health-collector
  do
    if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
      die "uncommissioned launchd job is loaded: $label"
    fi
  done

  role_processes=$(/bin/ps -wwaxo uid=,command=) || die 'process inventory is unavailable'
  if /bin/echo "$role_processes" | /usr/bin/awk '$1 >= 450 && $1 <= 454 { found=1 } END { exit(found ? 0 : 1) }'; then
    die 'an isolated trading role process is already running'
  fi
  for executable in \
    trading-harness-testnet-chat-broker \
    trading-harness-testnet-chat-collector \
    trading-harness-remote-vpn-health-collector \
    trading-harness-executor \
    trading-harness-mcp
  do
    if /bin/echo "$role_processes" | /usr/bin/grep -F "$executable" >/dev/null; then
      die "a trading process is already running: $executable"
    fi
  done
  for release_path in "$CURRENT_LINK/" "$OLD_RELEASE/" "$PARKED_LINK/"
  do
    if /bin/echo "$role_processes" | /usr/bin/grep -F "$release_path" >/dev/null; then
      die "a process command still references the uncommissioned release: $release_path"
    fi
  done
  if /usr/sbin/lsof -n -P +D "$OLD_RELEASE" >/dev/null 2>&1; then
    die 'a process still has an open path in the uncommissioned release'
  fi
}

atomic_rename_exclusive() {
  source=$1
  destination=$2
  [ -e "$source" ] || [ -L "$source" ] || die "exclusive-rename source is absent: $source"
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || die "exclusive-rename destination already exists: $destination"
  [ "$(/usr/bin/dirname "$source")" = "$TRADING_ROOT" ] || die 'exclusive-rename source parent differs'
  [ "$(/usr/bin/dirname "$destination")" = "$TRADING_ROOT" ] || die 'exclusive-rename destination parent differs'
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$ADMIN_PYTHON" -B -I -c '
import ctypes
import fcntl
import os
import sys

source, destination, parent = sys.argv[1:]
RENAME_EXCL = 0x00000004
libc = ctypes.CDLL(None, use_errno=True)
rename = libc.renamex_np
rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rename.restype = ctypes.c_int

flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(parent, flags)
try:
    if not os.path.islink(source) or os.path.lexists(destination):
        raise RuntimeError("exclusive symlink rename precondition changed")
    os.fsync(descriptor)
    fcntl.fcntl(descriptor, 51)
    ctypes.set_errno(0)
    if rename(os.fsencode(source), os.fsencode(destination), RENAME_EXCL) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    os.fsync(descriptor)
    fcntl.fcntl(descriptor, 51)
finally:
    os.close(descriptor)
' "$source" "$destination" "$TRADING_ROOT" || die 'exclusive durable symlink rename failed'
}

migration_state() {
  current_present=0
  parked_present=0
  if [ -e "$CURRENT_LINK" ] || [ -L "$CURRENT_LINK" ]; then current_present=1; fi
  if [ -e "$PARKED_LINK" ] || [ -L "$PARKED_LINK" ]; then parked_present=1; fi
  if [ "$current_present:$parked_present" = 1:0 ]; then
    assert_old_current
    /bin/echo old-current
  elif [ "$current_present:$parked_present" = 0:1 ]; then
    assert_parked_old
    /bin/echo parked-current-absent
  elif [ "$current_present:$parked_present" = 1:1 ]; then
    assert_parked_old
    assert_new_current
    /bin/echo replacement-current
  else
    die 'release migration state is unrecognized'
  fi
}

reject_incomplete_replacement() {
  if [ -e "$NEW_BOOTSTRAP" ] || [ -L "$NEW_BOOTSTRAP" ]; then
    die "replacement bootstrap is retained; use sibling 04 --quarantine-incomplete $NEW_RECEIPT_SHA256 after exact root review"
  fi
  if [ -e "$NEW_RELEASE" ] || [ -L "$NEW_RELEASE" ]; then
    if [ -f "$NEW_RELEASE/.INSTALLING" ] && [ ! -L "$NEW_RELEASE/.INSTALLING" ] && \
       [ ! -e "$NEW_RELEASE/.READY" ] && [ ! -L "$NEW_RELEASE/.READY" ]; then
      die "replacement release is retained incomplete; use sibling 04 --quarantine-incomplete $NEW_RECEIPT_SHA256 after exact root review"
    fi
    [ -f "$NEW_RELEASE/.READY" ] && [ ! -e "$NEW_RELEASE/.INSTALLING" ] || die 'replacement release state requires root review'
  fi
}

apply_migration() {
  media=$1
  require_bound_release
  assert_sealed_programs
  assert_secure_directory / 755
  assert_secure_directory /opt 755
  assert_secure_directory "$TRADING_ROOT" 755
  assert_secure_directory "$RELEASES_PARENT" 755
  assert_sealed_media "$media"
  assert_uncommissioned
  state=$(migration_state)
  case "$state" in
    old-current)
      atomic_rename_exclusive "$CURRENT_LINK" "$PARKED_LINK"
      assert_absent "$CURRENT_LINK"
      assert_parked_old
      ;;
    parked-current-absent) ;;
    replacement-current)
      /bin/echo "MIGRATION_COMPLETE current=$CURRENT_LINK release=$NEW_RELEASE parked_old=$PARKED_LINK"
      return 0
      ;;
    *) die 'release migration state changed unexpectedly' ;;
  esac
  reject_incomplete_replacement
  assert_sealed_programs
  assert_sealed_media "$media"
  if "$INSTALLER" --apply "$media"; then
    assert_parked_old
    assert_new_current
    /bin/echo "MIGRATION_COMPLETE current=$CURRENT_LINK release=$NEW_RELEASE parked_old=$PARKED_LINK"
    /bin/echo 'No commissioning, service, credential, network or venue action was performed.'
    return 0
  else
    installer_status=$?
  fi
  if [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
    assert_parked_old
    /bin/echo "Replacement install failed and current remains absent; run this sealed script with --restore-old or review sibling 04 quarantine using receipt $NEW_RECEIPT_SHA256." >&2
  else
    /bin/echo 'Replacement installer failed after a current link appeared; do not restore or overwrite it. Stop for exact root review.' >&2
  fi
  return "$installer_status"
}

restore_old() {
  require_bound_release
  assert_sealed_programs
  assert_secure_directory / 755
  assert_secure_directory /opt 755
  assert_secure_directory "$TRADING_ROOT" 755
  assert_secure_directory "$RELEASES_PARENT" 755
  assert_uncommissioned
  assert_absent "$CURRENT_LINK"
  assert_parked_old
  atomic_rename_exclusive "$PARKED_LINK" "$CURRENT_LINK"
  assert_absent "$PARKED_LINK"
  assert_old_current
  /bin/echo "OLD_CURRENT_RESTORED current=$CURRENT_LINK release=$OLD_RELEASE"
  /bin/echo 'Replacement release/bootstrap/candidate state, if any, was retained unchanged for explicit root review.'
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
  *)
    die 'unknown action; use plan, --apply ABSOLUTE_SEALED_MEDIA, or --restore-old'
    ;;
esac
