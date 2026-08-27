#!/bin/sh
set -eu
umask 077

EXPECTED_COMMIT=a0f82d5928e57c43e511127a490ecbcf48110684
EXPECTED_ARCHIVE_SHA256=de2d452200a9a54250d16be627eedb1a8d404292c6028cf8048b3a81bfd312ac
EXPECTED_WHEEL_MANIFEST_SHA256=6d96d2e7a436740f0f1f213b8403bdef78b1ea0e2611560c62d56c92c360f752
EXPECTED_APP_WHEEL_SHA256=c673e9f9fd506a1041114a13ca80cbb65f6a4f557db9faf99cac2e2b3628ae58
EXPECTED_RESEARCH_LOCK_SHA256=8bb08431c71094259ad2e231cc89aef21feb219d56b3f219cc58e87b04333898
EXPECTED_EXECUTOR_LOCK_SHA256=d1ad01eeed904d5e09709483220e201e1418b73f9d216ef1191f528d32f288da
EXPECTED_GUARD_SHA256=ef7341d5a8a30a15f363be63b99133d54ce13e581097bc38908ca30ec91c70d1
EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256=8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7
EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256=2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9
# Commit A and its archive, wheel, dependency locks and native readers were
# independently rebuilt and byte-compared before this binding commit.
ROLE_HELPER_RELEASE_REBIND_REQUIRED=0
EXPECTED_RELEASE_RECEIPT_SHA256=281b8829eddd4d75a340e0bd1894792904686e0276b84bc6415812e80a10fb9b
ARCHIVE_NAME=hypergrok-trading-desk-a0f82d5.tar
TRADING_ROOT=/opt/trading-desk
RUNTIME_ROOT=$TRADING_ROOT/runtime/python-3.11.16
PYTHON=$RUNTIME_ROOT/bin/python3.11
RELEASES_PARENT=$TRADING_ROOT/releases
RELEASE_FINAL=$RELEASES_PARENT/$EXPECTED_COMMIT
RELEASE_BOOTSTRAP=$RELEASES_PARENT/.bootstrap-$EXPECTED_COMMIT
RELEASE_INSTALLING=$RELEASE_FINAL/.INSTALLING
RELEASE_READY=$RELEASE_FINAL/.READY
RESEARCH_RELEASE=$RELEASE_FINAL/research
EXECUTOR_RELEASE=$RELEASE_FINAL/executor
BIN_RELEASE=$RELEASE_FINAL/bin
GUARD_RELEASE=$BIN_RELEASE/storage-headroom-guard.py
KEYCHAIN_HELPER_MEDIA_NAME=keychain-role-readers
KEYCHAIN_HELPER_MEDIA=
LIBEXEC_PARENT=$TRADING_ROOT/libexec
EXECUTOR_KEYCHAIN_HELPER=$LIBEXEC_PARENT/trading-keychain-reader-executor-v1
CONTROL_KEYCHAIN_HELPER=$LIBEXEC_PARENT/trading-keychain-reader-control-v1
EXECUTOR_KEYCHAIN_HELPER_STAGE=$LIBEXEC_PARENT/.trading-keychain-reader-executor-v1.installing
CONTROL_KEYCHAIN_HELPER_STAGE=$LIBEXEC_PARENT/.trading-keychain-reader-control-v1.installing
CURRENT_LINK=$TRADING_ROOT/current
CURRENT_CANDIDATE=$TRADING_ROOT/.current-$EXPECTED_COMMIT
QUARANTINE_PARENT=$TRADING_ROOT/quarantine
QUARANTINE_PREFIX=$QUARANTINE_PARENT/$EXPECTED_COMMIT-$EXPECTED_RELEASE_RECEIPT_SHA256
INSTALL_LOCK=$TRADING_ROOT/.install-v1.lock
PROBE_TMP=
PROBE_PARENT=
PROBE_LABEL=
LOCK_HELD=0

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no application, runtime, service, config, credential, database, or venue state changed'
  /bin/echo "First-install the reviewed source tree for merged main $EXPECTED_COMMIT."
  /bin/echo "Require archive_sha256=$EXPECTED_ARCHIVE_SHA256"
  /bin/echo "Require wheel_manifest_sha256=$EXPECTED_WHEEL_MANIFEST_SHA256"
  /bin/echo "Require executor_keychain_helper_sha256=$EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256"
  /bin/echo "Require control_keychain_helper_sha256=$EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256"
  /bin/echo "role_helper_release_rebind_required=$ROLE_HELPER_RELEASE_REBIND_REQUIRED"
  /bin/echo "Permanent release=$RELEASE_FINAL"
  /bin/echo "Build marker=$RELEASE_INSTALLING ready marker=$RELEASE_READY"
  /bin/echo "Atomic activation=$CURRENT_LINK -> releases/$EXPECTED_COMMIT"
  /bin/echo "Interrupted-release quarantine=$QUARANTINE_PREFIX-<source-inode>"
  /bin/echo "Apply: --apply ABSOLUTE_SEALED_MEDIA"
  /bin/echo "Recovery: --quarantine-incomplete $EXPECTED_RELEASE_RECEIPT_SHA256"
  /bin/echo 'The release venvs are created at their permanent absolute paths; they are never relocated.'
  /bin/echo 'Promotion is first-install only and refuses any pre-existing current path.'
  /bin/echo 'The build remains offline: pip --isolated check with --no-index and --only-binary=:all: against both exact resolved lock files.'
  /bin/echo 'The installer never starts a service and never runs validate, init, status, dry-run, or a venue call.'
}

assert_no_acl() {
  entries=$(/bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
  [ -z "$entries" ] || die "unexpected named ACL: $1"
}

assert_sealed_root() {
  [ "$(/usr/bin/id -u)" -eq 0 ] || die "run the sealed copy as root"
  [ "$(/usr/bin/id -g)" -eq 0 ] || die "sealed apply requires effective GID wheel"
  [ "$(/usr/bin/id -u trading-research)" = 450 ] || die "trading-research UID drift"
  [ "$(/usr/bin/id -u trading-executor)" = 451 ] || die "trading-executor UID drift"
  [ "$(/usr/bin/id -u trading-control)" = 452 ] || die "trading-control UID drift"
  [ "$(/usr/bin/id -g trading-research)" = 450 ] || die "trading-research primary GID drift"
  [ "$(/usr/bin/id -g trading-executor)" = 451 ] || die "trading-executor primary GID drift"
  [ "$(/usr/bin/id -g trading-control)" = 452 ] || die "trading-control primary GID drift"
  case "$0" in /*) ;; *) die "apply/recovery requires an absolute script path" ;; esac
  [ ! -L "$0" ] || die "script symlink rejected"
  script_path=$(/bin/realpath "$0")
  [ "$script_path" = "$0" ] || die "script path is non-canonical or has a symlinked ancestor"
  script_dir=$(/usr/bin/dirname "$script_path")
  [ "$(/usr/bin/stat -f %u "$script_path")" = 0 ] || die "script must be root-owned"
  [ "$(/usr/bin/stat -f %u "$script_dir")" = 0 ] || die "script directory must be root-owned"
  writable=$(/usr/bin/find "$script_path" "$script_dir" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "script path is group/world writable: $writable"
  assert_no_acl "$script_path"
  assert_root_owned_path_chain "$script_dir"
}

assert_sealed_tree() {
  path=$1
  [ -d "$path" ] || die "missing directory: $path"
  [ ! -L "$path" ] || die "directory symlink rejected: $path"
  first_special=$(/usr/bin/find "$path" ! -type d ! -type f -print -quit)
  [ -z "$first_special" ] || die "special file or symlink rejected: $first_special"
  first_nonroot=$(/usr/bin/find "$path" ! -user root -print -quit)
  [ -z "$first_nonroot" ] || die "non-root-owned media path: $first_nonroot"
  first_writable=$(/usr/bin/find "$path" -perm +022 -print -quit)
  [ -z "$first_writable" ] || die "group/world-writable media path: $first_writable"
  first_link=$(/usr/bin/find "$path" -type f -links +1 -print -quit)
  [ -z "$first_link" ] || die "hard-linked media file rejected: $first_link"
  first_acl=$(/usr/bin/find "$path" -acl -print -quit)
  [ -z "$first_acl" ] || die "named ACL in sealed media: $first_acl"
}

digest() {
  /usr/bin/openssl dgst -sha256 "$1" | /usr/bin/awk '{print $2}'
}

verify_media() {
  media=$1
  layout=$2
  archive=$media/$ARCHIVE_NAME
  wheelhouse=$media/wheelhouse
  manifest=$wheelhouse/SHA256SUMS
  case "$layout" in
    sealed-pack) lock_root=$media/staged ;;
    installed-media) lock_root=$media/locks ;;
    *) die "unknown media layout" ;;
  esac
  research_lock=$lock_root/resolved-research.txt
  executor_lock=$lock_root/resolved-executor.txt
  helper_root=$media/$KEYCHAIN_HELPER_MEDIA_NAME
  executor_helper=$helper_root/trading-keychain-reader-executor-v1
  control_helper=$helper_root/trading-keychain-reader-control-v1
  helper_manifest=$helper_root/SHA256SUMS
  assert_sealed_tree "$media"
  [ -f "$archive" ] || die "missing exact source archive"
  [ -d "$wheelhouse" ] || die "missing wheelhouse"
  [ -f "$manifest" ] || die "missing wheel manifest"
  [ -f "$research_lock" ] || die "missing research lock"
  [ -f "$executor_lock" ] || die "missing executor lock"
  [ -d "$helper_root" ] && [ ! -L "$helper_root" ] || die "missing keychain helper media"
  helper_count=$(/usr/bin/find "$helper_root" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END {print NR + 0}')
  helper_file_count=$(/usr/bin/find "$helper_root" -mindepth 1 -maxdepth 1 -type f | /usr/bin/awk 'END {print NR + 0}')
  [ "$helper_count" = 3 ] && [ "$helper_file_count" = 3 ] || die "keychain helper media inventory is not exact"
  [ -f "$executor_helper" ] && [ ! -L "$executor_helper" ] || die "missing executor keychain helper"
  [ -f "$control_helper" ] && [ ! -L "$control_helper" ] || die "missing control keychain helper"
  [ -f "$helper_manifest" ] && [ ! -L "$helper_manifest" ] || die "missing keychain helper manifest"
  [ "$(digest "$executor_helper")" = "$EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256" ] || die "executor keychain helper digest mismatch"
  [ "$(digest "$control_helper")" = "$EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256" ] || die "control keychain helper digest mismatch"
  [ "$(/usr/bin/awk 'NF {count += 1} END {print count + 0}' "$helper_manifest")" = 2 ] || die "keychain helper manifest line count differs"
  /usr/bin/grep -Fqx "$EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256  trading-keychain-reader-executor-v1" "$helper_manifest" || die "executor helper manifest entry differs"
  /usr/bin/grep -Fqx "$EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256  trading-keychain-reader-control-v1" "$helper_manifest" || die "control helper manifest entry differs"
  /usr/bin/codesign --verify --strict --verbose=2 "$executor_helper" || die "executor keychain helper signature invalid"
  /usr/bin/codesign --verify --strict --verbose=2 "$control_helper" || die "control keychain helper signature invalid"
  [ "$(digest "$archive")" = "$EXPECTED_ARCHIVE_SHA256" ] || die "source archive digest mismatch"
  [ "$(digest "$manifest")" = "$EXPECTED_WHEEL_MANIFEST_SHA256" ] || die "wheel manifest digest mismatch"
  app_count=$(/usr/bin/awk '$2 == "trading_harness-0.2.0.dev0-py3-none-any.whl" {count += 1} END {print count + 0}' "$manifest")
  [ "$app_count" = 1 ] || die "application wheel manifest entry count mismatch"
  app_sha=$(/usr/bin/awk '$2 == "trading_harness-0.2.0.dev0-py3-none-any.whl" {print $1}' "$manifest")
  [ "$app_sha" = "$EXPECTED_APP_WHEEL_SHA256" ] || die "application wheel digest differs from the merged-main build"
  [ "$(digest "$research_lock")" = "$EXPECTED_RESEARCH_LOCK_SHA256" ] || die "research lock digest mismatch"
  [ "$(digest "$executor_lock")" = "$EXPECTED_EXECUTOR_LOCK_SHA256" ] || die "executor lock digest mismatch"

  manifest_count=$(/usr/bin/awk 'NF {count += 1} END {print count + 0}' "$manifest")
  wheel_count=$(/usr/bin/find "$wheelhouse" -maxdepth 1 -type f -name '*.whl' | /usr/bin/awk 'END {print NR + 0}')
  [ "$manifest_count" = "$wheel_count" ] || die "wheelhouse file count differs from manifest"
  wheelhouse_entry_count=$(/usr/bin/find "$wheelhouse" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END {print NR + 0}')
  [ "$wheelhouse_entry_count" = "$((wheel_count + 1))" ] || die "wheelhouse contains an unexpected entry"
  duplicate_filename=$(/usr/bin/awk 'NF {if (seen[$2]++) {print $2; exit}}' "$manifest")
  [ -z "$duplicate_filename" ] || die "duplicate wheel manifest filename: $duplicate_filename"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    /bin/echo "$line" | /usr/bin/grep -Eq '^[0-9a-f]{64}  [A-Za-z0-9_.+-]+\.whl$' || die "noncanonical wheel manifest line"
    expected=${line%% *}
    filename=${line#*  }
    /bin/echo "$expected" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die "invalid wheel digest line"
    case "$filename" in
      ''|*/*|*..*|*[!A-Za-z0-9_.+-]*) die "unsafe wheel manifest filename: $filename" ;;
    esac
    [ -f "$wheelhouse/$filename" ] || die "missing wheel: $filename"
    [ "$(digest "$wheelhouse/$filename")" = "$expected" ] || die "wheel digest mismatch: $filename"
  done < "$manifest"

  if [ "$layout" = installed-media ]; then
    top_count=$(/usr/bin/find "$media" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END {print NR + 0}')
    [ "$top_count" = 3 ] || die "installed media contains an unexpected top-level entry"
    [ -d "$media/locks" ] || die "missing locks directory"
    lock_count=$(/usr/bin/find "$media/locks" -mindepth 1 -maxdepth 1 -type f | /usr/bin/awk 'END {print NR + 0}')
    [ "$lock_count" = 2 ] || die "locks directory contains an unexpected entry"
  fi
}

assert_exact_directory() {
  path=$1
  mode=$2
  [ -d "$path" ] || die "missing directory: $path"
  [ ! -L "$path" ] || die "directory symlink rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "directory must be root-owned: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = 0 ] || die "directory group must be wheel: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = "$mode" ] || die "directory mode must be 0$mode: $path"
  assert_no_acl "$path"
}

assert_secure_directory() {
  path=$1
  [ -d "$path" ] || die "missing directory: $path"
  [ ! -L "$path" ] || die "directory symlink rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "directory must be root-owned: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = 0 ] || die "directory group must be wheel: $path"
  writable=$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "directory is group/world writable: $path"
  assert_no_acl "$path"
}

assert_opt_ancestor_chain() {
  assert_exact_directory / 755
  assert_exact_directory /opt 755
  assert_exact_directory "$TRADING_ROOT" 755
  [ "$(/bin/realpath "$TRADING_ROOT")" = "$TRADING_ROOT" ] || die "trading root has a symlinked ancestor"
}

assert_root_owned_path_chain() {
  path=$1
  case "$path" in
    /*) ;;
    *) die "path must be absolute: $path" ;;
  esac
  [ "$(/bin/realpath "$path")" = "$path" ] || die "path is non-canonical or has a symlinked ancestor: $path"
  cursor=$path
  while :; do
    if [ -d "$cursor" ]; then
      assert_secure_directory "$cursor"
    else
      cursor=$(/usr/bin/dirname "$cursor")
      continue
    fi
    [ "$cursor" = / ] && break
    cursor=$(/usr/bin/dirname "$cursor")
  done
}

ensure_root_directory() {
  path=$1
  mode=$2
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    /bin/mkdir -m "$mode" "$path"
    /usr/sbin/chown root:wheel "$path"
  fi
  assert_exact_directory "$path" "$mode"
}

assert_no_acl_tree() {
  first_acl=$(/usr/bin/find "$1" -acl -print -quit)
  [ -z "$first_acl" ] || die "named ACL in release tree: $first_acl"
}

assert_secure_tree() {
  path=$1
  [ -d "$path" ] || die "missing tree: $path"
  [ ! -L "$path" ] || die "tree root symlink rejected: $path"
  first_special=$(/usr/bin/find "$path" ! -type d ! -type f ! -type l -print -quit)
  [ -z "$first_special" ] || die "special release path rejected: $first_special"
  first_nonroot=$(/usr/bin/find "$path" ! -user root -print -quit)
  [ -z "$first_nonroot" ] || die "non-root-owned release path: $first_nonroot"
  first_writable=$(/usr/bin/find "$path" \( -type d -o -type f \) -perm +022 -print -quit)
  [ -z "$first_writable" ] || die "group/world-writable release path: $first_writable"
  first_link=$(/usr/bin/find "$path" -type f -links +1 -print -quit)
  [ -z "$first_link" ] || die "hard-linked release file rejected: $first_link"
  assert_no_acl_tree "$path"
  if ! /usr/bin/find "$path" -type l -print | while IFS= read -r link; do
      resolved=$(/bin/realpath "$link" 2>/dev/null) || {
        exit 1
      }
      path_prefix=$path/
      runtime_prefix=$RUNTIME_ROOT/
      case "$resolved" in "$path"|"$RUNTIME_ROOT") continue ;; esac
      case "$resolved" in "$path_prefix"*) continue ;; esac
      case "$resolved" in "$runtime_prefix"*) continue ;; esac
      exit 1
    done; then
    die "release symlink escapes trusted trees or is broken"
  fi
}

assert_incomplete_tree_safe_to_move() {
  path=$1
  [ -d "$path" ] || die "missing incomplete tree: $path"
  [ ! -L "$path" ] || die "incomplete tree root symlink rejected"
  first_special=$(/usr/bin/find "$path" ! -type d ! -type f ! -type l -print -quit)
  [ -z "$first_special" ] || die "special path in incomplete release: $first_special"
  first_nonroot=$(/usr/bin/find "$path" ! -user root -print -quit)
  [ -z "$first_nonroot" ] || die "non-root-owned incomplete release path: $first_nonroot"
  first_world_writable=$(/usr/bin/find "$path" \( -type d -o -type f \) -perm +002 -print -quit)
  [ -z "$first_world_writable" ] || die "world-writable incomplete release path: $first_world_writable"
  first_link=$(/usr/bin/find "$path" -type f -links +1 -print -quit)
  [ -z "$first_link" ] || die "hard-linked incomplete release file rejected: $first_link"
  assert_no_acl_tree "$path"
}

assert_immutable_modes() {
  path=$1
  bad_dir=$(/usr/bin/find "$path" -type d ! -perm 0755 -print -quit)
  [ -z "$bad_dir" ] || die "release directory mode is not 0755: $bad_dir"
  bad_link=$(/usr/bin/find "$path" -type l ! -perm 0755 -print -quit)
  [ -z "$bad_link" ] || die "release symlink mode is not 0755: $bad_link"
  bad_exec=$(/usr/bin/find "$path" -type f -perm +111 ! -perm 0555 -print -quit)
  [ -z "$bad_exec" ] || die "release executable mode is not 0555: $bad_exec"
  bad_file=$(/usr/bin/find "$path" -type f ! -perm +111 ! -perm 0444 -print -quit)
  [ -z "$bad_file" ] || die "release data-file mode is not 0444: $bad_file"
}

release_receipt() {
  /bin/echo 'schema_version=1'
  /bin/echo "commit=$EXPECTED_COMMIT"
  /bin/echo "release_path=$RELEASE_FINAL"
  /bin/echo "archive_sha256=$EXPECTED_ARCHIVE_SHA256"
  /bin/echo "wheel_manifest_sha256=$EXPECTED_WHEEL_MANIFEST_SHA256"
  /bin/echo "app_wheel_sha256=$EXPECTED_APP_WHEEL_SHA256"
  /bin/echo "research_lock_sha256=$EXPECTED_RESEARCH_LOCK_SHA256"
  /bin/echo "executor_lock_sha256=$EXPECTED_EXECUTOR_LOCK_SHA256"
  /bin/echo "guard_sha256=$EXPECTED_GUARD_SHA256"
  /bin/echo "executor_keychain_helper_sha256=$EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256"
  /bin/echo "control_keychain_helper_sha256=$EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256"
}

write_installing_receipt() {
  directory=$1
  marker=$directory/.INSTALLING
  marker_temp=$directory/.INSTALLING.tmp
  [ ! -e "$marker" ] && [ ! -L "$marker" ] || die "installing marker already exists"
  [ ! -e "$marker_temp" ] && [ ! -L "$marker_temp" ] || die "installing marker temporary path already exists"
  release_receipt > "$marker_temp"
  /usr/sbin/chown root:wheel "$marker_temp"
  /bin/chmod 0400 "$marker_temp"
  [ "$(digest "$marker_temp")" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ] || die "internal release-receipt digest drift"
  sync_regular_file_durable "$marker_temp"
  atomic_rename_exclusive "$marker_temp" "$marker"
  verify_release_receipt "$marker"
}

verify_release_receipt() {
  marker=$1
  [ -f "$marker" ] || die "missing release receipt: $marker"
  [ ! -L "$marker" ] || die "release receipt symlink rejected"
  [ "$(/usr/bin/stat -f %u "$marker")" = 0 ] || die "release receipt must be root-owned"
  [ "$(/usr/bin/stat -f %g "$marker")" = 0 ] || die "release receipt group must be wheel"
  marker_mode=$(/usr/bin/stat -f %Lp "$marker")
  case "$marker_mode" in 400|444) ;; *) die "release receipt mode must be 0400 or 0444" ;; esac
  [ "$(/usr/bin/stat -f %l "$marker")" = 1 ] || die "hard-linked release receipt rejected"
  assert_no_acl "$marker"
  [ "$(digest "$marker")" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ] || die "release receipt digest mismatch"
}

atomic_rename_exclusive() {
  source=$1
  destination=$2
  [ -e "$source" ] || [ -L "$source" ] || die "atomic-rename source missing: $source"
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || die "atomic-rename destination already exists: $destination"
  source_device=$(/usr/bin/stat -f %d "$source")
  destination_parent=$(/usr/bin/dirname "$destination")
  [ "$source_device" = "$(/usr/bin/stat -f %d "$destination_parent")" ] || die "atomic rename crosses filesystems"
  [ "$(/usr/bin/uname -s)" = Darwin ] || die "exclusive atomic rename requires Darwin renamex_np"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -c '
import ctypes
import fcntl
import os
import stat
import sys
RENAME_EXCL=0x00000004
F_FULLFSYNC=51
libc = ctypes.CDLL(None, use_errno=True)
renamex_np = libc.renamex_np
renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
renamex_np.restype = ctypes.c_int
source_path = sys.argv[1]
destination_path = sys.argv[2]
source = os.fsencode(source_path)
destination = os.fsencode(destination_path)

def sync_fd(fd, *, full=False):
    os.fsync(fd)
    if full:
        fcntl.fcntl(fd, F_FULLFSYNC)

def sync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise RuntimeError(f"not a directory: {path}")
        sync_fd(fd, full=True)
    finally:
        os.close(fd)

source_metadata = os.lstat(source_path)
if stat.S_ISREG(source_metadata.st_mode):
    fd = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        sync_fd(fd, full=True)
    finally:
        os.close(fd)
elif stat.S_ISDIR(source_metadata.st_mode):
    sync_directory(source_path)
elif not stat.S_ISLNK(source_metadata.st_mode):
    raise RuntimeError(f"unsupported atomic-rename source: {source_path}")

source_parent = os.path.dirname(source_path)
destination_parent = os.path.dirname(destination_path)
sync_directory(source_parent)
if destination_parent != source_parent:
    sync_directory(destination_parent)
if renamex_np(source, destination, RENAME_EXCL) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), sys.argv[2])
sync_directory(source_parent)
if destination_parent != source_parent:
    sync_directory(destination_parent)
' "$source" "$destination"
}

sync_regular_file_durable() {
  sync_file=$1
  [ "$(/usr/bin/uname -s)" = Darwin ] || die "durability barrier requires Darwin F_FULLFSYNC"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -c '
import fcntl
import os
import stat
import sys
F_FULLFSYNC=51
path = sys.argv[1]
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode):
    raise RuntimeError(f"durability target is not a regular file: {path}")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    os.fsync(fd)
    fcntl.fcntl(fd, F_FULLFSYNC)
finally:
    os.close(fd)
parent = os.path.dirname(path)
fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(fd)
    fcntl.fcntl(fd, F_FULLFSYNC)
finally:
    os.close(fd)
' "$sync_file"
}

sync_directory_durable() {
  sync_directory=$1
  [ "$(/usr/bin/uname -s)" = Darwin ] || die "directory durability barrier requires Darwin F_FULLFSYNC"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -c '
import fcntl
import os
import stat
import sys
F_FULLFSYNC=51
path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise RuntimeError(f"durability target is not a directory: {path}")
    os.fsync(fd)
    fcntl.fcntl(fd, F_FULLFSYNC)
finally:
    os.close(fd)
' "$sync_directory"
}

sync_tree_durable() {
  sync_root=$1
  [ "$(/usr/bin/uname -s)" = Darwin ] || die "durability barrier requires Darwin F_FULLFSYNC"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -c '
import fcntl
import os
import stat
import sys
F_FULLFSYNC=51
top = sys.argv[1]

def sync_regular(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"non-regular durability file: {path}")
        os.fsync(fd)
    finally:
        os.close(fd)

def sync_directory(path, *, full=False):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise RuntimeError(f"non-directory durability path: {path}")
        os.fsync(fd)
        if full:
            fcntl.fcntl(fd, F_FULLFSYNC)
    finally:
        os.close(fd)

for directory, child_directories, filenames in os.walk(top, topdown=False, followlinks=False):
    for filename in filenames:
        path = os.path.join(directory, filename)
        if stat.S_ISREG(os.lstat(path).st_mode):
            sync_regular(path)
    for child in child_directories:
        path = os.path.join(directory, child)
        if stat.S_ISDIR(os.lstat(path).st_mode):
            sync_directory(path)
    sync_directory(directory)
sync_directory(top, full=True)
' "$sync_root"
}

verify_runtime() {
  [ -x "$PYTHON" ] || die "sealed Python runtime is not installed"
  assert_root_owned_path_chain "$RUNTIME_ROOT"
  assert_secure_tree "$RUNTIME_ROOT"
  CLEAN_PATH=$RUNTIME_ROOT/bin:/usr/bin:/bin:/usr/sbin:/sbin
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -c \
    'import ssl,sys; assert sys.version_info[:3] == (3,11,16); assert sys.prefix == "/opt/trading-desk/runtime/python-3.11.16"; assert ssl.OPENSSL_VERSION.startswith("OpenSSL 3.5.8 ")'
}

verify_guard_source() {
  guard_source=$script_dir/storage-headroom-guard.py
  [ -f "$guard_source" ] || die "missing storage guard beside installer"
  [ ! -L "$guard_source" ] || die "storage guard symlink rejected"
  [ "$(/usr/bin/stat -f %u "$guard_source")" = 0 ] || die "storage guard must be root-owned"
  [ "$(/usr/bin/stat -f %l "$guard_source")" = 1 ] || die "hard-linked storage guard rejected"
  writable=$(/usr/bin/find "$guard_source" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "storage guard is group/world writable"
  assert_no_acl "$guard_source"
  [ "$(digest "$guard_source")" = "$EXPECTED_GUARD_SHA256" ] || die "storage guard digest mismatch"
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ -n "$PROBE_PARENT" ] && [ -n "$PROBE_LABEL" ]; then
    case "$PROBE_PARENT" in
      "$TRADING_ROOT"|"$RELEASES_PARENT"|"$RELEASE_FINAL"|"$RESEARCH_RELEASE"|"$EXECUTOR_RELEASE"|"$BIN_RELEASE"|"$LIBEXEC_PARENT")
        /bin/rm -f "$PROBE_PARENT/.rights-$PROBE_LABEL-target" \
          "$PROBE_PARENT/.rights-$PROBE_LABEL-renamed" \
          "$PROBE_PARENT/.rights-$PROBE_LABEL-create-501" \
          "$PROBE_PARENT/.rights-$PROBE_LABEL-create-450" \
          "$PROBE_PARENT/.rights-$PROBE_LABEL-create-451" \
          "$PROBE_PARENT/.rights-$PROBE_LABEL-create-452"
        ;;
    esac
  fi
  case "$PROBE_TMP" in
    /private/tmp/trading-desk-install-probe.*)
      [ ! -L "$PROBE_TMP" ] && /usr/bin/find "$PROBE_TMP" -depth -delete 2>/dev/null
      ;;
  esac
  if [ "$LOCK_HELD" = 1 ]; then
    /bin/rm -f "$INSTALL_LOCK"
  fi
  exit "$status"
}

acquire_install_lock() {
  /usr/bin/shlock -p "$$" -f "$INSTALL_LOCK" || die "another installer transaction holds $INSTALL_LOCK"
  LOCK_HELD=1
  /usr/sbin/chown root:wheel "$INSTALL_LOCK"
  /bin/chmod 0600 "$INSTALL_LOCK"
  assert_no_acl "$INSTALL_LOCK"
}

assert_identities() {
  [ "$(/usr/bin/id -u 501)" = 501 ] || die "admin UID 501 is unavailable"
  [ "$(/usr/bin/id -u trading-research)" = 450 ] || die "trading-research UID drift"
  [ "$(/usr/bin/id -u trading-executor)" = 451 ] || die "trading-executor UID drift"
  [ "$(/usr/bin/id -u trading-control)" = 452 ] || die "trading-control UID drift"
  [ "$(/usr/bin/id -g trading-research)" = 450 ] || die "trading-research primary GID drift"
  [ "$(/usr/bin/id -g trading-executor)" = 451 ] || die "trading-executor primary GID drift"
  [ "$(/usr/bin/id -g trading-control)" = 452 ] || die "trading-control primary GID drift"
}

identity_uid() {
  case "$1" in '#501') /bin/echo 501 ;; *) /usr/bin/id -u "$1" ;; esac
}

identity_gid() {
  case "$1" in '#501') /usr/bin/id -g 501 ;; *) /usr/bin/id -g "$1" ;; esac
}

run_as() {
  run_identity=$1
  shift
  /usr/bin/sudo -n -u "$run_identity" -- "$@"
}

expect_denied() {
  denial_description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    die "unexpectedly permitted: $denial_description"
  fi
}

prepare_probe_sources() {
  [ -z "$PROBE_TMP" ] || return 0
  PROBE_TMP=$(/usr/bin/mktemp -d /private/tmp/trading-desk-install-probe.XXXXXX)
  /usr/sbin/chown root:wheel "$PROBE_TMP"
  /bin/chmod 0711 "$PROBE_TMP"
  for identity in '#501' trading-research trading-executor trading-control; do
    uid=$(identity_uid "$identity")
    gid=$(identity_gid "$identity")
    identity_dir=$PROBE_TMP/$uid
    /bin/mkdir -m 0700 "$identity_dir"
    /usr/sbin/chown "$uid:$gid" "$identity_dir"
    run_as "$identity" /usr/bin/touch "$identity_dir/replacement"
  done
}

verify_parent_denials() {
  parent=$1
  label=$2
  case "$label" in current|releases|release|research|executor|bin|libexec) ;; *) die "unsafe probe label" ;; esac
  assert_secure_directory "$parent"
  prepare_probe_sources
  PROBE_PARENT=$parent
  PROBE_LABEL=$label
  target=$parent/.rights-$label-target
  renamed=$parent/.rights-$label-renamed
  [ ! -e "$target" ] && [ ! -L "$target" ] || die "probe target already exists"
  [ ! -e "$renamed" ] && [ ! -L "$renamed" ] || die "probe rename target already exists"
  /bin/echo "installer-rights-probe=$EXPECTED_COMMIT" > "$target"
  /usr/sbin/chown root:wheel "$target"
  /bin/chmod 0400 "$target"
  target_digest=$(digest "$target")
  for identity in '#501' trading-research trading-executor trading-control; do
    uid=$(identity_uid "$identity")
    created=$parent/.rights-$label-create-$uid
    replacement=$PROBE_TMP/$uid/replacement
    expect_denied "$identity create in $label parent" run_as "$identity" /usr/bin/touch "$created"
    expect_denied "$identity delete from $label parent" run_as "$identity" /bin/rm -f "$target"
    expect_denied "$identity rename in $label parent" run_as "$identity" /bin/mv "$target" "$renamed"
    expect_denied "$identity replace in $label parent" run_as "$identity" /bin/mv -f "$replacement" "$target"
    [ -f "$target" ] && [ ! -L "$target" ] || die "probe target changed after denied operation"
    [ "$(digest "$target")" = "$target_digest" ] || die "probe target bytes changed after denied operation"
    [ -f "$replacement" ] || die "replacement source consumed after denied operation"
    [ ! -e "$created" ] && [ ! -L "$created" ] || die "denied create left an entry"
    [ ! -e "$renamed" ] && [ ! -L "$renamed" ] || die "denied rename left an entry"
  done
  /bin/rm -f "$target"
  PROBE_PARENT=
  PROBE_LABEL=
}

assert_archive_members() {
  archive=$1
  member_list=$PROBE_TMP/archive-members.txt
  /usr/bin/tar -tf "$archive" > "$member_list"
  [ -s "$member_list" ] || die "source archive is empty"
  while IFS= read -r member; do
    case "$member" in
      hypergrok-trading-desk/|hypergrok-trading-desk/*) ;;
      *) die "source archive member escapes reviewed prefix: $member" ;;
    esac
    case "/$member/" in */../*|*/./*) die "source archive member contains traversal: $member" ;; esac
  done < "$member_list"
}

harden_release() {
  /usr/sbin/chown -R root:wheel "$RELEASE_FINAL"
  /bin/chmod -RN "$RELEASE_FINAL"
  /usr/bin/find "$RELEASE_FINAL" -type l -exec /bin/chmod -h 0755 {} +
  /usr/bin/find "$RELEASE_FINAL" -type f -perm +111 -exec /bin/chmod 0555 {} +
  /usr/bin/find "$RELEASE_FINAL" -type f ! -perm +111 -exec /bin/chmod 0444 {} +
  # Keep the release root at 0700 until every descendant is hardened so tar
  # modes can never become reachable during the transition.
  /usr/bin/find "$RELEASE_FINAL" -mindepth 1 -type d -exec /bin/chmod 0755 {} +
  /bin/chmod 0755 "$RELEASE_FINAL"
}

verify_release_payload() {
  media=$1
  marker=$2
  verify_release_receipt "$marker"
  case "$marker" in
    "$RELEASE_INSTALLING")
      [ ! -e "$RELEASE_READY" ] && [ ! -L "$RELEASE_READY" ] || die "INSTALLING release contains READY"
      ;;
    "$RELEASE_READY")
      [ ! -e "$RELEASE_INSTALLING" ] && [ ! -L "$RELEASE_INSTALLING" ] || die "READY release contains INSTALLING"
      ;;
    *) die "unrecognized release marker path" ;;
  esac
  assert_exact_directory "$RELEASE_FINAL" 755
  assert_exact_directory "$RESEARCH_RELEASE" 755
  assert_exact_directory "$EXECUTOR_RELEASE" 755
  assert_exact_directory "$BIN_RELEASE" 755
  assert_secure_tree "$RELEASE_FINAL"
  assert_immutable_modes "$RELEASE_FINAL"
  top_count=$(/usr/bin/find "$RELEASE_FINAL" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END {print NR + 0}')
  [ "$top_count" = 4 ] || die "release contains an unexpected top-level entry"
  [ -f "$GUARD_RELEASE" ] && [ ! -L "$GUARD_RELEASE" ] || die "installed guard is missing or symlinked"
  [ "$(digest "$GUARD_RELEASE")" = "$EXPECTED_GUARD_SHA256" ] || die "installed storage guard digest mismatch"
  bin_count=$(/usr/bin/find "$BIN_RELEASE" -mindepth 1 -maxdepth 1 -print | /usr/bin/awk 'END {print NR + 0}')
  [ "$bin_count" = 1 ] || die "release bin directory contains an unexpected entry"
  [ "$(digest "$RESEARCH_RELEASE/INSTALL-MANIFEST.txt")" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ] || die "research install manifest mismatch"
  [ "$(digest "$EXECUTOR_RELEASE/INSTALL-MANIFEST.txt")" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ] || die "executor install manifest mismatch"
  [ "$(/usr/bin/head -n 1 "$RESEARCH_RELEASE/.venv/bin/trading-harness")" = "#!$RESEARCH_RELEASE/.venv/bin/python" ] || die "research shebang drift"
  [ "$(/usr/bin/head -n 1 "$EXECUTOR_RELEASE/.venv/bin/trading-harness-executor")" = "#!$EXECUTOR_RELEASE/.venv/bin/python" ] || die "executor shebang drift"

  research_freeze=$PROBE_TMP/resolved-research.txt
  executor_freeze=$PROBE_TMP/resolved-executor.txt
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null \
    "$RESEARCH_RELEASE/.venv/bin/python" -B -I -m pip --isolated check
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null \
    "$EXECUTOR_RELEASE/.venv/bin/python" -B -I -m pip --isolated check
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null \
    "$RESEARCH_RELEASE/.venv/bin/python" -B -I -m pip --isolated freeze > "$research_freeze"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null \
    "$EXECUTOR_RELEASE/.venv/bin/python" -B -I -m pip --isolated freeze > "$executor_freeze"
  /usr/bin/cmp -s "$research_freeze" "$media/staged/resolved-research.txt" || die "research environment differs from lock"
  /usr/bin/cmp -s "$executor_freeze" "$media/staged/resolved-executor.txt" || die "executor environment differs from lock"
  if run_as '#501' /bin/test -w "$RELEASE_FINAL"; then die "admin login can modify release"; fi
  if run_as trading-research /bin/test -w "$RESEARCH_RELEASE/.venv"; then die "research identity can modify its venv"; fi
  if run_as trading-executor /bin/test -w "$EXECUTOR_RELEASE/.venv"; then die "executor identity can modify its venv"; fi
  if run_as trading-control /bin/test -w "$RELEASE_FINAL"; then die "control identity can modify release"; fi
  run_as trading-research /usr/bin/env -i PATH="$RESEARCH_RELEASE/.venv/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
    "$RESEARCH_RELEASE/.venv/bin/trading-harness" doctor
  run_as trading-executor /usr/bin/env -i PATH="$EXECUTOR_RELEASE/.venv/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
    "$EXECUTOR_RELEASE/.venv/bin/trading-harness-executor" --help >/dev/null
  run_as trading-executor /usr/bin/env -i PATH="$EXECUTOR_RELEASE/.venv/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
    "$EXECUTOR_RELEASE/.venv/bin/python" -B -I -c \
    'from Crypto.Hash import keccak; assert keccak.new(digest_bits=256, data=b"x").hexdigest() == "7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83"'
  run_as trading-research /usr/bin/env -i PATH="$RESEARCH_RELEASE/.venv/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
    "$RESEARCH_RELEASE/.venv/bin/python" -B -I -c \
    'import mcp, pydantic_core; assert mcp is not None and pydantic_core is not None'
  assert_secure_tree "$RELEASE_FINAL"
  assert_immutable_modes "$RELEASE_FINAL"
}

verify_release_parent_denials() {
  verify_parent_denials "$RELEASE_FINAL" release
  verify_parent_denials "$RESEARCH_RELEASE" research
  verify_parent_denials "$EXECUTOR_RELEASE" executor
  verify_parent_denials "$BIN_RELEASE" bin
}

assert_safe_keychain_helper_stage() {
  path=$1
  case "$path" in
    "$EXECUTOR_KEYCHAIN_HELPER_STAGE"|"$CONTROL_KEYCHAIN_HELPER_STAGE") ;;
    *) die "unexpected keychain helper staging path: $path" ;;
  esac
  [ -f "$path" ] && [ ! -L "$path" ] || die "keychain helper stage is not a regular file: $path"
  [ "$(/bin/realpath "$path")" = "$path" ] || die "keychain helper staging path is not canonical: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "keychain helper stage must be root-owned: $path"
  [ "$(/usr/bin/stat -f %l "$path")" = 1 ] || die "hard-linked keychain helper stage rejected: $path"
  writable=$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "keychain helper stage is group/world writable: $path"
  assert_no_acl "$path"
}

verify_installed_keychain_helper() {
  path=$1
  expected_gid=$2
  expected_sha=$3
  expected_identifier=$4
  [ -f "$path" ] && [ ! -L "$path" ] || die "keychain helper missing or symlinked: $path"
  [ "$(/bin/realpath "$path")" = "$path" ] || die "keychain helper path is not canonical: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "keychain helper owner must be root: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = "$expected_gid" ] || die "keychain helper group differs: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = 510 ] || die "keychain helper mode must be 0510: $path"
  [ "$(/usr/bin/stat -f %l "$path")" = 1 ] || die "hard-linked keychain helper rejected: $path"
  assert_no_acl "$path"
  [ "$(digest "$path")" = "$expected_sha" ] || die "keychain helper digest mismatch: $path"
  details=$PROBE_TMP/keychain-helper-codesign-$expected_gid.txt
  /usr/bin/codesign --verify --strict --verbose=2 "$path" || die "keychain helper signature invalid: $path"
  /usr/bin/codesign -d --verbose=4 "$path" > /dev/null 2> "$details"
  /usr/bin/grep -Fqx "Identifier=$expected_identifier" "$details" || die "keychain helper identifier differs: $path"
  /usr/bin/grep -F 'flags=0x10002(adhoc,runtime)' "$details" >/dev/null || die "keychain helper lacks hardened runtime: $path"
}

install_role_helpers() {
  media=$1
  ensure_root_directory "$LIBEXEC_PARENT" 755
  verify_parent_denials "$LIBEXEC_PARENT" libexec
  for role in executor control; do
    case "$role" in
      executor)
        source=$media/$KEYCHAIN_HELPER_MEDIA_NAME/trading-keychain-reader-executor-v1
        stage=$EXECUTOR_KEYCHAIN_HELPER_STAGE
        final=$EXECUTOR_KEYCHAIN_HELPER
        group=trading-executor
        gid=451
        expected_sha=$EXPECTED_EXECUTOR_KEYCHAIN_HELPER_SHA256
        identifier=com.jawndiego.trading-desk.keychain-reader.executor.v1
        ;;
      control)
        source=$media/$KEYCHAIN_HELPER_MEDIA_NAME/trading-keychain-reader-control-v1
        stage=$CONTROL_KEYCHAIN_HELPER_STAGE
        final=$CONTROL_KEYCHAIN_HELPER
        group=trading-control
        gid=452
        expected_sha=$EXPECTED_CONTROL_KEYCHAIN_HELPER_SHA256
        identifier=com.jawndiego.trading-desk.keychain-reader.control.v1
        ;;
    esac
    if [ -e "$final" ] || [ -L "$final" ]; then
      [ ! -e "$stage" ] && [ ! -L "$stage" ] || die "helper final and staging paths both exist: $role"
      verify_installed_keychain_helper "$final" "$gid" "$expected_sha" "$identifier"
      continue
    fi
    if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
      /bin/cp "$source" "$stage"
    else
      assert_safe_keychain_helper_stage "$stage"
    fi
    assert_safe_keychain_helper_stage "$stage"
    # A prior run may have stopped while copying.  Never trust the retained
    # bytes: after validating the inode, replace its contents from sealed media.
    /bin/cp "$source" "$stage"
    assert_safe_keychain_helper_stage "$stage"
    /usr/sbin/chown root:"$group" "$stage"
    /bin/chmod 0510 "$stage"
    sync_regular_file_durable "$stage"
    verify_installed_keychain_helper "$stage" "$gid" "$expected_sha" "$identifier"
    atomic_rename_exclusive "$stage" "$final"
    verify_installed_keychain_helper "$final" "$gid" "$expected_sha" "$identifier"
  done
  verify_parent_denials "$LIBEXEC_PARENT" libexec
  run_as trading-executor /bin/test -x "$EXECUTOR_KEYCHAIN_HELPER" || die "executor cannot execute its role helper"
  run_as trading-control /bin/test -x "$CONTROL_KEYCHAIN_HELPER" || die "control cannot execute its role helper"
  for identity in '#501' trading-research; do
    if run_as "$identity" /bin/test -x "$EXECUTOR_KEYCHAIN_HELPER"; then die "$identity can execute executor helper"; fi
    if run_as "$identity" /bin/test -x "$CONTROL_KEYCHAIN_HELPER"; then die "$identity can execute control helper"; fi
  done
  if run_as trading-executor /bin/test -x "$CONTROL_KEYCHAIN_HELPER"; then die "executor can execute control helper"; fi
  if run_as trading-control /bin/test -x "$EXECUTOR_KEYCHAIN_HELPER"; then die "control can execute executor helper"; fi
  if run_as trading-executor /bin/test -r "$EXECUTOR_KEYCHAIN_HELPER"; then die "executor can read helper bytes"; fi
  if run_as trading-control /bin/test -r "$CONTROL_KEYCHAIN_HELPER"; then die "control can read helper bytes"; fi
}

build_release() {
  media=$1
  [ ! -e "$RELEASE_FINAL" ] && [ ! -L "$RELEASE_FINAL" ] || die "release path already exists"
  [ ! -e "$RELEASE_BOOTSTRAP" ] && [ ! -L "$RELEASE_BOOTSTRAP" ] || die "bootstrap path exists; use explicit quarantine after root review"
  /bin/mkdir -m 0700 "$RELEASE_BOOTSTRAP"
  /usr/sbin/chown root:wheel "$RELEASE_BOOTSTRAP"
  write_installing_receipt "$RELEASE_BOOTSTRAP"
  verify_release_receipt "$RELEASE_BOOTSTRAP/.INSTALLING"
  atomic_rename_exclusive "$RELEASE_BOOTSTRAP" "$RELEASE_FINAL"
  verify_release_receipt "$RELEASE_INSTALLING"

  /bin/mkdir -m 0700 "$RESEARCH_RELEASE" "$EXECUTOR_RELEASE" "$BIN_RELEASE"
  archive=$media/$ARCHIVE_NAME
  assert_archive_members "$archive"
  /usr/bin/tar -xf "$archive" -C "$RESEARCH_RELEASE" --strip-components 1
  /usr/bin/tar -xf "$archive" -C "$EXECUTOR_RELEASE" --strip-components 1
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -m venv "$RESEARCH_RELEASE/.venv"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C "$PYTHON" -B -I -m venv "$EXECUTOR_RELEASE/.venv"
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$RESEARCH_RELEASE/.venv/bin/python" -B -I -m pip --isolated install --no-index --no-cache-dir --only-binary=:all: \
    --find-links="$media/wheelhouse" 'trading-harness[mcp]==0.2.0.dev0'
  /usr/bin/env -i PATH="$CLEAN_PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$EXECUTOR_RELEASE/.venv/bin/python" -B -I -m pip --isolated install --no-index --no-cache-dir --only-binary=:all: \
    --find-links="$media/wheelhouse" 'trading-harness[execution]==0.2.0.dev0'
  /bin/cp "$RELEASE_INSTALLING" "$RESEARCH_RELEASE/INSTALL-MANIFEST.txt"
  /bin/cp "$RELEASE_INSTALLING" "$EXECUTOR_RELEASE/INSTALL-MANIFEST.txt"
  /bin/cp "$guard_source" "$GUARD_RELEASE"
  harden_release
  verify_release_payload "$media" "$RELEASE_INSTALLING"
  verify_release_parent_denials
  sync_tree_durable "$RELEASE_FINAL"
  atomic_rename_exclusive "$RELEASE_INSTALLING" "$RELEASE_READY"
  verify_release_payload "$media" "$RELEASE_READY"
}

verify_ready_release() {
  media=$1
  [ -d "$RELEASE_FINAL" ] && [ ! -L "$RELEASE_FINAL" ] || die "ready release is missing"
  [ -f "$RELEASE_READY" ] || die "release is not READY"
  [ ! -e "$RELEASE_INSTALLING" ] && [ ! -L "$RELEASE_INSTALLING" ] || die "READY release still contains INSTALLING"
  verify_release_payload "$media" "$RELEASE_READY"
}

assert_current_exact() {
  [ -L "$CURRENT_LINK" ] || die "current is not a symlink"
  [ "$(/usr/bin/stat -f %u "$CURRENT_LINK")" = 0 ] || die "current symlink must be root-owned"
  [ "$(/usr/bin/stat -f %g "$CURRENT_LINK")" = 0 ] || die "current symlink group must be wheel"
  [ "$(/usr/bin/stat -f %Lp "$CURRENT_LINK")" = 755 ] || die "current symlink mode must be 0755"
  [ "$(/usr/bin/stat -f %l "$CURRENT_LINK")" = 1 ] || die "hard-linked current symlink rejected"
  [ "$(/usr/bin/readlink "$CURRENT_LINK")" = "releases/$EXPECTED_COMMIT" ] || die "current target is not the reviewed relative target"
  [ "$(/bin/realpath "$CURRENT_LINK")" = "$RELEASE_FINAL" ] || die "current does not resolve to the exact reviewed release"
  verify_release_receipt "$CURRENT_LINK/.READY"
}

assert_current_candidate_exact() {
  [ -L "$CURRENT_CANDIDATE" ] || die "current candidate is not a symlink"
  [ "$(/usr/bin/readlink "$CURRENT_CANDIDATE")" = "releases/$EXPECTED_COMMIT" ] || die "current candidate is not relative and exact"
  [ "$(/usr/bin/stat -f %u "$CURRENT_CANDIDATE")" = 0 ] || die "current candidate must be root-owned"
  [ "$(/usr/bin/stat -f %g "$CURRENT_CANDIDATE")" = 0 ] || die "current candidate group must be wheel"
  [ "$(/usr/bin/stat -f %Lp "$CURRENT_CANDIDATE")" = 755 ] || die "current candidate mode must be 0755"
  [ "$(/bin/realpath "$CURRENT_CANDIDATE")" = "$RELEASE_FINAL" ] || die "current candidate does not resolve to the exact READY release"
  verify_release_receipt "$CURRENT_CANDIDATE/.READY"
}

promote_current_once() {
  [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ] || die "current already exists; v1 never upgrades or replaces it"
  verify_release_receipt "$RELEASE_READY"
  if [ ! -e "$CURRENT_CANDIDATE" ] && [ ! -L "$CURRENT_CANDIDATE" ]; then
    (umask 022; /bin/ln -s "releases/$EXPECTED_COMMIT" "$CURRENT_CANDIDATE")
    /usr/sbin/chown -h root:wheel "$CURRENT_CANDIDATE"
    /bin/chmod -h 0755 "$CURRENT_CANDIDATE"
  fi
  assert_current_candidate_exact
  [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ] || die "current appeared before exclusive promotion"
  atomic_rename_exclusive "$CURRENT_CANDIDATE" "$CURRENT_LINK"
  assert_current_exact
  sync_directory_durable "$TRADING_ROOT"
}

apply_install() {
  media=$1
  case "$media" in /*) ;; *) die "media path must be absolute" ;; esac
  [ "$ROLE_HELPER_RELEASE_REBIND_REQUIRED" = 0 ] || die "role-helper release commit/wheel/pack rebind is required before apply"
  assert_sealed_root
  assert_identities
  assert_opt_ancestor_chain
  verify_runtime
  assert_root_owned_path_chain "$media"
  verify_media "$media" sealed-pack
  verify_guard_source
  trap cleanup EXIT HUP INT TERM
  acquire_install_lock
  ensure_root_directory "$RELEASES_PARENT" 755
  verify_parent_denials "$TRADING_ROOT" current
  verify_parent_denials "$RELEASES_PARENT" releases
  [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ] || die "current already exists; v1 first-install refuses replacement"
  if [ -e "$CURRENT_CANDIDATE" ] || [ -L "$CURRENT_CANDIDATE" ]; then
    [ -f "$RELEASE_READY" ] && [ ! -e "$RELEASE_INSTALLING" ] || die "current candidate exists without an exact READY release"
    assert_current_candidate_exact
  fi
  if [ -e "$RELEASE_BOOTSTRAP" ] || [ -L "$RELEASE_BOOTSTRAP" ]; then
    die "bootstrap transaction exists; use --quarantine-incomplete with the exact receipt hash"
  fi
  if [ -e "$RELEASE_FINAL" ] || [ -L "$RELEASE_FINAL" ]; then
    if [ -f "$RELEASE_READY" ] && [ ! -e "$RELEASE_INSTALLING" ]; then
      prepare_probe_sources
      verify_ready_release "$media"
    elif [ -f "$RELEASE_INSTALLING" ] && [ ! -e "$RELEASE_READY" ]; then
      die "incomplete release exists; use --quarantine-incomplete with the exact receipt hash"
    else
      die "unrecognized release state requires root review"
    fi
  else
    prepare_probe_sources
    build_release "$media"
  fi
  install_role_helpers "$media"
  verify_release_parent_denials
  verify_ready_release "$media"
  sync_tree_durable "$RELEASE_FINAL"
  promote_current_once
  /bin/echo "INSTALL_COMPLETE commit=$EXPECTED_COMMIT current=$CURRENT_LINK release=$RELEASE_FINAL"
  /bin/echo 'No config, credential, database, init, service, process, network, or venue operation was performed.'
}

quarantine_incomplete() {
  supplied_sha=$1
  [ "$supplied_sha" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ] || die "quarantine confirmation does not match the exact canonical receipt hash"
  assert_sealed_root
  assert_identities
  assert_opt_ancestor_chain
  verify_runtime
  trap cleanup EXIT HUP INT TERM
  acquire_install_lock
  [ ! -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ] || die "refuse quarantine while current exists"
  [ ! -e "$CURRENT_CANDIDATE" ] && [ ! -L "$CURRENT_CANDIDATE" ] || die "refuse quarantine while a current candidate exists"
  source=
  if [ -d "$RELEASE_FINAL" ] && [ ! -L "$RELEASE_FINAL" ]; then source=$RELEASE_FINAL; fi
  if [ -d "$RELEASE_BOOTSTRAP" ] && [ ! -L "$RELEASE_BOOTSTRAP" ]; then
    [ -z "$source" ] || die "both release and bootstrap paths exist"
    source=$RELEASE_BOOTSTRAP
  fi
  [ -n "$source" ] || die "no incomplete release exists"
  marker=$source/.INSTALLING
  canonical_marker=0
  if [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(digest "$marker")" = "$EXPECTED_RELEASE_RECEIPT_SHA256" ]; then
    verify_release_receipt "$marker"
    canonical_marker=1
  else
    [ "$source" = "$RELEASE_BOOTSTRAP" ] || die "release is missing its exact canonical INSTALLING receipt"
    # No payload build starts under the bootstrap name. This narrow case
    # recovers a crash while the canonical receipt itself was being created.
    bootstrap_extra=$(/usr/bin/find "$source" -mindepth 1 -maxdepth 1 \
      ! -name '.INSTALLING' ! -name '.INSTALLING.tmp' -print -quit)
    [ -z "$bootstrap_extra" ] || die "markerless bootstrap contains an unexpected entry"
  fi
  [ ! -e "$source/.READY" ] && [ ! -L "$source/.READY" ] || die "READY releases cannot be quarantined"
  # Quarantine never opens or follows release children. A crash may have left
  # venv symlinks temporarily broken or archive modes group-writable, so the
  # move gate checks ownership, world writability, ACLs and file types without
  # requiring the incomplete payload to be runnable.
  assert_incomplete_tree_safe_to_move "$source"
  sync_tree_durable "$source"
  ensure_root_directory "$QUARANTINE_PARENT" 700
  source_inode=$(/usr/bin/stat -f %i "$source")
  /bin/echo "$source_inode" | /usr/bin/grep -Eq '^[0-9]+$' || die "invalid incomplete-release inode"
  QUARANTINE_FINAL=$QUARANTINE_PREFIX-$source_inode
  [ ! -e "$QUARANTINE_FINAL" ] && [ ! -L "$QUARANTINE_FINAL" ] || die "quarantine destination already exists"
  atomic_rename_exclusive "$source" "$QUARANTINE_FINAL"
  if [ "$canonical_marker" = 1 ]; then
    verify_release_receipt "$QUARANTINE_FINAL/.INSTALLING"
  fi
  /bin/echo "QUARANTINE_COMPLETE source=$source destination=$QUARANTINE_FINAL receipt_sha256=$supplied_sha"
  /bin/echo 'The incomplete release was atomically moved, not deleted; current was absent and unchanged.'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die "plan takes no arguments"
    plan
    ;;
  --apply)
    [ "$#" -eq 2 ] || die "--apply requires one absolute sealed media directory"
    apply_install "$2"
    ;;
  --quarantine-incomplete)
    [ "$#" -eq 2 ] || die "--quarantine-incomplete requires the exact canonical INSTALLING receipt SHA-256"
    quarantine_incomplete "$2"
    ;;
  *)
    die "unknown phase; run with no arguments for the plan"
    ;;
esac
