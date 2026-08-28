#!/bin/sh
set -eu
umask 077

BASE=/var/db/trading-desk-volumes
EXECUTOR_ROOT=$BASE/executor
EXECUTOR_STATE=$EXECUTOR_ROOT/state
EXECUTION=$EXECUTOR_STATE/execution
NONCE=$EXECUTOR_STATE/nonce
DAILY_LOSS=$EXECUTOR_STATE/daily-loss
SOCKET=$EXECUTOR_STATE/socket
EXECUTOR_LOGS=$EXECUTOR_ROOT/logs
RESEARCH_ROOT=$BASE/research
RESEARCH_STATE=$RESEARCH_ROOT/state
LEARNING=$RESEARCH_STATE/learning-shared
RESEARCH_PRIVATE=$RESEARCH_STATE/research-private
RESEARCH_LOGS=$RESEARCH_ROOT/logs

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no ACL or filesystem state changed'
  /bin/echo "Apply the pre-init, no-delete inheritance model at $EXECUTION and $LEARNING."
  /bin/echo 'Nonce, daily-loss, socket, and research-private parents retain no named ACL.'
  /bin/echo 'The script requires empty state parents, exact APFS volume markers, and the literal --apply-preinit.'
  /bin/echo 'It never runs executor init, opens SQLite, installs a service, reads a credential, or calls a venue.'
}

assert_sealed_root() {
  [ "$(/usr/bin/id -u)" -eq 0 ] || die "run the sealed copy as root"
  [ "$(/usr/bin/id -u trading-research)" = 450 ] || die "trading-research UID drift"
  [ "$(/usr/bin/id -u trading-executor)" = 451 ] || die "trading-executor UID drift"
  [ "$(/usr/bin/id -u trading-control)" = 452 ] || die "trading-control UID drift"
  script_path=$(/bin/realpath "$0")
  [ "$script_path" = "$0" ] || die "script path must be canonical and absolute"
  [ -f "$script_path" ] && [ ! -L "$script_path" ] || die "script must be a real regular file"
  script_dir=$(/usr/bin/dirname "$script_path")
  [ "$(/usr/bin/stat -f %u "$script_path")" = 0 ] || die "script must be root-owned"
  [ "$(/usr/bin/stat -f %g "$script_path")" = 0 ] || die "script group must be wheel"
  [ "$(/usr/bin/stat -f %l "$script_path")" = 1 ] || die "hard-linked script rejected"
  [ -z "$(/usr/bin/find "$script_path" -maxdepth 0 -perm +022 -print -quit)" ] || die "script is group/world writable"
  [ -z "$(/bin/ls -led "$script_path" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')" ] || die "script has a named ACL"
  cursor=$script_dir
  while :; do
    [ -d "$cursor" ] && [ ! -L "$cursor" ] || die "script ancestor is unsafe: $cursor"
    [ "$(/bin/realpath "$cursor")" = "$cursor" ] || die "script ancestor is non-canonical: $cursor"
    [ "$(/usr/bin/stat -f %u "$cursor")" = 0 ] || die "script ancestor is not root-owned: $cursor"
    [ "$(/usr/bin/stat -f %g "$cursor")" = 0 ] || die "script ancestor group is not wheel: $cursor"
    [ -z "$(/usr/bin/find "$cursor" -maxdepth 0 -perm +022 -print -quit)" ] || die "script ancestor is group/world writable: $cursor"
    [ -z "$(/bin/ls -led "$cursor" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')" ] || die "script ancestor has a named ACL: $cursor"
    [ "$cursor" = / ] && break
    cursor=$(/usr/bin/dirname "$cursor")
  done
}

acl_entries() {
  /bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p'
}

acl_export() {
  acl_entries "$1" | /usr/bin/sed -E 's/^[[:space:]]*[0-9][0-9]*:[[:space:]]*//'
}

# Do not use chmod -C: deployed Darwin returns 1 for both canonical ACLs and
# operational errors. Validate the documented canonical entry classes here.
assert_acl_canonical() {
  path=$1
  acl_entries "$path" | /usr/bin/awk '
  {
    is_allow = ($0 ~ / allow /)
    is_deny = ($0 ~ / deny /)
    if (is_allow == is_deny) invalid = 1
    score = (($0 ~ / inherited /) ? -5 : 0) + (is_deny ? 1 : 0)
    if (seen && previous < score) invalid = 1
    previous = score
    seen = 1
  }
  END { exit (!seen || invalid) }
  ' || die "non-canonical ACL order: $path"
}

prepare_recovery_dir() {
  RECOVERY_PARENT=/etc/trading-desk/acl-recovery
  STOP_MARKER=/etc/trading-desk/ACL-RECOVERY-REQUIRED
  [ ! -e "$STOP_MARKER" ] || die "ACL recovery stop marker exists: $STOP_MARKER"
  if [ ! -e "$RECOVERY_PARENT" ]; then
    /bin/mkdir -m 0700 "$RECOVERY_PARENT"
    /usr/sbin/chown root:wheel "$RECOVERY_PARENT"
  fi
  [ -d "$RECOVERY_PARENT" ] || die "ACL recovery parent is not a directory"
  [ ! -L "$RECOVERY_PARENT" ] || die "ACL recovery parent symlink rejected"
  [ "$(/usr/bin/stat -f %u "$RECOVERY_PARENT")" = 0 ] || die "ACL recovery parent must be root-owned"
  [ "$(/usr/bin/stat -f %Lp "$RECOVERY_PARENT")" = 700 ] || die "ACL recovery parent mode must be 0700"
  [ -z "$(acl_entries "$RECOVERY_PARENT")" ] || die "ACL recovery parent must not have a named ACL"
  acl_backup=$RECOVERY_PARENT/preinit-v1
  [ ! -e "$acl_backup" ] || die "unfinished pre-init ACL transaction requires root review: $acl_backup"
  /bin/mkdir -m 0700 "$acl_backup"
  /usr/sbin/chown root:wheel "$acl_backup"
}

write_stop_marker() {
  reason=$1
  temp=$(/usr/bin/mktemp /etc/trading-desk/.ACL-RECOVERY-REQUIRED.XXXXXX)
  {
    /bin/echo 'schema_version=1'
    /bin/echo 'phase=preinit'
    /bin/echo "recovery_directory=$acl_backup"
    /bin/echo "reason=$reason"
  } > "$temp"
  /usr/sbin/chown root:wheel "$temp"
  /bin/chmod 0400 "$temp"
  /bin/mv -f "$temp" "$STOP_MARKER"
}

restore_acl_exact() {
  path=$1
  backup=$2
  label=$3
  reread=$acl_backup/.reread-$label
  /bin/chmod -E "$path" < "$backup" || return 1
  acl_export "$path" > "$reread" || return 1
  /usr/bin/cmp -s "$backup" "$reread" || return 1
  /bin/rm -f "$reread"
}

assert_dir() {
  path=$1
  uid=$2
  gid=$3
  [ -d "$path" ] || die "missing directory: $path"
  [ ! -L "$path" ] || die "symlink directory rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = "$uid" ] || die "owner mismatch: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = "$gid" ] || die "group mismatch: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = 700 ] || die "mode must be 0700: $path"
}

assert_no_acl() {
  [ -z "$(acl_entries "$1")" ] || die "unexpected named ACL: $1"
}

assert_empty() {
  first=$(/usr/bin/find "$1" -mindepth 1 -maxdepth 1 -print -quit)
  [ -z "$first" ] || die "directory must be empty before init: $first"
}

assert_marker() {
  root=$1
  role=$2
  marker=$root/.trading-desk-volume-v1
  [ -f "$marker" ] || die "missing volume marker: $marker"
  [ ! -L "$marker" ] || die "marker symlink rejected: $marker"
  [ "$(/usr/bin/stat -f %u "$marker")" = 0 ] || die "marker must be root-owned"
  [ "$(/usr/bin/stat -f %Lp "$marker")" = 444 ] || die "marker mode must be 0444"
  [ "$(/usr/bin/stat -f %l "$marker")" = 1 ] || die "marker hard link rejected"
  [ "$(/usr/bin/awk 'NF {count += 1} END {print count + 0}' "$marker")" = 7 ] || die "marker record count mismatch"
  [ "$(/usr/bin/awk -F= '$1 == "schema_version" {print $2}' "$marker")" = 1 ] || die "marker schema mismatch"
  [ "$(/usr/bin/awk -F= '$1 == "role" {print $2}' "$marker")" = "$role" ] || die "marker role mismatch"
  case "$role" in
    executor) expected_quota=17179869184; expected_reserve=8589934592 ;;
    research) expected_quota=8589934592; expected_reserve=0 ;;
    *) die "unknown marker role" ;;
  esac
  [ "$(/usr/bin/awk -F= '$1 == "quota_bytes" {print $2}' "$marker")" = "$expected_quota" ] || die "marker quota mismatch"
  [ "$(/usr/bin/awk -F= '$1 == "reserve_bytes" {print $2}' "$marker")" = "$expected_reserve" ] || die "marker reserve mismatch"
  uuid=$(/usr/bin/awk -F= '$1 == "volume_uuid" {print $2}' "$marker")
  container_uuid=$(/usr/bin/awk -F= '$1 == "apfs_container_uuid" {print $2}' "$marker")
  [ "$(/usr/bin/awk -F= '$1 == "filesystem_type" {print $2}' "$marker")" = apfs ] || die "marker filesystem mismatch"
  /bin/echo "$uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "marker UUID malformed"
  /bin/echo "$container_uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "marker container UUID malformed"
  root_device=$(/usr/bin/stat -f %d "$root")
  parent_device=$(/usr/bin/stat -f %d "$BASE")
  [ "$root_device" != "$parent_device" ] || die "volume is not mounted at $root"
  [ "$(/usr/bin/stat -f %d "$marker")" = "$root_device" ] || die "marker device mismatch"
}

reset_acl() {
  path=$1
  shift
  before=$(acl_entries "$path")
  if [ -n "$before" ]; then
    while IFS= read -r line
    do
      case "$line" in
        *trading-research*" allow "*|*trading-executor*" allow "*|*trading-control*" allow "*) ;;
        *) die "unexpected pre-existing ACL on $path: $line" ;;
      esac
    done <<EOF
$before
EOF
  fi
  count=$(/bin/echo "$before" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  while [ "$count" -gt 0 ]; do
    count=$((count - 1))
    /bin/chmod -a# "$count" "$path"
  done
  index=0
  for entry in "$@"; do
    /bin/chmod +a# "$index" "$entry" "$path"
    index=$((index + 1))
  done
  assert_acl_canonical "$path"
  after=$(acl_entries "$path")
  /bin/echo "$after" | /usr/bin/grep -q delete_child && die "delete_child present: $path"
}

run_as() {
  identity=$1
  shift
  /usr/bin/sudo -n -u "$identity" -- "$@"
}

expect_denied() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    die "unexpectedly allowed: $label"
  fi
  /bin/echo "DENIED_OK $label"
}

apply_preinit() {
  assert_sealed_root
  assert_marker "$EXECUTOR_ROOT" executor
  assert_marker "$RESEARCH_ROOT" research

  assert_dir "$BASE" 0 0
  assert_dir "$EXECUTOR_ROOT" 0 0
  assert_dir "$EXECUTOR_STATE" 0 0
  assert_dir "$EXECUTOR_LOGS" 0 0
  assert_dir "$RESEARCH_ROOT" 0 0
  assert_dir "$RESEARCH_STATE" 0 0
  assert_dir "$RESEARCH_LOGS" 0 0
  for path in "$EXECUTION" "$NONCE" "$DAILY_LOSS" "$SOCKET" "$LEARNING"; do
    assert_dir "$path" 451 451
    assert_empty "$path"
  done
  assert_dir "$RESEARCH_PRIVATE" 450 450
  assert_empty "$RESEARCH_PRIVATE"
  assert_no_acl "$NONCE"
  assert_no_acl "$DAILY_LOSS"
  assert_no_acl "$SOCKET"
  assert_no_acl "$RESEARCH_PRIVATE"

  prepare_recovery_dir
  acl_export "$BASE" > "$acl_backup/01-base"
  acl_export "$EXECUTOR_ROOT" > "$acl_backup/02-executor-root"
  acl_export "$EXECUTOR_STATE" > "$acl_backup/03-executor-state"
  acl_export "$EXECUTOR_LOGS" > "$acl_backup/04-executor-logs"
  acl_export "$RESEARCH_ROOT" > "$acl_backup/05-research-root"
  acl_export "$RESEARCH_STATE" > "$acl_backup/06-research-state"
  acl_export "$RESEARCH_LOGS" > "$acl_backup/07-research-logs"
  acl_export "$EXECUTION" > "$acl_backup/08-execution"
  acl_export "$LEARNING" > "$acl_backup/09-learning"
  /usr/sbin/chown -R root:wheel "$acl_backup"
  /usr/bin/find "$acl_backup" -type f -exec /bin/chmod 0400 {} +
  committed=0
  exec_main=$EXECUTION/.acl-preinit-main
  exec_replacement=$EXECUTION/.acl-preinit-replacement
  exec_sidecar=$EXECUTION/.acl-preinit-sidecar
  exec_snapshot=$EXECUTION/.acl-preinit-snapshot
  learning_main=$LEARNING/.acl-preinit-main
  learning_control_replacement=$LEARNING/.acl-preinit-control-replacement
  learning_research_replacement=$LEARNING/.acl-preinit-research-replacement
  learning_control_sidecar=$LEARNING/.acl-preinit-control-sidecar
  learning_research_sidecar=$LEARNING/.acl-preinit-research-sidecar
  learning_control_snapshot=$LEARNING/.acl-preinit-control-snapshot
  learning_research_snapshot=$LEARNING/.acl-preinit-research-snapshot
  remove_probes() {
    /bin/rm -f "$exec_main" "$exec_replacement" "$exec_sidecar" "${exec_main}.moved" \
      "$learning_main" "$learning_control_replacement" "$learning_research_replacement" \
      "$learning_control_sidecar" "$learning_research_sidecar" \
      "${learning_main}.control-moved" "${learning_main}.research-moved"
    /bin/rmdir "$exec_snapshot" "$learning_control_snapshot" "$learning_research_snapshot" 2>/dev/null || true
  }
  cleanup() {
    remove_probes
    if [ "$committed" = 0 ]; then
      restored=1
      restore_acl_exact "$BASE" "$acl_backup/01-base" base || restored=0
      restore_acl_exact "$EXECUTOR_ROOT" "$acl_backup/02-executor-root" executor-root || restored=0
      restore_acl_exact "$EXECUTOR_STATE" "$acl_backup/03-executor-state" executor-state || restored=0
      restore_acl_exact "$EXECUTOR_LOGS" "$acl_backup/04-executor-logs" executor-logs || restored=0
      restore_acl_exact "$RESEARCH_ROOT" "$acl_backup/05-research-root" research-root || restored=0
      restore_acl_exact "$RESEARCH_STATE" "$acl_backup/06-research-state" research-state || restored=0
      restore_acl_exact "$RESEARCH_LOGS" "$acl_backup/07-research-logs" research-logs || restored=0
      restore_acl_exact "$EXECUTION" "$acl_backup/08-execution" execution || restored=0
      restore_acl_exact "$LEARNING" "$acl_backup/09-learning" learning || restored=0
      if [ "$restored" = 0 ]; then
        write_stop_marker restore-proof-failed || true
        /bin/echo "CRITICAL: ACL restore proof failed; backups retained at $acl_backup" >&2
        return
      fi
    fi
    /bin/rm -rf "$acl_backup"
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  reset_acl "$BASE" \
    'user:trading-executor allow search' \
    'user:trading-control allow search' \
    'user:trading-research allow search'
  reset_acl "$EXECUTOR_ROOT" \
    'user:trading-executor allow search' \
    'user:trading-control allow search'
  reset_acl "$EXECUTOR_STATE" \
    'user:trading-executor allow search' \
    'user:trading-control allow search'
  reset_acl "$EXECUTOR_LOGS" 'user:trading-executor allow search'
  reset_acl "$RESEARCH_ROOT" \
    'user:trading-executor allow search' \
    'user:trading-control allow search' \
    'user:trading-research allow search'
  reset_acl "$RESEARCH_STATE" \
    'user:trading-executor allow search' \
    'user:trading-control allow search' \
    'user:trading-research allow search'
  reset_acl "$RESEARCH_LOGS" 'user:trading-research allow search'

  reset_acl "$EXECUTION" \
    'user:trading-control allow list,search,add_file,add_subdirectory,readattr' \
    'user:trading-control allow read,write,readattr,file_inherit,only_inherit' \
    'user:trading-control allow delete,directory_inherit,only_inherit' \
    'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
  reset_acl "$LEARNING" \
    'user:trading-control allow list,search,add_file,add_subdirectory,readattr' \
    'user:trading-research allow list,search,add_file,add_subdirectory,readattr' \
    'user:trading-control allow read,write,readattr,file_inherit,only_inherit' \
    'user:trading-research allow read,write,readattr,file_inherit,only_inherit' \
    'user:trading-executor allow read,write,readattr,file_inherit,only_inherit' \
    'user:trading-control allow delete,directory_inherit,only_inherit' \
    'user:trading-research allow delete,directory_inherit,only_inherit'

  for path in "$EXECUTION" "$LEARNING"; do
    entries=$(acl_entries "$path")
    if /bin/echo "$entries" | /usr/bin/awk '/file_inherit/ && /delete/ {found=1} END {exit !found}'; then
      die "pre-init file inheritance contains delete: $path"
    fi
  done

  run_as trading-executor /usr/bin/touch "$exec_main"
  run_as trading-control /usr/bin/tee "$exec_main" </dev/null >/dev/null
  expect_denied 'research list executor volume' run_as trading-research /bin/ls "$EXECUTOR_ROOT"
  expect_denied 'research read execution main' run_as trading-research /bin/cat "$exec_main"
  expect_denied 'control unlink execution main' run_as trading-control /bin/rm "$exec_main"
  expect_denied 'control rename execution main' run_as trading-control /bin/mv "$exec_main" "${exec_main}.moved"
  run_as trading-control /usr/bin/touch "$exec_replacement"
  expect_denied 'control replace execution main' run_as trading-control /bin/mv -f "$exec_replacement" "$exec_main"
  run_as trading-control /usr/bin/touch "$exec_sidecar"
  expect_denied 'pre-init control sidecar delete' run_as trading-control /bin/rm "$exec_sidecar"
  run_as trading-control /bin/mkdir "$exec_snapshot"
  run_as trading-control /bin/rmdir "$exec_snapshot"

  for private in "$NONCE" "$DAILY_LOSS" "$SOCKET"; do
    expect_denied "control list $private" run_as trading-control /bin/ls "$private"
    expect_denied "research list $private" run_as trading-research /bin/ls "$private"
  done

  run_as trading-executor /usr/bin/touch "$learning_main"
  run_as trading-control /usr/bin/tee "$learning_main" </dev/null >/dev/null
  run_as trading-research /usr/bin/tee "$learning_main" </dev/null >/dev/null
  expect_denied 'control unlink learning main' run_as trading-control /bin/rm "$learning_main"
  expect_denied 'research unlink learning main' run_as trading-research /bin/rm "$learning_main"
  expect_denied 'control rename learning main' run_as trading-control /bin/mv "$learning_main" "${learning_main}.control-moved"
  expect_denied 'research rename learning main' run_as trading-research /bin/mv "$learning_main" "${learning_main}.research-moved"
  run_as trading-control /usr/bin/touch "$learning_control_replacement"
  run_as trading-research /usr/bin/touch "$learning_research_replacement"
  expect_denied 'control replace learning main' run_as trading-control /bin/mv -f "$learning_control_replacement" "$learning_main"
  expect_denied 'research replace learning main' run_as trading-research /bin/mv -f "$learning_research_replacement" "$learning_main"
  run_as trading-control /usr/bin/touch "$learning_control_sidecar"
  run_as trading-research /usr/bin/touch "$learning_research_sidecar"
  expect_denied 'pre-init control learning sidecar delete' run_as trading-control /bin/rm "$learning_control_sidecar"
  expect_denied 'pre-init research learning sidecar delete' run_as trading-research /bin/rm "$learning_research_sidecar"
  run_as trading-control /bin/mkdir "$learning_control_snapshot"
  run_as trading-research /bin/mkdir "$learning_research_snapshot"
  run_as trading-control /bin/rmdir "$learning_control_snapshot"
  run_as trading-research /bin/rmdir "$learning_research_snapshot"

  remove_probes
  for path in "$EXECUTION" "$NONCE" "$DAILY_LOSS" "$SOCKET" "$LEARNING" "$RESEARCH_PRIVATE"; do
    assert_empty "$path"
  done
  committed=1
  cleanup
  trap - EXIT HUP INT TERM
  /bin/echo 'PREINIT_ACL_COMPLETE final state parents remain empty; init was not run'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die "plan takes no arguments"
    plan
    ;;
  --apply-preinit)
    [ "$#" -eq 1 ] || die "--apply-preinit takes no additional arguments"
    apply_preinit
    ;;
  *)
    die "unknown phase; run with no arguments for the plan"
    ;;
esac
