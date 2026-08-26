#!/bin/sh
set -eu
umask 077

BASE=/var/db/trading-desk-volumes
EXECUTOR_ROOT=$BASE/executor
RESEARCH_ROOT=$BASE/research
EXECUTION=$EXECUTOR_ROOT/state/execution
NONCE=$EXECUTOR_ROOT/state/nonce
DAILY_LOSS=$EXECUTOR_ROOT/state/daily-loss
SOCKET=$EXECUTOR_ROOT/state/socket
LEARNING=$RESEARCH_ROOT/state/learning-shared
EXECUTION_MAIN=$EXECUTION/execution.sqlite3
NONCE_MAIN=$NONCE/nonce.sqlite3
DAILY_LOSS_MAIN=$DAILY_LOSS/daily-loss.sqlite3
STAGING_MAIN=$LEARNING/staging.sqlite3
LEARNING_MAIN=$LEARNING/learning.sqlite3

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no ACL or filesystem state changed'
  /bin/echo 'After a retained successful one-time init, add delete only to future-file inheritance.'
  /bin/echo 'Existing execution, staging, and learning mains are hash/ACL/inode checked before and after.'
  /bin/echo 'The literal --apply-postinit is single-use and refuses missing, partial, or wrong-owner state.'
  /bin/echo 'It never opens SQLite, changes a main-file ACL, reads a credential, installs a service, or calls a venue.'
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
  acl_backup=$RECOVERY_PARENT/postinit-v1
  [ ! -e "$acl_backup" ] || die "unfinished post-init ACL transaction requires root review: $acl_backup"
  /bin/mkdir -m 0700 "$acl_backup"
  /usr/sbin/chown root:wheel "$acl_backup"
}

write_stop_marker() {
  reason=$1
  temp=$(/usr/bin/mktemp /etc/trading-desk/.ACL-RECOVERY-REQUIRED.XXXXXX)
  {
    /bin/echo 'schema_version=1'
    /bin/echo 'phase=postinit'
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

assert_main() {
  path=$1
  owner_class=$2
  [ -f "$path" ] || die "missing initialized main database: $path"
  [ ! -L "$path" ] || die "main database symlink rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 451 ] || die "main database owner must be executor: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = 451 ] || die "main database group must be executor: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = 600 ] || die "main database mode must be 0600: $path"
  [ "$(/usr/bin/stat -f %l "$path")" = 1 ] || die "hard-linked main database rejected: $path"
  parent=$(/usr/bin/dirname "$path")
  [ "$(/usr/bin/stat -f %d "$path")" = "$(/usr/bin/stat -f %d "$parent")" ] || die "main database device differs from its reviewed parent: $path"
  entries=$(acl_entries "$path")
  if /bin/echo "$entries" | /usr/bin/grep -q ' allow .*delete'; then
    die "existing main database already has delete authority: $path"
  fi
  case "$owner_class" in
    executor-only)
      [ -z "$entries" ] || die "executor-only main has a named ACL: $path"
      ;;
    execution-shared)
      [ "$(/bin/echo "$entries" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 2 ] || die "execution main ACL count drift: $path"
      [ "$(/bin/echo "$entries" | /usr/bin/grep -c trading-control)" = 1 ] || die "execution main control ACL drift"
      [ "$(/bin/echo "$entries" | /usr/bin/grep -c trading-executor)" = 1 ] || die "execution main executor ACL drift"
      while IFS= read -r line; do
        case "$line" in
          *trading-control*" allow read,write,readattr"|*trading-executor*" allow read,write,readattr") ;;
          *) die "execution main ACE rights drift: $line" ;;
        esac
      done <<EOF
$entries
EOF
      ;;
    learning-shared)
      [ "$(/bin/echo "$entries" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 3 ] || die "learning main ACL count drift: $path"
      for identity in trading-control trading-executor trading-research; do
        [ "$(/bin/echo "$entries" | /usr/bin/grep -c "$identity")" = 1 ] || die "learning main ACL principal drift: $identity"
      done
      while IFS= read -r line; do
        case "$line" in
          *trading-control*" allow read,write,readattr"|*trading-executor*" allow read,write,readattr"|*trading-research*" allow read,write,readattr") ;;
          *) die "learning main ACE rights drift: $line" ;;
        esac
      done <<EOF
$entries
EOF
      ;;
    *) die "unknown main owner class" ;;
  esac
}

assert_state_dir() {
  path=$1
  [ -d "$path" ] || die "state parent missing: $path"
  [ ! -L "$path" ] || die "state parent symlink rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 451 ] || die "state parent owner drift: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = 451 ] || die "state parent group drift: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = 700 ] || die "state parent mode drift: $path"
}

assert_volume_marker() {
  root=$1
  role=$2
  quota=$3
  reserve=$4
  marker=$root/.trading-desk-volume-v1
  [ -f "$marker" ] || die "volume marker missing: $marker"
  [ ! -L "$marker" ] || die "volume marker symlink rejected: $marker"
  [ "$(/usr/bin/stat -f %u "$marker")" = 0 ] || die "volume marker owner drift: $marker"
  [ "$(/usr/bin/stat -f %Lp "$marker")" = 444 ] || die "volume marker mode drift: $marker"
  [ "$(/usr/bin/stat -f %l "$marker")" = 1 ] || die "volume marker hard link rejected: $marker"
  [ "$(/usr/bin/awk 'NF {count += 1} END {print count + 0}' "$marker")" = 7 ] || die "volume marker record count drift"
  [ "$(/usr/bin/awk -F= '$1 == "schema_version" {print $2}' "$marker")" = 1 ] || die "volume marker schema drift"
  [ "$(/usr/bin/awk -F= '$1 == "role" {print $2}' "$marker")" = "$role" ] || die "volume marker role drift"
  [ "$(/usr/bin/awk -F= '$1 == "quota_bytes" {print $2}' "$marker")" = "$quota" ] || die "volume marker quota drift"
  [ "$(/usr/bin/awk -F= '$1 == "reserve_bytes" {print $2}' "$marker")" = "$reserve" ] || die "volume marker reserve drift"
  uuid=$(/usr/bin/awk -F= '$1 == "volume_uuid" {print $2}' "$marker")
  container_uuid=$(/usr/bin/awk -F= '$1 == "apfs_container_uuid" {print $2}' "$marker")
  [ "$(/usr/bin/awk -F= '$1 == "filesystem_type" {print $2}' "$marker")" = apfs ] || die "volume marker filesystem drift"
  /bin/echo "$uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "volume marker UUID malformed"
  /bin/echo "$container_uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "volume marker container UUID malformed"
  [ "$(/usr/bin/stat -f %d "$root")" != "$(/usr/bin/stat -f %d "$BASE")" ] || die "volume is not mounted: $root"
  [ "$(/usr/bin/stat -f %d "$marker")" = "$(/usr/bin/stat -f %d "$root")" ] || die "volume marker device mismatch"
}

assert_exact_preinit_parent() {
  path=$1
  kind=$2
  actual=$(/usr/bin/mktemp /private/tmp/trading-desk-preinit-parent-actual.XXXXXX)
  expected=$(/usr/bin/mktemp /private/tmp/trading-desk-preinit-parent-expected.XXXXXX)
  acl_export "$path" > "$actual"
  case "$kind" in
    execution)
      {
        /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
        /bin/echo 'user:trading-control allow read,write,readattr,file_inherit,only_inherit'
        /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
        /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
      } > "$expected"
      ;;
    learning)
      {
        /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
        /bin/echo 'user:trading-research allow list,search,add_file,add_subdirectory,readattr'
        /bin/echo 'user:trading-control allow read,write,readattr,file_inherit,only_inherit'
        /bin/echo 'user:trading-research allow read,write,readattr,file_inherit,only_inherit'
        /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
        /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
        /bin/echo 'user:trading-research allow delete,directory_inherit,only_inherit'
      } > "$expected"
      ;;
    *) die "unknown parent ACL kind" ;;
  esac
  /usr/bin/cmp -s "$actual" "$expected" || die "pre-init parent ACL differs from the exact reviewed ACE set: $path"
  /bin/rm -f "$actual" "$expected"
}

assert_preinit_parent() {
  path=$1
  expected_count=$2
  entries=$(acl_entries "$path")
  count=$(/bin/echo "$entries" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" = "$expected_count" ] || die "pre-init ACL entry count drift: $path"
  /bin/echo "$entries" | /usr/bin/grep -q delete_child && die "delete_child present: $path"
  if /bin/echo "$entries" | /usr/bin/awk '/file_inherit/ && /delete/ {found=1} END {exit !found}'; then
    die "future-file delete is already enabled: $path"
  fi
}

assert_postinit_parent() {
  path=$1
  expected_count=$2
  expected_file_delete_count=$3
  entries=$(acl_entries "$path")
  count=$(/bin/echo "$entries" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  delete_count=$(/bin/echo "$entries" | /usr/bin/awk '/file_inherit/ && /delete/ {count += 1} END {print count + 0}')
  [ "$count" = "$expected_count" ] || die "post-init ACL entry count drift: $path"
  [ "$delete_count" = "$expected_file_delete_count" ] || die "post-init future-file delete count drift: $path"
  /bin/echo "$entries" | /usr/bin/grep -q delete_child && die "delete_child present after conversion: $path"
  while IFS= read -r line; do
    case "$line" in
      *trading-control*" allow "*|*trading-executor*" allow "*|*trading-research*" allow "*) ;;
      *) die "unexpected post-init ACL principal or deny entry: $line" ;;
    esac
  done <<EOF
$entries
EOF
}

snapshot_main_metadata() {
  output=$1
  shift
  : > "$output"
  for path in "$@"; do
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

expect_denied() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    die "unexpectedly allowed: $label"
  fi
  /bin/echo "DENIED_OK $label"
}

probe_main_like_denials() {
  source_main=$1
  probe=$2
  moved=$3
  control_replacement=$4
  research_replacement=$5
  label=$6
  research_enabled=$7
  acl_file=$probe_root/$label-main.acl
  acl_reread=$probe_root/$label-main-reread.acl

  # Never run destructive probes against an authoritative SQLite main. Create
  # an expendable executor-owned inode in the exact parent, replace its
  # inherited ACL with the source main's exact ACL, and probe that inode.
  run_as trading-executor /usr/bin/touch "$probe"
  /bin/chmod 0600 "$probe"
  acl_export "$source_main" > "$acl_file"
  /bin/chmod -E "$probe" < "$acl_file"
  acl_export "$probe" > "$acl_reread"
  /usr/bin/cmp -s "$acl_file" "$acl_reread" || die "main-like probe ACL differs: $label"
  [ "$(/usr/bin/stat -f %u "$probe")" = 451 ] || die "main-like probe owner drift: $label"
  [ "$(/usr/bin/stat -f %g "$probe")" = 451 ] || die "main-like probe group drift: $label"
  [ "$(/usr/bin/stat -f %Lp "$probe")" = 600 ] || die "main-like probe mode drift: $label"
  [ "$(/usr/bin/stat -f %l "$probe")" = 1 ] || die "main-like probe link drift: $label"

  expect_denied "control unlink $label main-like probe" run_as trading-control /bin/rm "$probe"
  expect_denied "control rename $label main-like probe" run_as trading-control /bin/mv "$probe" "$moved"
  run_as trading-control /usr/bin/touch "$control_replacement"
  expect_denied "control replace $label main-like probe" run_as trading-control /bin/mv -f "$control_replacement" "$probe"
  if [ "$research_enabled" = 1 ]; then
    expect_denied "research unlink $label main-like probe" run_as trading-research /bin/rm "$probe"
    expect_denied "research rename $label main-like probe" run_as trading-research /bin/mv "$probe" "$moved"
    run_as trading-research /usr/bin/touch "$research_replacement"
    expect_denied "research replace $label main-like probe" run_as trading-research /bin/mv -f "$research_replacement" "$probe"
  fi
  /bin/rm -f "$probe" "$moved" "$control_replacement" "$research_replacement"
}

apply_postinit() {
  assert_sealed_root
  assert_volume_marker "$EXECUTOR_ROOT" executor 17179869184 8589934592
  assert_volume_marker "$RESEARCH_ROOT" research 8589934592 0
  for path in "$EXECUTION" "$NONCE" "$DAILY_LOSS" "$SOCKET" "$LEARNING"; do
    assert_state_dir "$path"
  done
  [ "$(/usr/bin/stat -f %d "$EXECUTION")" = "$(/usr/bin/stat -f %d "$EXECUTOR_ROOT")" ] || die "execution parent device drift"
  [ "$(/usr/bin/stat -f %d "$LEARNING")" = "$(/usr/bin/stat -f %d "$RESEARCH_ROOT")" ] || die "learning parent device drift"
  assert_main "$EXECUTION_MAIN" execution-shared
  assert_main "$NONCE_MAIN" executor-only
  assert_main "$DAILY_LOSS_MAIN" executor-only
  assert_main "$STAGING_MAIN" learning-shared
  assert_main "$LEARNING_MAIN" learning-shared
  assert_preinit_parent "$EXECUTION" 4
  assert_preinit_parent "$LEARNING" 7
  assert_exact_preinit_parent "$EXECUTION" execution
  assert_exact_preinit_parent "$LEARNING" learning
  [ -z "$(acl_entries "$NONCE")" ] || die "nonce parent ACL drift"
  [ -z "$(acl_entries "$DAILY_LOSS")" ] || die "daily-loss parent ACL drift"
  [ -z "$(acl_entries "$SOCKET")" ] || die "socket parent ACL drift"

  receipt=/etc/trading-desk/postinit-acl-v1.receipt
  [ ! -e "$receipt" ] || die "post-init receipt already exists; conversion is single-use"

  prepare_recovery_dir
  before=$(/usr/bin/mktemp /private/tmp/trading-desk-main-before.XXXXXX)
  after=$(/usr/bin/mktemp /private/tmp/trading-desk-main-after.XXXXXX)
  execution_before_acl=$acl_backup/execution-before.acl
  learning_before_acl=$acl_backup/learning-before.acl
  execution_after_acl=$(/usr/bin/mktemp /private/tmp/trading-desk-execution-acl-after.XXXXXX)
  learning_after_acl=$(/usr/bin/mktemp /private/tmp/trading-desk-learning-acl-after.XXXXXX)
  probe_root=$(/usr/bin/mktemp -d /private/tmp/trading-desk-acl-candidate.XXXXXX)
  receipt_temp=''
  receipt_expected=$acl_backup/postinit-receipt.expected
  committed=0
  execution_probe=$EXECUTION/.postinit-main-probe-execution
  execution_probe_moved=$EXECUTION/.postinit-main-probe-execution-moved
  execution_control_replacement=$EXECUTION/.postinit-main-probe-execution-control-replacement
  execution_research_replacement=$EXECUTION/.postinit-main-probe-execution-research-replacement
  staging_probe=$LEARNING/.postinit-main-probe-staging
  staging_probe_moved=$LEARNING/.postinit-main-probe-staging-moved
  staging_control_replacement=$LEARNING/.postinit-main-probe-staging-control-replacement
  staging_research_replacement=$LEARNING/.postinit-main-probe-staging-research-replacement
  learning_probe=$LEARNING/.postinit-main-probe-learning
  learning_probe_moved=$LEARNING/.postinit-main-probe-learning-moved
  learning_control_replacement=$LEARNING/.postinit-main-probe-learning-control-replacement
  learning_research_replacement=$LEARNING/.postinit-main-probe-learning-research-replacement
  acl_export "$EXECUTION" > "$execution_before_acl"
  acl_export "$LEARNING" > "$learning_before_acl"
  /usr/sbin/chown root:wheel "$execution_before_acl" "$learning_before_acl"
  /bin/chmod 0400 "$execution_before_acl" "$learning_before_acl"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
  } > "$execution_after_acl"
  {
    /bin/echo 'user:trading-control allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-research allow list,search,add_file,add_subdirectory,readattr'
    /bin/echo 'user:trading-control allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-research allow read,write,delete,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-executor allow read,write,readattr,file_inherit,only_inherit'
    /bin/echo 'user:trading-control allow delete,directory_inherit,only_inherit'
    /bin/echo 'user:trading-research allow delete,directory_inherit,only_inherit'
  } > "$learning_after_acl"
  cleanup() {
    retain_backup=0
    safe_to_restore=1
    if [ "$committed" = 0 ]; then
      # A signal can arrive after the receipt rename but before the in-memory
      # commit flag changes. Remove only our exact receipt before rolling ACLs
      # back; otherwise retain all recovery evidence and stop for root review.
      if [ -e "$receipt" ] || [ -L "$receipt" ]; then
        if [ -f "$receipt" ] && [ ! -L "$receipt" ] && \
           [ "$(/usr/bin/stat -f %u "$receipt")" = 0 ] && \
           [ "$(/usr/bin/stat -f %g "$receipt")" = 0 ] && \
           [ "$(/usr/bin/stat -f %Lp "$receipt")" = 400 ] && \
           [ "$(/usr/bin/stat -f %l "$receipt")" = 1 ] && \
           [ -z "$(acl_entries "$receipt")" ] && \
           [ -f "$receipt_expected" ] && \
           /usr/bin/cmp -s "$receipt" "$receipt_expected"; then
          /bin/rm -f "$receipt" || safe_to_restore=0
        else
          safe_to_restore=0
        fi
      fi
      restored=1
      if [ "$safe_to_restore" = 1 ]; then
        restore_acl_exact "$EXECUTION" "$execution_before_acl" execution || restored=0
        restore_acl_exact "$LEARNING" "$learning_before_acl" learning || restored=0
      else
        restored=0
      fi
      if [ "$restored" = 0 ]; then
        write_stop_marker restore-proof-failed || true
        /bin/echo "CRITICAL: ACL restore proof failed; backups retained at $acl_backup" >&2
        retain_backup=1
      fi
    fi
    /bin/rm -f "$before" "$after" "$execution_after_acl" "$learning_after_acl" ${receipt_temp:+"$receipt_temp"} \
      "$EXECUTION/.postinit-executor-sidecar" "$EXECUTION/.postinit-control-sidecar" \
      "$EXECUTION/.postinit-replacement" \
      "$LEARNING/.postinit-executor-for-control" "$LEARNING/.postinit-executor-for-research" \
      "$LEARNING/.postinit-control-sidecar" "$LEARNING/.postinit-research-sidecar" \
      "$execution_probe" "$execution_probe_moved" \
      "$execution_control_replacement" "$execution_research_replacement" \
      "$staging_probe" "$staging_probe_moved" \
      "$staging_control_replacement" "$staging_research_replacement" \
      "$learning_probe" "$learning_probe_moved" \
      "$learning_control_replacement" "$learning_research_replacement"
    /bin/rm -rf "$probe_root"
    if [ "$retain_backup" = 0 ]; then
      /bin/rm -rf "$acl_backup"
    fi
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM
  snapshot_main_metadata "$before" "$EXECUTION_MAIN" "$NONCE_MAIN" "$DAILY_LOSS_MAIN" "$STAGING_MAIN" "$LEARNING_MAIN"

  /bin/mkdir -m 0700 "$probe_root/execution" "$probe_root/learning"
  /bin/chmod -E "$probe_root/execution" < "$execution_after_acl"
  /bin/chmod -E "$probe_root/learning" < "$learning_after_acl"
  /bin/chmod -C "$probe_root/execution" "$probe_root/learning" || die "candidate ACL is non-canonical"
  assert_postinit_parent "$probe_root/execution" 4 1
  assert_postinit_parent "$probe_root/learning" 7 2

  /bin/chmod -E "$EXECUTION" < "$execution_after_acl"
  /bin/chmod -E "$LEARNING" < "$learning_after_acl"
  /bin/chmod -C "$EXECUTION" "$LEARNING" || die "installed post-init ACL is non-canonical"
  assert_postinit_parent "$EXECUTION" 4 1
  assert_postinit_parent "$LEARNING" 7 2
  installed_acl=$(/usr/bin/mktemp /private/tmp/trading-desk-postinit-installed-acl.XXXXXX)
  acl_export "$EXECUTION" > "$installed_acl"
  /usr/bin/cmp -s "$installed_acl" "$execution_after_acl" || die "execution parent ACE set differs from the exact candidate"
  acl_export "$LEARNING" > "$installed_acl"
  /usr/bin/cmp -s "$installed_acl" "$learning_after_acl" || die "learning parent ACE set differs from the exact candidate"
  /bin/rm -f "$installed_acl"

  run_as trading-executor /usr/bin/touch "$EXECUTION/.postinit-executor-sidecar"
  run_as trading-control /bin/rm "$EXECUTION/.postinit-executor-sidecar"
  run_as trading-control /usr/bin/touch "$EXECUTION/.postinit-control-sidecar"
  run_as trading-executor /bin/rm "$EXECUTION/.postinit-control-sidecar"

  probe_main_like_denials "$EXECUTION_MAIN" "$execution_probe" \
    "$execution_probe_moved" "$execution_control_replacement" \
    "$execution_research_replacement" execution 0

  run_as trading-executor /usr/bin/touch "$LEARNING/.postinit-executor-for-control"
  run_as trading-control /bin/rm "$LEARNING/.postinit-executor-for-control"
  run_as trading-executor /usr/bin/touch "$LEARNING/.postinit-executor-for-research"
  run_as trading-research /bin/rm "$LEARNING/.postinit-executor-for-research"
  run_as trading-control /usr/bin/touch "$LEARNING/.postinit-control-sidecar"
  run_as trading-research /bin/rm "$LEARNING/.postinit-control-sidecar"
  run_as trading-research /usr/bin/touch "$LEARNING/.postinit-research-sidecar"
  run_as trading-control /bin/rm "$LEARNING/.postinit-research-sidecar"

  probe_main_like_denials "$STAGING_MAIN" "$staging_probe" \
    "$staging_probe_moved" "$staging_control_replacement" \
    "$staging_research_replacement" staging 1
  probe_main_like_denials "$LEARNING_MAIN" "$learning_probe" \
    "$learning_probe_moved" "$learning_control_replacement" \
    "$learning_research_replacement" learning 1

  assert_main "$EXECUTION_MAIN" execution-shared
  assert_main "$NONCE_MAIN" executor-only
  assert_main "$DAILY_LOSS_MAIN" executor-only
  assert_main "$STAGING_MAIN" learning-shared
  assert_main "$LEARNING_MAIN" learning-shared
  snapshot_main_metadata "$after" "$EXECUTION_MAIN" "$NONCE_MAIN" "$DAILY_LOSS_MAIN" "$STAGING_MAIN" "$LEARNING_MAIN"
  /usr/bin/cmp -s "$before" "$after" || die "a durable main inode, byte, mode, owner, link count, or ACL changed"

  {
    /bin/echo 'schema_version=1'
    /bin/echo 'future_file_delete_inheritance=enabled'
    /bin/echo 'parent_delete_child=forbidden'
    /bin/echo "main_evidence_sha256=$(/usr/bin/openssl dgst -sha256 "$after" | /usr/bin/awk '{print $2}')"
  } > "$receipt_expected"
  /usr/sbin/chown root:wheel "$receipt_expected"
  /bin/chmod 0400 "$receipt_expected"
  receipt_temp=$(/usr/bin/mktemp /etc/trading-desk/.postinit-acl-v1.receipt.XXXXXX)
  /bin/cp "$receipt_expected" "$receipt_temp"
  /usr/sbin/chown root:wheel "$receipt_temp"
  /bin/chmod 0400 "$receipt_temp"
  /usr/bin/cmp -s "$receipt_expected" "$receipt_temp" || die "post-init receipt staging drift"
  /bin/mv "$receipt_temp" "$receipt"
  receipt_temp=''
  committed=1
  cleanup
  trap - EXIT HUP INT TERM
  /bin/echo 'POSTINIT_ACL_COMPLETE existing main files were unchanged; only future files inherit delete'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die "plan takes no arguments"
    plan
    ;;
  --apply-postinit)
    [ "$#" -eq 1 ] || die "--apply-postinit takes no additional arguments"
    apply_postinit
    ;;
  *)
    die "unknown phase; run with no arguments for the plan"
    ;;
esac
