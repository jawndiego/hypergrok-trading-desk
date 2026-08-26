#!/bin/sh
set -eu
umask 077

EXECUTOR_NAME=TradingDeskExecutor
RESEARCH_NAME=TradingDeskResearch
BASE=/var/db/trading-desk-volumes
EXECUTOR_MOUNT=$BASE/executor
RESEARCH_MOUNT=$BASE/research
EXECUTOR_QUOTA=17179869184
EXECUTOR_RESERVE=8589934592
RESEARCH_QUOTA=8589934592
MIN_CONTAINER_FREE=34359738368
STATE=/etc/trading-desk/storage-provision-v1
FSTAB_BEGIN='# BEGIN TRADING-DESK-TESTNET-STORAGE-V1'
FSTAB_END='# END TRADING-DESK-TESTNET-STORAGE-V1'

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no machine state changed'
  /bin/echo "executor name=$EXECUTOR_NAME mount=$EXECUTOR_MOUNT quota=$EXECUTOR_QUOTA reserve=$EXECUTOR_RESERVE"
  /bin/echo "research name=$RESEARCH_NAME mount=$RESEARCH_MOUNT quota=$RESEARCH_QUOTA reserve=0"
  /bin/echo 'The creation phase supports only an explicitly accepted unencrypted TESTNET layout.'
  /bin/echo 'Encrypted volumes require a separately reviewed unattended-boot unlock design and are not created here.'
  /bin/echo 'Phases: --audit; --apply-create-unencrypted-testnet; --apply-adopt-mounted-unencrypted-testnet; --apply-persist EXPECTED_FSTAB_SHA256_OR_ABSENT; --apply-layout.'
  /bin/echo 'No phase deletes an APFS volume, initializes the harness, installs a service, reads a credential, or calls a venue.'
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

assert_root_file() {
  path=$1
  [ -f "$path" ] || die "not a regular file: $path"
  [ ! -L "$path" ] || die "symlink rejected: $path"
  [ "$(/bin/realpath "$path")" = "$path" ] || die "non-canonical file path rejected: $path"
  [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "file is not root-owned: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = 0 ] || die "file group is not wheel: $path"
  [ "$(/usr/bin/stat -f %l "$path")" = 1 ] || die "hard-linked file rejected: $path"
  exposed=$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$exposed" ] || die "group/world-writable file rejected: $path"
  [ -z "$(/bin/ls -led "$path" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')" ] || die "named ACL rejected: $path"
}

info_file=''
candidate_file=''
cleanup() {
  if [ -n "$info_file" ]; then
    /bin/rm -f "$info_file"
  fi
  if [ -n "$candidate_file" ]; then
    /bin/rm -f "$candidate_file"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

disk_value() {
  path=$1
  key=$2
  if [ -z "$info_file" ]; then
    info_file=$(/usr/bin/mktemp /private/tmp/trading-desk-disk-info.XXXXXX)
  fi
  /usr/sbin/diskutil info -plist "$path" > "$info_file" || die "diskutil info failed: $path"
  /usr/bin/plutil -extract "$key" raw -o - "$info_file" 2>/dev/null || die "missing disk property $key for $path"
}

assert_volume() {
  path=$1
  expected_name=$2
  expected_quota=$3
  expected_reserve=$4
  expected_uuid=${5-}
  expected_container=${6-}
  expected_container_uuid=${7-}
  [ -d "$path" ] || die "missing volume mount: $path"
  [ ! -L "$path" ] || die "volume mount symlink rejected: $path"
  name=$(disk_value "$path" VolumeName)
  [ "$name" = "$expected_name" ] || die "volume-name mismatch at $path"
  filesystem=$(disk_value "$path" FilesystemType)
  [ "$filesystem" = apfs ] || die "non-APFS volume at $path"
  quota=$(disk_value "$path" APFSQuotaSize)
  reserve=$(disk_value "$path" APFSReserveSize)
  encrypted=$(disk_value "$path" Encrypted)
  uuid=$(disk_value "$path" VolumeUUID)
  actual_container=$(disk_value "$path" APFSContainerReference)
  actual_container_uuid=$(disk_value "$path" APFSContainerUUID)
  mountpoint=$(disk_value "$path" MountPoint)
  [ "$quota" = "$expected_quota" ] || die "quota mismatch at $path"
  [ "$reserve" = "$expected_reserve" ] || die "reserve mismatch at $path"
  [ "$encrypted" = false ] || die "this credential-free path accepts only the reviewed unencrypted TESTNET choice"
  [ "$mountpoint" = "$path" ] || die "mountpoint mismatch at $path"
  /bin/echo "$uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "invalid volume UUID"
  if [ -n "$expected_uuid" ]; then
    [ "$uuid" = "$expected_uuid" ] || die "volume UUID mismatch at $path"
  fi
  if [ -n "$expected_container" ]; then
    [ "$actual_container" = "$expected_container" ] || die "APFS container identity mismatch at $path"
  fi
  if [ -n "$expected_container_uuid" ]; then
    [ "$actual_container_uuid" = "$expected_container_uuid" ] || die "APFS stable container UUID mismatch at $path"
  fi
  /bin/echo "$uuid"
}

state_value() {
  key=$1
  [ -f "$STATE" ] || return 0
  assert_root_file "$STATE"
  count=$(/usr/bin/awk -F= -v key="$key" '$1 == key {count += 1} END {print count + 0}' "$STATE")
  [ "$count" -le 1 ] || die "duplicate state key: $key"
  /usr/bin/awk -F= -v key="$key" '$1 == key {print substr($0, length(key) + 2)}' "$STATE"
}

write_state() {
  recorded_container=$1
  recorded_container_uuid=$2
  executor_uuid=$3
  research_uuid=$4
  persisted=$5
  layout=$6
  temp=$(/usr/bin/mktemp /etc/trading-desk/.storage-provision-v1.XXXXXX)
  {
    /bin/echo 'schema_version=1'
    /bin/echo 'encryption=unencrypted-testnet-explicitly-accepted'
    /bin/echo "container_reference=$recorded_container"
    /bin/echo "apfs_container_uuid=$recorded_container_uuid"
    /bin/echo "executor_uuid=$executor_uuid"
    /bin/echo "research_uuid=$research_uuid"
    /bin/echo "fstab_persisted=$persisted"
    /bin/echo "layout_created=$layout"
  } > "$temp"
  /usr/sbin/chown root:wheel "$temp"
  /bin/chmod 0600 "$temp"
  /bin/mv -f "$temp" "$STATE"
}

load_state() {
  if [ -e "$STATE" ]; then
    assert_root_file "$STATE"
    line_count=$(/usr/bin/awk 'NF {count += 1} END {print count + 0}' "$STATE")
    [ "$line_count" = 8 ] || die "storage state must contain exactly eight records"
    [ "$(state_value schema_version)" = 1 ] || die "storage state schema mismatch"
    [ "$(state_value encryption)" = unencrypted-testnet-explicitly-accepted ] || die "storage encryption decision drift"
  fi
  recorded_container=$(state_value container_reference)
  recorded_container_uuid=$(state_value apfs_container_uuid)
  executor_uuid=$(state_value executor_uuid)
  research_uuid=$(state_value research_uuid)
  persisted=$(state_value fstab_persisted)
  layout=$(state_value layout_created)
  persisted=${persisted:-0}
  layout=${layout:-0}
  case "$persisted:$layout" in
    0:0|1:0|1:1) ;;
    *) die "invalid persisted/layout state transition" ;;
  esac
  for uuid in "$executor_uuid" "$research_uuid"; do
    if [ -n "$uuid" ]; then
      /bin/echo "$uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "recorded volume UUID malformed"
    fi
  done
  if [ -n "$recorded_container" ]; then
    /bin/echo "$recorded_container" | /usr/bin/grep -Eq '^disk[0-9]+$' || die "recorded APFS container reference malformed"
  fi
  if [ -n "$recorded_container_uuid" ]; then
    /bin/echo "$recorded_container_uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "recorded APFS container UUID malformed"
  fi
}

prepare_mountpoints() {
  [ -d /etc/trading-desk ] || die "missing /etc/trading-desk"
  [ ! -L /etc/trading-desk ] || die "/etc/trading-desk symlink rejected"
  [ "$(/usr/bin/stat -f %u /etc/trading-desk)" = 0 ] || die "/etc/trading-desk must be root-owned"
  if [ ! -e "$BASE" ]; then
    /bin/mkdir -m 0700 "$BASE"
    /usr/sbin/chown root:wheel "$BASE"
  fi
  [ -d "$BASE" ] || die "storage base is not a directory"
  [ ! -L "$BASE" ] || die "storage base symlink rejected"
  for path in "$EXECUTOR_MOUNT" "$RESEARCH_MOUNT"
  do
    if [ ! -e "$path" ]; then
      /bin/mkdir -m 0700 "$path"
      /usr/sbin/chown root:wheel "$path"
    fi
    [ -d "$path" ] || die "mountpoint is not a directory: $path"
    [ ! -L "$path" ] || die "mountpoint symlink rejected: $path"
  done
}

discover_container() {
  container=$(disk_value /var/db/trading-desk APFSContainerReference)
  /bin/echo "$container" | /usr/bin/grep -Eq '^disk[0-9]+$' || die "unexpected APFS container reference"
  container_uuid=$(disk_value /var/db/trading-desk APFSContainerUUID)
  /bin/echo "$container_uuid" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' || die "unexpected APFS container UUID"
  free=$(disk_value /var/db/trading-desk APFSContainerFree)
  /bin/echo "$free" | /usr/bin/grep -Eq '^[0-9]+$' || die "invalid APFS container free value"
  [ "$free" -ge "$MIN_CONTAINER_FREE" ] || die "APFS container has less than the reviewed 32 GiB preflight headroom"
}

audit() {
  plan
  /bin/echo 'AUDIT_ONLY'
  if [ -e "$STATE" ]; then
    assert_root_file "$STATE"
    /bin/cat "$STATE"
  else
    /bin/echo "MISSING $STATE"
  fi
  for path in "$EXECUTOR_MOUNT" "$RESEARCH_MOUNT"
  do
    if [ -e "$path" ]; then
      /usr/bin/stat -f '%N|type=%HT|owner=%Su(%u)|group=%Sg(%g)|mode=%Sp|links=%l|device=%d' "$path"
      /bin/ls -ldeO@ "$path"
      /bin/df -k "$path" || true
    else
      /bin/echo "MISSING $path"
    fi
  done
  if [ -e /etc/fstab ]; then
    assert_root_file /etc/fstab
    /bin/echo "fstab_sha256=$(/usr/bin/openssl dgst -sha256 /etc/fstab | /usr/bin/awk '{print $2}')"
  else
    /bin/echo 'fstab=ABSENT'
  fi
  /bin/echo 'AUDIT_COMPLETE no state changed'
}

create_volumes() {
  assert_sealed_root
  prepare_mountpoints
  discover_container
  load_state
  # diskN references are volatile across reboot; retain them only as the last
  # observation while binding identity to the stable APFS container UUID.
  recorded_container=$container
  if [ -n "$recorded_container_uuid" ]; then
    [ "$recorded_container_uuid" = "$container_uuid" ] || die "recorded APFS container UUID differs from the active data container"
  else
    recorded_container_uuid=$container_uuid
  fi
  [ "$persisted" = 0 ] || die "creation phase refused after fstab persistence"
  [ "$layout" = 0 ] || die "creation phase refused after layout creation"

  if [ -z "$executor_uuid" ]; then
    base_device=$(/usr/bin/stat -f %d "$BASE")
    mount_device=$(/usr/bin/stat -f %d "$EXECUTOR_MOUNT")
    [ "$base_device" = "$mount_device" ] || die "unrecorded executor volume is already mounted; use the explicit adoption phase"
    /usr/sbin/diskutil apfs addVolume "$container" APFS "$EXECUTOR_NAME" \
      -reserve "$EXECUTOR_RESERVE" -quota "$EXECUTOR_QUOTA" -mountpoint "$EXECUTOR_MOUNT"
    executor_uuid=$(assert_volume "$EXECUTOR_MOUNT" "$EXECUTOR_NAME" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE" '' "$recorded_container" "$recorded_container_uuid")
    write_state "$recorded_container" "$recorded_container_uuid" "$executor_uuid" '' 0 0
  else
    assert_volume "$EXECUTOR_MOUNT" "$EXECUTOR_NAME" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE" "$executor_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null
  fi

  if [ -z "$research_uuid" ]; then
    base_device=$(/usr/bin/stat -f %d "$BASE")
    mount_device=$(/usr/bin/stat -f %d "$RESEARCH_MOUNT")
    [ "$base_device" = "$mount_device" ] || die "unrecorded research volume is already mounted; use the explicit adoption phase"
    /usr/sbin/diskutil apfs addVolume "$container" APFS "$RESEARCH_NAME" \
      -quota "$RESEARCH_QUOTA" -mountpoint "$RESEARCH_MOUNT"
    research_uuid=$(assert_volume "$RESEARCH_MOUNT" "$RESEARCH_NAME" "$RESEARCH_QUOTA" 0 '' "$recorded_container" "$recorded_container_uuid")
    write_state "$recorded_container" "$recorded_container_uuid" "$executor_uuid" "$research_uuid" 0 0
  else
    assert_volume "$RESEARCH_MOUNT" "$RESEARCH_NAME" "$RESEARCH_QUOTA" 0 "$research_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null
  fi
  /bin/echo 'APFS_CREATE_COMPLETE no fstab, ACL, harness state, service, or credential was changed'
}

adopt_mounted() {
  assert_sealed_root
  prepare_mountpoints
  discover_container
  load_state
  [ "$persisted" = 0 ] || die "adoption refused after fstab persistence"
  [ "$layout" = 0 ] || die "adoption refused after layout creation"
  recorded_container=$container
  if [ -n "$recorded_container_uuid" ]; then
    [ "$recorded_container_uuid" = "$container_uuid" ] || die "recorded APFS container UUID differs from the active data container"
  else
    recorded_container_uuid=$container_uuid
  fi
  adopted_executor=$(assert_volume "$EXECUTOR_MOUNT" "$EXECUTOR_NAME" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE" "$executor_uuid" "$recorded_container" "$recorded_container_uuid")
  adopted_research=$(assert_volume "$RESEARCH_MOUNT" "$RESEARCH_NAME" "$RESEARCH_QUOTA" 0 "$research_uuid" "$recorded_container" "$recorded_container_uuid")
  write_state "$recorded_container" "$recorded_container_uuid" "$adopted_executor" "$adopted_research" 0 0
  /bin/echo 'APFS_ADOPTION_COMPLETE mounted volumes matched every reviewed public property'
}

persist_mounts() {
  expected=${1-}
  [ -n "$expected" ] || die "supply the exact current fstab SHA-256 or ABSENT"
  assert_sealed_root
  discover_container
  load_state
  [ -n "$executor_uuid" ] || die "executor volume is not recorded"
  [ -n "$research_uuid" ] || die "research volume is not recorded"
  recorded_container=$container
  [ "$recorded_container_uuid" = "$container_uuid" ] || die "recorded APFS container UUID differs from the active data container"
  assert_volume "$EXECUTOR_MOUNT" "$EXECUTOR_NAME" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE" "$executor_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null
  assert_volume "$RESEARCH_MOUNT" "$RESEARCH_NAME" "$RESEARCH_QUOTA" 0 "$research_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null

  editor=$(/usr/bin/dirname "$(/bin/realpath "$0")")/fstab-editor.sh
  assert_root_file "$editor"
  [ -x "$editor" ] || die "fstab editor is not executable"

  if [ -e /etc/fstab ]; then
    assert_root_file /etc/fstab
    actual=$(/usr/bin/openssl dgst -sha256 /etc/fstab | /usr/bin/awk '{print $2}')
    [ "$actual" = "$expected" ] || die "fstab SHA-256 differs from the attended value"
  else
    [ "$expected" = ABSENT ] || die "fstab is absent but the attended value was not ABSENT"
    actual=$(/usr/bin/openssl dgst -sha256 /dev/null | /usr/bin/awk '{print $2}')
  fi

  exact_executor="UUID=$executor_uuid $EXECUTOR_MOUNT apfs rw,nodev,nosuid,noexec,nobrowse,nofollow 0 0"
  exact_research="UUID=$research_uuid $RESEARCH_MOUNT apfs rw,nodev,nosuid,noexec,nobrowse,nofollow 0 0"
  if [ -e /etc/fstab ] && /usr/bin/grep -Fqx "$FSTAB_BEGIN" /etc/fstab; then
    [ "$(/usr/bin/grep -Fxc "$FSTAB_BEGIN" /etc/fstab)" = 1 ] || die "duplicate fstab begin marker"
    [ "$(/usr/bin/grep -Fxc "$FSTAB_END" /etc/fstab)" = 1 ] || die "fstab end marker mismatch"
    /usr/bin/grep -Fqx "$exact_executor" /etc/fstab || die "persisted executor entry drift"
    /usr/bin/grep -Fqx "$exact_research" /etc/fstab || die "persisted research entry drift"
    write_state "$recorded_container" "$recorded_container_uuid" "$executor_uuid" "$research_uuid" 1 "$layout"
    /bin/echo 'FSTAB_ALREADY_EXACT no state changed except the idempotent receipt'
    return
  fi
  if [ -e /etc/fstab ]; then
    /usr/bin/grep -F "$EXECUTOR_MOUNT" /etc/fstab >/dev/null && die "existing fstab already mentions executor mount"
    /usr/bin/grep -F "$RESEARCH_MOUNT" /etc/fstab >/dev/null && die "existing fstab already mentions research mount"
    /usr/bin/grep -F "$executor_uuid" /etc/fstab >/dev/null && die "existing fstab already mentions executor UUID"
    /usr/bin/grep -F "$research_uuid" /etc/fstab >/dev/null && die "existing fstab already mentions research UUID"
  fi

  candidate_file=$(/usr/bin/mktemp /private/tmp/trading-desk-fstab.XXXXXX)
  if [ -e /etc/fstab ]; then
    backup=/etc/trading-desk/fstab.before-$actual
    if [ -e "$backup" ]; then
      assert_root_file "$backup"
      [ "$(/usr/bin/openssl dgst -sha256 "$backup" | /usr/bin/awk '{print $2}')" = "$actual" ] || die "existing fstab backup digest mismatch"
    else
      /bin/cp /etc/fstab "$backup"
      /usr/sbin/chown root:wheel "$backup"
      /bin/chmod 0400 "$backup"
    fi
    /bin/cp /etc/fstab "$candidate_file"
    byte_count=$(/usr/bin/stat -f %z "$candidate_file")
    if [ "$byte_count" -gt 0 ]; then
      final_byte=$(/usr/bin/tail -c 1 "$candidate_file" | /usr/bin/od -An -tu1 | /usr/bin/tr -d ' ')
      [ "$final_byte" = 10 ] || /bin/echo >> "$candidate_file"
    fi
  else
    backup=/etc/trading-desk/fstab.before-ABSENT
    if [ -e "$backup" ]; then
      assert_root_file "$backup"
      [ "$(/bin/cat "$backup")" = ABSENT ] || die "fstab absence receipt drift"
    else
      /bin/echo ABSENT > "$backup"
      /usr/sbin/chown root:wheel "$backup"
      /bin/chmod 0400 "$backup"
    fi
  fi
  {
    /bin/echo "$FSTAB_BEGIN"
    /bin/echo "$exact_executor"
    /bin/echo "$exact_research"
    /bin/echo "$FSTAB_END"
  } >> "$candidate_file"
  /usr/sbin/chown root:wheel "$candidate_file"
  /bin/chmod 0600 "$candidate_file"
  wanted=$(/usr/bin/openssl dgst -sha256 "$candidate_file" | /usr/bin/awk '{print $2}')

  TRADING_DESK_FSTAB_CANDIDATE=$candidate_file \
  TRADING_DESK_FSTAB_EXPECTED_SHA256=$actual \
  EDITOR=$editor /usr/sbin/vifs

  assert_root_file /etc/fstab
  installed=$(/usr/bin/openssl dgst -sha256 /etc/fstab | /usr/bin/awk '{print $2}')
  [ "$installed" = "$wanted" ] || die "installed fstab differs from the locked candidate"
  /usr/sbin/chown root:wheel /etc/fstab
  /bin/chmod 0644 /etc/fstab
  write_state "$recorded_container" "$recorded_container_uuid" "$executor_uuid" "$research_uuid" 1 "$layout"
  /bin/echo "FSTAB_PERSIST_COMPLETE sha256=$installed"
  /bin/echo 'Reboot persistence is not qualified until a later reboot audit proves both UUID mounts.'
}

assert_mount_flags() {
  path=$1
  line=$(/sbin/mount | /usr/bin/grep -F " on $path " || true)
  [ -n "$line" ] || die "mount table lacks the expected volume: $path"
  [ "$(/bin/echo "$line" | /usr/bin/awk 'END {print NR + 0}')" = 1 ] || die "ambiguous mount table entry: $path"
  /bin/echo "$line" | /usr/bin/grep -q '(apfs,' || die "active mount is not APFS: $path"
  for option in nodev nosuid noexec nobrowse; do
    /bin/echo "$line" | /usr/bin/grep -Eq "[(, ]$option([, )])" || die "active mount lacks $option; reboot through the reviewed fstab before layout"
  done
}

acl_entries() {
  /bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p'
}

ensure_layout_dir() {
  path=$1
  expected_uid=$2
  expected_gid=$3
  if [ ! -e "$path" ]; then
    /bin/mkdir -m 0700 "$path"
  fi
  [ -d "$path" ] || die "layout path is not a directory: $path"
  [ ! -L "$path" ] || die "layout symlink rejected: $path"
  current_uid=$(/usr/bin/stat -f %u "$path")
  case "$current_uid" in
    0|"$expected_uid") ;;
    *) die "partial layout path has an unreviewed owner: $path" ;;
  esac
  [ -z "$(acl_entries "$path")" ] || die "partial layout path has a named ACL: $path"
  /usr/sbin/chown "$expected_uid:$expected_gid" "$path"
  /bin/chmod 0700 "$path"
  [ "$(/usr/bin/stat -f %u "$path")" = "$expected_uid" ] || die "layout owner mismatch: $path"
  [ "$(/usr/bin/stat -f %g "$path")" = "$expected_gid" ] || die "layout group mismatch: $path"
  [ "$(/usr/bin/stat -f %Lp "$path")" = 700 ] || die "layout mode mismatch: $path"
}

ensure_empty_layout_dir() {
  path=$1
  expected_uid=$2
  expected_gid=$3
  if [ -e "$path" ]; then
    [ -d "$path" ] || die "partial leaf is not a directory: $path"
    [ ! -L "$path" ] || die "partial leaf symlink rejected: $path"
    first=$(/usr/bin/find "$path" -mindepth 1 -maxdepth 1 -print -quit)
    [ -z "$first" ] || die "partial layout leaf is not exactly empty: $first"
  fi
  ensure_layout_dir "$path" "$expected_uid" "$expected_gid"
}

assert_child_subset() {
  parent=$1
  shift
  for child in "$parent"/* "$parent"/.[!.]* "$parent"/..?*; do
    [ -e "$child" ] || [ -L "$child" ] || continue
    name=${child##*/}
    allowed=0
    for expected in "$@"; do
      if [ "$name" = "$expected" ]; then
        allowed=1
      fi
    done
    [ "$allowed" = 1 ] || die "unexpected partial-layout entry: $child"
  done
}

layout_evidence() {
  output=$1
  shift
  : > "$output"
  for path in "$@"; do
    [ -d "$path" ] || die "layout evidence path is missing: $path"
    [ ! -L "$path" ] || die "layout evidence symlink rejected: $path"
    [ -z "$(acl_entries "$path")" ] || die "layout evidence ACL drift: $path"
    case "$path" in
      "$EXECUTOR_MOUNT"|"$EXECUTOR_MOUNT"/*) expected_device=$(/usr/bin/stat -f %d "$EXECUTOR_MOUNT") ;;
      "$RESEARCH_MOUNT"|"$RESEARCH_MOUNT"/*) expected_device=$(/usr/bin/stat -f %d "$RESEARCH_MOUNT") ;;
      *) die "layout evidence path escapes reviewed volumes: $path" ;;
    esac
    [ "$(/usr/bin/stat -f %d "$path")" = "$expected_device" ] || die "layout path crosses filesystem boundary: $path"
    /usr/bin/stat -f '%N|type=%HT|owner=%u|group=%g|mode=%Lp' "$path" >> "$output"
  done
}

record_layout_step() {
  step=$1
  evidence=$2
  receipt=$LAYOUT_RECEIPTS/$step
  pending=$LAYOUT_RECEIPTS/.${step}.pending
  evidence_sha=$(/usr/bin/openssl dgst -sha256 "$evidence" | /usr/bin/awk '{print $2}')
  expected=$(/usr/bin/mktemp /private/tmp/trading-desk-layout-receipt.XXXXXX)
  {
    /bin/echo 'schema_version=1'
    /bin/echo "step=$step"
    /bin/echo "apfs_container_uuid=$recorded_container_uuid"
    /bin/echo "executor_uuid=$executor_uuid"
    /bin/echo "research_uuid=$research_uuid"
    /bin/echo "evidence_sha256=$evidence_sha"
  } > "$expected"
  if [ -e "$receipt" ]; then
    assert_root_file "$receipt"
    /usr/bin/cmp -s "$expected" "$receipt" || die "layout step receipt differs from current exact evidence: $step"
  else
    if [ -e "$pending" ]; then
      assert_root_file "$pending"
      /usr/bin/cmp -s "$expected" "$pending" || die "partial layout receipt is not exactly adoptable: $pending"
    else
      /bin/cp "$expected" "$pending"
      /usr/sbin/chown root:wheel "$pending"
      /bin/chmod 0400 "$pending"
    fi
    /bin/mv "$pending" "$receipt"
  fi
  /bin/rm -f "$expected"
}

install_or_adopt_marker() {
  root=$1
  role=$2
  uuid=$3
  quota=$4
  reserve=$5
  marker=$root/.trading-desk-volume-v1
  pending=$root/.trading-desk-volume-v1.pending
  expected=$(/usr/bin/mktemp /private/tmp/trading-desk-volume-marker.XXXXXX)
  {
    /bin/echo 'schema_version=1'
    /bin/echo "role=$role"
    /bin/echo "apfs_container_uuid=$recorded_container_uuid"
    /bin/echo 'filesystem_type=apfs'
    /bin/echo "volume_uuid=$uuid"
    /bin/echo "quota_bytes=$quota"
    /bin/echo "reserve_bytes=$reserve"
  } > "$expected"
  if [ -e "$marker" ]; then
    assert_root_file "$marker"
    [ "$(/usr/bin/stat -f %Lp "$marker")" = 444 ] || die "volume marker mode drift: $marker"
    /usr/bin/cmp -s "$expected" "$marker" || die "volume marker content drift: $marker"
  else
    if [ -e "$pending" ]; then
      assert_root_file "$pending"
      /usr/bin/cmp -s "$expected" "$pending" || die "partial marker is not exactly adoptable: $pending"
    else
      /bin/cp "$expected" "$pending"
      /usr/sbin/chown root:wheel "$pending"
    fi
    # The inode must already have its final mode before the atomic rename. A
    # crash after rename therefore leaves an exactly adoptable final marker.
    /bin/chmod 0444 "$pending"
    /bin/mv "$pending" "$marker"
    [ "$(/usr/bin/stat -f %Lp "$marker")" = 444 ] || die "installed marker mode drift: $marker"
  fi
  /bin/rm -f "$expected"
}

assert_exact_children() {
  parent=$1
  shift
  actual=$(/usr/bin/mktemp /private/tmp/trading-desk-layout-actual.XXXXXX)
  expected=$(/usr/bin/mktemp /private/tmp/trading-desk-layout-expected.XXXXXX)
  /usr/bin/find "$parent" -mindepth 1 -maxdepth 1 -print | /usr/bin/sed 's#^.*/##' | LC_ALL=C /usr/bin/sort > "$actual"
  for name in "$@"; do
    /bin/echo "$name"
  done | LC_ALL=C /usr/bin/sort > "$expected"
  /usr/bin/cmp -s "$actual" "$expected" || die "layout child inventory drift: $parent"
  /bin/rm -f "$actual" "$expected"
}

create_layout() {
  assert_sealed_root
  discover_container
  load_state
  [ "$persisted" = 1 ] || die "fstab persistence must be complete before layout creation"
  recorded_container=$container
  [ "$recorded_container_uuid" = "$container_uuid" ] || die "recorded APFS container UUID differs from the active data container"
  assert_volume "$EXECUTOR_MOUNT" "$EXECUTOR_NAME" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE" "$executor_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null
  assert_volume "$RESEARCH_MOUNT" "$RESEARCH_NAME" "$RESEARCH_QUOTA" 0 "$research_uuid" "$recorded_container" "$recorded_container_uuid" >/dev/null
  assert_mount_flags "$EXECUTOR_MOUNT"
  assert_mount_flags "$RESEARCH_MOUNT"
  if [ "$layout" = 1 ]; then
    /bin/echo 'LAYOUT_ALREADY_COMPLETE exact receipts and layout will be reverified'
  fi

  LAYOUT_RECEIPTS=/etc/trading-desk/storage-layout-v1.d
  if [ ! -e "$LAYOUT_RECEIPTS" ]; then
    /bin/mkdir -m 0700 "$LAYOUT_RECEIPTS"
    /usr/sbin/chown root:wheel "$LAYOUT_RECEIPTS"
  fi
  [ -d "$LAYOUT_RECEIPTS" ] || die "layout receipt path is not a directory"
  [ ! -L "$LAYOUT_RECEIPTS" ] || die "layout receipt symlink rejected"
  [ "$(/usr/bin/stat -f %u "$LAYOUT_RECEIPTS")" = 0 ] || die "layout receipts must be root-owned"
  [ "$(/usr/bin/stat -f %Lp "$LAYOUT_RECEIPTS")" = 700 ] || die "layout receipt mode must be 0700"
  [ -z "$(acl_entries "$LAYOUT_RECEIPTS")" ] || die "layout receipts must not have a named ACL"
  assert_child_subset "$LAYOUT_RECEIPTS" \
    01-volume-parents .01-volume-parents.pending \
    02-executor-children .02-executor-children.pending \
    03-research-children .03-research-children.pending \
    04-volume-markers .04-volume-markers.pending \
    05-complete .05-complete.pending

  # APFS may maintain root-owned volume metadata at the mount root. Exact
  # adoption applies to the harness-owned state/log/tmp subtrees and marker;
  # those APFS-maintained siblings are neither traversed nor normalized here.
  ensure_layout_dir "$EXECUTOR_MOUNT" 0 0
  ensure_layout_dir "$EXECUTOR_MOUNT/state" 0 0
  ensure_layout_dir "$EXECUTOR_MOUNT/logs" 0 0
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/tmp" 451 451
  ensure_layout_dir "$RESEARCH_MOUNT" 0 0
  ensure_layout_dir "$RESEARCH_MOUNT/state" 0 0
  ensure_layout_dir "$RESEARCH_MOUNT/logs" 0 0
  ensure_empty_layout_dir "$RESEARCH_MOUNT/tmp" 450 450
  step_evidence=$(/usr/bin/mktemp /private/tmp/trading-desk-layout-evidence.XXXXXX)
  layout_evidence "$step_evidence" "$EXECUTOR_MOUNT" "$EXECUTOR_MOUNT/state" "$EXECUTOR_MOUNT/logs" "$EXECUTOR_MOUNT/tmp" "$RESEARCH_MOUNT" "$RESEARCH_MOUNT/state" "$RESEARCH_MOUNT/logs" "$RESEARCH_MOUNT/tmp"
  record_layout_step 01-volume-parents "$step_evidence"

  assert_child_subset "$EXECUTOR_MOUNT/state" execution nonce daily-loss socket
  assert_child_subset "$EXECUTOR_MOUNT/logs" executor
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/state/execution" 451 451
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/state/nonce" 451 451
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/state/daily-loss" 451 451
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/state/socket" 451 451
  ensure_empty_layout_dir "$EXECUTOR_MOUNT/logs/executor" 451 451
  assert_exact_children "$EXECUTOR_MOUNT/state/execution"
  assert_exact_children "$EXECUTOR_MOUNT/state/nonce"
  assert_exact_children "$EXECUTOR_MOUNT/state/daily-loss"
  assert_exact_children "$EXECUTOR_MOUNT/state/socket"
  assert_exact_children "$EXECUTOR_MOUNT/logs/executor"
  layout_evidence "$step_evidence" "$EXECUTOR_MOUNT/state/execution" "$EXECUTOR_MOUNT/state/nonce" "$EXECUTOR_MOUNT/state/daily-loss" "$EXECUTOR_MOUNT/state/socket" "$EXECUTOR_MOUNT/logs/executor"
  record_layout_step 02-executor-children "$step_evidence"

  assert_child_subset "$RESEARCH_MOUNT/state" learning-shared research-private
  assert_child_subset "$RESEARCH_MOUNT/logs" research learning-mcp
  ensure_empty_layout_dir "$RESEARCH_MOUNT/state/learning-shared" 451 451
  ensure_empty_layout_dir "$RESEARCH_MOUNT/state/research-private" 450 450
  ensure_empty_layout_dir "$RESEARCH_MOUNT/logs/research" 450 450
  ensure_empty_layout_dir "$RESEARCH_MOUNT/logs/learning-mcp" 450 450
  assert_exact_children "$RESEARCH_MOUNT/state/learning-shared"
  assert_exact_children "$RESEARCH_MOUNT/state/research-private"
  assert_exact_children "$RESEARCH_MOUNT/logs/research"
  assert_exact_children "$RESEARCH_MOUNT/logs/learning-mcp"
  layout_evidence "$step_evidence" "$RESEARCH_MOUNT/state/learning-shared" "$RESEARCH_MOUNT/state/research-private" "$RESEARCH_MOUNT/logs/research" "$RESEARCH_MOUNT/logs/learning-mcp"
  record_layout_step 03-research-children "$step_evidence"

  install_or_adopt_marker "$EXECUTOR_MOUNT" executor "$executor_uuid" "$EXECUTOR_QUOTA" "$EXECUTOR_RESERVE"
  install_or_adopt_marker "$RESEARCH_MOUNT" research "$research_uuid" "$RESEARCH_QUOTA" 0
  {
    [ "$(/usr/bin/stat -f %d "$EXECUTOR_MOUNT/.trading-desk-volume-v1")" = "$(/usr/bin/stat -f %d "$EXECUTOR_MOUNT")" ] || die "executor marker filesystem mismatch"
    [ "$(/usr/bin/stat -f %d "$RESEARCH_MOUNT/.trading-desk-volume-v1")" = "$(/usr/bin/stat -f %d "$RESEARCH_MOUNT")" ] || die "research marker filesystem mismatch"
    /usr/bin/stat -f '%N|owner=%u|group=%g|mode=%Lp|size=%z|links=%l' "$EXECUTOR_MOUNT/.trading-desk-volume-v1" "$RESEARCH_MOUNT/.trading-desk-volume-v1"
    /usr/bin/openssl dgst -sha256 "$EXECUTOR_MOUNT/.trading-desk-volume-v1" "$RESEARCH_MOUNT/.trading-desk-volume-v1"
  } > "$step_evidence"
  record_layout_step 04-volume-markers "$step_evidence"

  assert_exact_children "$EXECUTOR_MOUNT/state" execution nonce daily-loss socket
  assert_exact_children "$EXECUTOR_MOUNT/logs" executor
  assert_exact_children "$EXECUTOR_MOUNT/tmp"
  assert_exact_children "$RESEARCH_MOUNT/state" learning-shared research-private
  assert_exact_children "$RESEARCH_MOUNT/logs" research learning-mcp
  assert_exact_children "$RESEARCH_MOUNT/tmp"
  layout_evidence "$step_evidence" "$EXECUTOR_MOUNT/state/execution" "$EXECUTOR_MOUNT/state/nonce" "$EXECUTOR_MOUNT/state/daily-loss" "$EXECUTOR_MOUNT/state/socket" "$EXECUTOR_MOUNT/logs/executor" "$EXECUTOR_MOUNT/tmp" "$RESEARCH_MOUNT/state/learning-shared" "$RESEARCH_MOUNT/state/research-private" "$RESEARCH_MOUNT/logs/research" "$RESEARCH_MOUNT/logs/learning-mcp" "$RESEARCH_MOUNT/tmp"
  record_layout_step 05-complete "$step_evidence"
  assert_exact_children "$LAYOUT_RECEIPTS" 01-volume-parents 02-executor-children 03-research-children 04-volume-markers 05-complete
  /bin/rm -f "$step_evidence"
  write_state "$recorded_container" "$recorded_container_uuid" "$executor_uuid" "$research_uuid" 1 1
  /bin/echo 'LAYOUT_COMPLETE no ACL, database, config, credential, service, or venue action was performed'
  /bin/echo 'Run the separately reviewed final-path pre-init ACL phase next.'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die "plan takes no arguments"
    plan
    ;;
  --audit)
    [ "$#" -eq 1 ] || die "--audit takes no arguments"
    audit
    ;;
  --apply-create-unencrypted-testnet)
    [ "$#" -eq 1 ] || die "creation takes no additional arguments"
    create_volumes
    ;;
  --apply-adopt-mounted-unencrypted-testnet)
    [ "$#" -eq 1 ] || die "adoption takes no additional arguments"
    adopt_mounted
    ;;
  --apply-persist)
    [ "$#" -eq 2 ] || die "--apply-persist requires the attended current fstab digest or ABSENT"
    persist_mounts "$2"
    ;;
  --apply-layout)
    [ "$#" -eq 1 ] || die "layout takes no additional arguments"
    create_layout
    ;;
  *)
    die "unknown phase; run with no arguments for the plan"
    ;;
esac
