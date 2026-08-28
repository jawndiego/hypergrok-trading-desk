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
COLLECTOR_BIRTH_MARKER=/etc/trading-desk/.testnet-foreground-collector-birth-v2
ROUTER_BIRTH_MARKER=/etc/trading-desk/.testnet-foreground-router-birth-v2

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
CHAT_SOCKET_PARENT=/private/var/db/trading-desk-testnet-chat-socket

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
BASELINE_SUPPLEMENTARY_GROUPS=
REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS=12,61,100,701
REVIEWED_DARWIN_GROUP_PRINCIPALS='12:everyone:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:none,61:localaccounts:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D:none,100:_lpoperator:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000064:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D+ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062,701:com.apple.sharepoint.group.1:EE977B55-20FF-44D2-81CD-3A51B6BBC5DC:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C'
RESEARCH_USER_GENERATED_UID=F142D892-254A-4D6A-AD46-642636A3779F
RESEARCH_GROUP_GENERATED_UID=DEB0100A-9EA4-4A8C-9FC0-42C4DD26C16A
EXECUTOR_USER_GENERATED_UID=9A28F3AD-315C-4913-BBC8-5B95DED8588E
EXECUTOR_GROUP_GENERATED_UID=7EB35DF7-1E26-4AD8-9E43-520F1F29CA5A
CONTROL_USER_GENERATED_UID=43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88
CONTROL_GROUP_GENERATED_UID=2DB06E8A-27DF-49F0-941D-E15142737975

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

identity_receipt_payload() {
    role=$1
    account=$2
    uid=$3
    gid=$4
    home=$5
    user_generated_uid=$(assert_generated_uid_unique /Users "$account")
    group_generated_uid=$(assert_generated_uid_unique /Groups "$account")
    authentication_variant=$(disabled_account_variant "$account")
    /bin/echo 'schema_version=3'
    /bin/echo "role=$role"
    /bin/echo "account=$account"
    /bin/echo "uid=$uid"
    /bin/echo "gid=$gid"
    /bin/echo "user_generated_uid=$user_generated_uid"
    /bin/echo "group_generated_uid=$group_generated_uid"
    /bin/echo "home=$home"
    /bin/echo 'shell=/usr/bin/false'
    /bin/echo 'authentication=password-star-and-false-shell'
    /bin/echo "authentication_authority=$authentication_variant"
    /bin/echo 'hidden=1'
    /bin/echo "supplementary_groups=$BASELINE_SUPPLEMENTARY_GROUPS"
    /bin/echo 'supplementary_group_model=matches-existing-trading-role-baseline'
    /bin/echo "supplementary_group_principals=$REVIEWED_DARWIN_GROUP_PRINCIPALS"
    /bin/echo 'primary_group_members=none'
    /bin/echo 'primary_group_nested_groups=none'
    /bin/echo 'credential_loaded=false'
    /bin/echo 'network_changed=false'
    /bin/echo 'service_started=false'
    /bin/echo 'venue_write_attempted=false'
    /bin/echo 'mainnet_authorized=false'
}

assert_identity_receipt_exact() {
  target=$1
  role=$2
  account=$3
  uid=$4
  gid=$5
  home=$6
  assert_regular "$target" 0 0 400
  assert_no_acl "$target"
  expected_receipt=$(identity_receipt_payload "$role" "$account" "$uid" "$gid" "$home")
  actual_receipt=$(/bin/cat "$target") || die "identity receipt cannot be read: $target"
  [ "$actual_receipt" = "$expected_receipt" ] || die "identity receipt differs: $target"
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
  identity_receipt_payload "$role" "$account" "$uid" "$gid" "$home" > "$pending"
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
  assert_identity_receipt_exact "$target" "$role" "$account" "$uid" "$gid" "$home"
  fullsync_paths "$target" /etc/trading-desk
}

write_or_verify_birth_marker() {
  target=$1
  role=$2
  account=$3
  uid=$4
  gid=$5
  home=$6
  assert_directory /etc/trading-desk 0 0 700
  pending=$TEMP_ROOT/$role-birth-marker
  {
    /bin/echo 'schema_version=2'
    /bin/echo 'kind=identity-birth-marker'
    /bin/echo "role=$role"
    /bin/echo "account=$account"
    /bin/echo "uid=$uid"
    /bin/echo "gid=$gid"
    /bin/echo "home=$home"
    /bin/echo 'shell=/usr/bin/false'
    /bin/echo 'password_marker=*'
    /bin/echo 'publish_numeric_uid_last=true'
    /bin/echo 'credential_loaded=false'
    /bin/echo 'network_changed=false'
    /bin/echo 'service_started=false'
    /bin/echo 'venue_write_attempted=false'
  } > "$pending"
  /usr/sbin/chown root:wheel "$pending"
  /bin/chmod 0400 "$pending"
  fullsync_paths "$pending"
  if [ -e "$target" ] || [ -L "$target" ]; then
    assert_regular "$target" 0 0 400
    assert_no_acl "$target"
    /usr/bin/cmp -s "$target" "$pending" || die "identity birth marker differs: $target"
  else
    /bin/mv "$pending" "$target"
  fi
  assert_regular "$target" 0 0 400
  assert_no_acl "$target"
  fullsync_paths "$target" /etc/trading-desk
}

prepare_new_identity_birth() {
  marker=$1
  role=$2
  account=$3
  uid=$4
  gid=$5
  home=$6
  marker_preexisted=1
  if [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
    marker_preexisted=0
    if /usr/bin/dscl . -read "/Users/$account" >/dev/null 2>&1; then
      die "unmarked unresolved user record exists: $account"
    fi
    if /usr/bin/dscl . -read "/Groups/$account" >/dev/null 2>&1; then
      die "unmarked unresolved group record exists: $account"
    fi
    assert_directory_id_unused /Users UniqueID "$uid"
    assert_directory_id_unused /Groups PrimaryGroupID "$gid"
  fi
  write_or_verify_birth_marker "$marker" "$role" "$account" "$uid" "$gid" "$home"
  if [ "$marker_preexisted" = 1 ]; then
    assert_resumable_identity_prefix "$account" "$uid" "$gid" "$home"
  fi
  assert_directory_id_available_to_name /Users UniqueID "$uid" "$account"
  assert_directory_id_available_to_name /Groups PrimaryGroupID "$gid" "$account"
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
  assert_platform_group_baseline
  assert_collector_identity_exact
  assert_identity_receipt_exact "$COLLECTOR_IDENTITY_RECEIPT" collector trading-public-collector 453 453 /var/empty
  assert_router_identity_exact
  assert_identity_receipt_exact "$ROUTER_IDENTITY_RECEIPT" router trading-router-operator 454 454 "$LIMA_HOME"
  assert_router_home_exact
  [ "$(/usr/bin/id -u jawndiego)" = 501 ] || die "attended Codex bridge UID drift"
}

dscl_value() {
  node=$1
  attribute=$2
  attribute_record=$(/usr/bin/dscl . -read "$node" "$attribute" 2>/dev/null) || \
    die "$node $attribute read failed"
  case "$attribute" in
    IsHidden)
      attribute_value=$(/usr/bin/printf '%s\n' "$attribute_record" | \
        /usr/bin/sed -n -e 's/^IsHidden: //p' -e 's/^dsAttrTypeNative:IsHidden: //p')
      ;;
    *)
      attribute_value=$(/usr/bin/printf '%s\n' "$attribute_record" | \
        /usr/bin/sed -n "s/^$attribute: //p")
      ;;
  esac
  [ "$(/usr/bin/printf '%s\n' "$attribute_value" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 1 ] || \
    die "$node $attribute value is absent or ambiguous"
  /usr/bin/printf '%s\n' "$attribute_value"
}

generated_uid_inventory() {
  generated_inventory_node=$1
  raw_generated_inventory=$(/usr/bin/dscl . -list "$generated_inventory_node" GeneratedUID 2>/dev/null) || \
    die "$generated_inventory_node GeneratedUID inventory failed"
  canonical_generated_inventory=$(/usr/bin/printf '%s\n' "$raw_generated_inventory" | \
    /usr/bin/awk '
function invalid() { failed=1; exit 1 }
function canonical_uuid(value, pieces, count) {
  if (length(value) != 36 || value !~ /^[0-9A-F-]+$/) return 0
  count=split(value, pieces, "-")
  return count == 5 && length(pieces[1]) == 8 && length(pieces[2]) == 4 && length(pieces[3]) == 4 && length(pieces[4]) == 4 && length(pieces[5]) == 12
}
NF != 2 { invalid() }
{
  if (!canonical_uuid($2)) invalid()
  if (seen_name[$1]++ || seen_uuid[$2]++) invalid()
  print $1 " " $2
}
END { if (failed || NR < 1) exit 1 }
') || die "$generated_inventory_node GeneratedUID inventory is malformed or non-unique"
  /usr/bin/printf '%s\n' "$canonical_generated_inventory"
}

assert_generated_uid_unique() {
  generated_node=$1
  generated_account=$2
  generated_uid=$(dscl_value "$generated_node/$generated_account" GeneratedUID)
  [ "$(canonical_uuid_set "$generated_uid")" = "$generated_uid" ] || \
    die "$generated_account GeneratedUID is not canonical"
  user_results=$(generated_uid_inventory /Users) || die 'user GeneratedUID inventory validation failed'
  group_results=$(generated_uid_inventory /Groups) || die 'group GeneratedUID inventory validation failed'
  user_matches=$(/usr/bin/printf '%s\n' "$user_results" | \
    /usr/bin/awk -v generated_uid="$generated_uid" '$NF == generated_uid {print}')
  group_matches=$(/usr/bin/printf '%s\n' "$group_results" | \
    /usr/bin/awk -v generated_uid="$generated_uid" '$NF == generated_uid {print}')
  user_count=$(/usr/bin/printf '%s\n' "$user_matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  group_count=$(/usr/bin/printf '%s\n' "$group_matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$((user_count + group_count))" = 1 ] || die "$generated_account GeneratedUID is not globally unique"
  case "$generated_node" in
    /Users)
      [ "$user_count" = 1 ] && [ "$group_count" = 0 ] && \
        [ "$(/usr/bin/printf '%s\n' "$user_matches" | /usr/bin/awk 'NF {print NF}')" = 2 ] && \
        [ "$(/usr/bin/printf '%s\n' "$user_matches" | /usr/bin/awk 'NF {print $1}')" = "$generated_account" ] || \
        die "$generated_account user GeneratedUID belongs to another record"
      ;;
    /Groups)
      [ "$group_count" = 1 ] && [ "$user_count" = 0 ] && \
        [ "$(/usr/bin/printf '%s\n' "$group_matches" | /usr/bin/awk 'NF {print NF}')" = 2 ] && \
        [ "$(/usr/bin/printf '%s\n' "$group_matches" | /usr/bin/awk 'NF {print $1}')" = "$generated_account" ] || \
        die "$generated_account group GeneratedUID belongs to another record"
      ;;
    *) die 'GeneratedUID node is invalid' ;;
  esac
  /usr/bin/printf '%s\n' "$generated_uid"
}

canonical_uuid_set() {
  raw_uuid_set=$1
  /usr/bin/printf '%s\n' "$raw_uuid_set" | /usr/bin/awk '
function invalid() { failed=1; exit 1 }
function canonical_uuid(value, pieces, count) {
  if (length(value) != 36 || value !~ /^[0-9A-F-]+$/) return 0
  count=split(value, pieces, "-")
  return count == 5 && length(pieces[1]) == 8 && length(pieces[2]) == 4 && length(pieces[3]) == 4 && length(pieces[4]) == 4 && length(pieces[5]) == 12
}
NR != 1 { invalid() }
{
  for (i=1; i<=NF; i += 1) {
    if (!canonical_uuid($i) || seen[$i]++) invalid()
    values[++value_count]=$i
  }
}
END {
  if (failed || NR != 1 || value_count < 1) exit 1
  for (i=2; i<=value_count; i += 1) {
    value=values[i]
    cursor=i - 1
    while (cursor >= 1 && values[cursor] > value) {
      values[cursor + 1]=values[cursor]
      cursor -= 1
    }
    values[cursor + 1]=value
  }
  for (i=1; i<=value_count; i += 1) {
    if (i > 1) printf "+"
    printf "%s", values[i]
  }
  printf "\n"
}'
}

reviewed_group_nested_set() {
  reviewed_group=$1
  reviewed_group_record=$(/usr/bin/dscl . -read "/Groups/$reviewed_group" 2>/dev/null) || \
    die "$reviewed_group reviewed group record read failed"
  [ -z "$(/usr/bin/printf '%s\n' "$reviewed_group_record" | /usr/bin/sed -n '/^GroupMembership:/p')" ] || \
    die "$reviewed_group reviewed group has explicit members"
  [ -z "$(/usr/bin/printf '%s\n' "$reviewed_group_record" | /usr/bin/sed -n '/^GroupMembers:/p')" ] || \
    die "$reviewed_group reviewed group has explicit member UUIDs"
  nested_lines=$(/usr/bin/printf '%s\n' "$reviewed_group_record" | /usr/bin/sed -n '/^NestedGroups:/p')
  if [ -z "$nested_lines" ]; then
    /bin/echo none
    return 0
  fi
  [ "$(/usr/bin/printf '%s\n' "$nested_lines" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 1 ] || \
    die "$reviewed_group reviewed nested-group value is ambiguous"
  raw_nested=${nested_lines#NestedGroups: }
  canonical_uuid_set "$raw_nested" || die "$reviewed_group reviewed nested-group value is malformed"
}

assert_reviewed_group_principal() {
  reviewed_gid=$1
  reviewed_name=$2
  reviewed_uuid=$3
  reviewed_nested=$4
  assert_directory_id_singleton /Groups PrimaryGroupID "$reviewed_gid" "$reviewed_name"
  [ "$(assert_generated_uid_unique /Groups "$reviewed_name")" = "$reviewed_uuid" ] || \
    die "$reviewed_name GeneratedUID differs from the reviewed principal"
  [ "$(reviewed_group_nested_set "$reviewed_name")" = "$reviewed_nested" ] || \
    die "$reviewed_name nesting differs from the reviewed principal"
}

assert_reviewed_supplementary_group_principals() {
  assert_reviewed_group_principal 12 everyone ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C none
  assert_reviewed_group_principal 61 localaccounts ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D none
  assert_reviewed_group_principal 100 _lpoperator ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000064 'ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D+ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062'
  assert_reviewed_group_principal 701 com.apple.sharepoint.group.1 EE977B55-20FF-44D2-81CD-3A51B6BBC5DC ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C
}

supplementary_group_set() {
  group_account=$1
  primary_gid=$2
  raw_group_ids=$(/usr/bin/id -G "$group_account") || \
    die "$group_account group inventory failed"
  canonical_groups=$(/usr/bin/printf '%s\n' "$raw_group_ids" | \
    /usr/bin/awk -v primary="$primary_gid" '
function invalid() { failed=1; exit 1 }
NR != 1 { invalid() }
{
  for (i=1; i<=NF; i += 1) {
    if ($i !~ /^[0-9]+$/) invalid()
    numeric=$i + 0
    if (sprintf("%d", numeric) != $i || seen[numeric]++) invalid()
    if (numeric == primary) primary_count += 1
    else groups[++group_count]=numeric
  }
}
END {
  if (failed || NR != 1 || primary_count != 1) exit 1
  for (i=2; i<=group_count; i += 1) {
    value=groups[i]
    cursor=i - 1
    while (cursor >= 1 && groups[cursor] > value) {
      groups[cursor + 1]=groups[cursor]
      cursor -= 1
    }
    groups[cursor + 1]=value
  }
  for (i=1; i<=group_count; i += 1) {
    if (i > 1) printf ","
    printf "%d", groups[i]
  }
  printf "\n"
}') || die "$group_account group inventory is malformed"
  /usr/bin/printf '%s\n' "$canonical_groups"
}

assert_existing_role_identity() {
  role_account=$1
  role_uid=$2
  expected_user_uuid=$3
  expected_group_uuid=$4
  assert_directory_id_singleton /Users UniqueID "$role_uid" "$role_account"
  assert_directory_id_singleton /Groups PrimaryGroupID "$role_uid" "$role_account"
  assert_identity "$role_account" "$role_uid" "$role_uid"
  [ "$(dscl_value "/Users/$role_account" NFSHomeDirectory)" = /var/empty ] || \
    die "$role_account home drift"
  [ "$(dscl_value "/Users/$role_account" UserShell)" = /usr/bin/false ] || \
    die "$role_account shell drift"
  [ "$(dscl_value "/Users/$role_account" IsHidden)" = 1 ] || \
    die "$role_account hidden flag drift"
  assert_disabled_password_account "$role_account"
  [ "$(assert_generated_uid_unique /Users "$role_account")" = "$expected_user_uuid" ] || \
    die "$role_account user GeneratedUID drift"
  [ "$(assert_generated_uid_unique /Groups "$role_account")" = "$expected_group_uuid" ] || \
    die "$role_account group GeneratedUID drift"
  assert_primary_group_has_no_members "$role_account"
  [ "$(supplementary_group_set "$role_account" "$role_uid")" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] || \
    die "$role_account supplementary groups differ from the reviewed Darwin set"
}

assert_platform_group_baseline() {
  research_groups=$(supplementary_group_set trading-research 450)
  executor_groups=$(supplementary_group_set trading-executor 451)
  control_groups=$(supplementary_group_set trading-control 452)
  [ "$research_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] && \
    [ "$executor_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] && \
    [ "$control_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] || \
    die 'existing trading-role supplementary groups differ from the reviewed Darwin set'
  assert_existing_role_identity trading-research 450 "$RESEARCH_USER_GENERATED_UID" "$RESEARCH_GROUP_GENERATED_UID"
  assert_existing_role_identity trading-executor 451 "$EXECUTOR_USER_GENERATED_UID" "$EXECUTOR_GROUP_GENERATED_UID"
  assert_existing_role_identity trading-control 452 "$CONTROL_USER_GENERATED_UID" "$CONTROL_GROUP_GENERATED_UID"
  assert_reviewed_supplementary_group_principals
  BASELINE_SUPPLEMENTARY_GROUPS=$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS
}

assert_baseline_supplementary_groups() {
  group_account=$1
  primary_gid=$2
  [ -n "$BASELINE_SUPPLEMENTARY_GROUPS" ] || assert_platform_group_baseline
  actual_groups=$(supplementary_group_set "$group_account" "$primary_gid")
  [ "$actual_groups" = "$BASELINE_SUPPLEMENTARY_GROUPS" ] || \
    die "$group_account supplementary groups differ from the trading-role baseline"
}

disabled_account_variant() {
  disabled_account=$1
  user_record=$(/usr/bin/dscl . -read "/Users/$disabled_account" 2>/dev/null) || \
    die "$disabled_account directory-service record read failed"
  password_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^Password: /p')
  [ "$password_lines" = 'Password: *' ] || \
    die "$disabled_account password marker is not disabled"
  authentication_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^AuthenticationAuthority:/p')
  case "$authentication_lines" in
    '') /bin/echo absent ;;
    'AuthenticationAuthority: ;DisabledUser;') /bin/echo disabled-user ;;
    *) die "$disabled_account authentication authority differs" ;;
  esac
}

assert_disabled_password_account() {
  disabled_account_variant "$1" >/dev/null
}

assert_primary_group_has_no_members() {
  member_group=$1
  group_record=$(/usr/bin/dscl . -read "/Groups/$member_group" 2>/dev/null) || \
    die "$member_group group record read failed"
  membership_lines=$(/usr/bin/printf '%s\n' "$group_record" | \
    /usr/bin/sed -n '/^GroupMembership:/p')
  member_uuid_lines=$(/usr/bin/printf '%s\n' "$group_record" | \
    /usr/bin/sed -n '/^GroupMembers:/p')
  nested_group_lines=$(/usr/bin/printf '%s\n' "$group_record" | \
    /usr/bin/sed -n '/^NestedGroups:/p')
  [ -z "$membership_lines" ] || die "$member_group group has explicit members"
  [ -z "$member_uuid_lines" ] || die "$member_group group has explicit member UUIDs"
  [ -z "$nested_group_lines" ] || die "$member_group group has nested groups"
}

assert_resumable_identity_prefix() {
  prefix_account=$1
  prefix_uid=$2
  prefix_gid=$3
  prefix_home=$4

  group_names=$(/usr/bin/dscl . -list /Groups 2>/dev/null) || \
    die 'group-name inventory failed during identity resume'
  group_name_count=$(/usr/bin/printf '%s\n' "$group_names" | \
    /usr/bin/awk -v account="$prefix_account" '$1 == account && NF == 1 {count += 1} END {print count + 0}')
  [ "$group_name_count" -le 1 ] || die "$prefix_account group name is not unique"
  if [ "$group_name_count" = 1 ]; then
    group_record=$(/usr/bin/dscl . -read "/Groups/$prefix_account" 2>/dev/null) || \
      die "$prefix_account partial group record cannot be read"
    group_id_lines=$(/usr/bin/printf '%s\n' "$group_record" | /usr/bin/sed -n '/^PrimaryGroupID:/p')
    case "$group_id_lines" in
      ''|"PrimaryGroupID: $prefix_gid") ;;
      *) die "$prefix_account partial group ID differs" ;;
    esac
    assert_primary_group_has_no_members "$prefix_account"
    assert_generated_uid_unique /Groups "$prefix_account" >/dev/null
  fi

  user_names=$(/usr/bin/dscl . -list /Users 2>/dev/null) || \
    die 'user-name inventory failed during identity resume'
  user_name_count=$(/usr/bin/printf '%s\n' "$user_names" | \
    /usr/bin/awk -v account="$prefix_account" '$1 == account && NF == 1 {count += 1} END {print count + 0}')
  [ "$user_name_count" -le 1 ] || die "$prefix_account user name is not unique"
  [ "$user_name_count" = 1 ] || return 0

  user_record=$(/usr/bin/dscl . -read "/Users/$prefix_account" 2>/dev/null) || \
    die "$prefix_account partial user record cannot be read"
  shell_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^UserShell:/p')
  password_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^Password:/p')
  home_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^NFSHomeDirectory:/p')
  primary_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^PrimaryGroupID:/p')
  hidden_lines=$(/usr/bin/printf '%s\n' "$user_record" | \
    /usr/bin/sed -n -e '/^IsHidden:/p' -e '/^dsAttrTypeNative:IsHidden:/p')
  unique_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^UniqueID:/p')
  authentication_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^AuthenticationAuthority:/p')
  unexpected_security=$(/usr/bin/printf '%s\n' "$user_record" | \
    /usr/bin/sed -n -E '/^(AltSecurityIdentities|AuthenticationHint|ShadowHashData|SMBHome|SMBScriptPath|SMBSID|dsAttrTypeNative:(ShadowHashData|KerberosKeys)):/p')
  case "$shell_lines" in ''|'UserShell: /usr/bin/false') ;; *) die "$prefix_account partial shell differs" ;; esac
  case "$password_lines" in ''|'Password: *') ;; *) die "$prefix_account partial password marker differs" ;; esac
  case "$home_lines" in ''|"NFSHomeDirectory: $prefix_home") ;; *) die "$prefix_account partial home differs" ;; esac
  case "$primary_lines" in ''|"PrimaryGroupID: $prefix_gid") ;; *) die "$prefix_account partial primary group differs" ;; esac
  case "$hidden_lines" in ''|'IsHidden: 1'|'dsAttrTypeNative:IsHidden: 1') ;; *) die "$prefix_account partial hidden flag differs" ;; esac
  case "$unique_lines" in ''|"UniqueID: $prefix_uid") ;; *) die "$prefix_account partial UID differs" ;; esac
  case "$authentication_lines" in ''|'AuthenticationAuthority: ;DisabledUser;') ;; *) die "$prefix_account partial authentication authority differs" ;; esac
  [ -z "$unexpected_security" ] || die "$prefix_account partial user has an unexpected security attribute"

  missing_prefix=0
  for prefix_value in "$shell_lines" "$password_lines" "$home_lines" "$primary_lines" "$hidden_lines" "$unique_lines"
  do
    if [ -z "$prefix_value" ]; then
      missing_prefix=1
    elif [ "$missing_prefix" = 1 ]; then
      die "$prefix_account partial user attributes are not an exact creation prefix"
    fi
  done
  assert_generated_uid_unique /Users "$prefix_account" >/dev/null
}

directory_id_inventory() {
  inventory_node=$1
  inventory_attribute=$2
  raw_inventory=$(/usr/bin/dscl . -list "$inventory_node" "$inventory_attribute" 2>/dev/null) || \
    die "$inventory_node $inventory_attribute list failed"
  canonical_inventory=$(/usr/bin/printf '%s\n' "$raw_inventory" | \
    /usr/bin/awk '
function invalid() { failed=1; exit 1 }
NF != 2 { invalid() }
{
  if ($2 !~ /^-?[0-9]+$/ || sprintf("%d", $2 + 0) != $2) invalid()
  if (seen_name[$1]++ || seen_id[$2]++) invalid()
  print $1 " " $2
}
END { if (failed || NR < 1) exit 1 }
') || die "$inventory_node $inventory_attribute inventory is malformed or non-unique"
  /usr/bin/printf '%s\n' "$canonical_inventory"
}

assert_directory_id_singleton() {
  node=$1
  attribute=$2
  numeric_id=$3
  expected_name=$4
  results=$(directory_id_inventory "$node" "$attribute") || die "$node $attribute inventory failed"
  matches=$(/bin/echo "$results" | /usr/bin/awk -v numeric_id="$numeric_id" '$2 == numeric_id {print}')
  count=$(/bin/echo "$matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" = 1 ] || die "$node $attribute $numeric_id is not unique"
  [ "$(/bin/echo "$matches" | /usr/bin/awk 'NF {print $1}')" = "$expected_name" ] || die "$node $attribute $numeric_id belongs to another name"
  [ "$(/bin/echo "$matches" | /usr/bin/awk 'NF {print NF}')" = 2 ] || die "$node $attribute list result is ambiguous"
}

assert_directory_id_unused() {
  node=$1
  attribute=$2
  numeric_id=$3
  results=$(directory_id_inventory "$node" "$attribute") || die "$node $attribute collision inventory failed"
  matches=$(/bin/echo "$results" | /usr/bin/awk -v numeric_id="$numeric_id" '$2 == numeric_id {print}')
  count=$(/bin/echo "$matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" = 0 ] || die "$node $attribute $numeric_id is already assigned: $matches"
}

assert_directory_id_available_to_name() {
  node=$1
  attribute=$2
  numeric_id=$3
  expected_name=$4
  results=$(directory_id_inventory "$node" "$attribute") || \
    die "$node $attribute availability inventory failed"
  matches=$(/bin/echo "$results" | /usr/bin/awk -v numeric_id="$numeric_id" '$2 == numeric_id {print}')
  count=$(/bin/echo "$matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$count" -le 1 ] || die "$node $attribute $numeric_id is not unique"
  if [ "$count" = 1 ]; then
    [ "$(/bin/echo "$matches" | /usr/bin/awk 'NF {print $1}')" = "$expected_name" ] || \
      die "$node $attribute $numeric_id belongs to another name"
    [ "$(/bin/echo "$matches" | /usr/bin/awk 'NF {print NF}')" = 2 ] || \
      die "$node $attribute availability result is ambiguous"
  fi
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
  assert_disabled_password_account trading-public-collector
  assert_generated_uid_unique /Users trading-public-collector >/dev/null
  assert_generated_uid_unique /Groups trading-public-collector >/dev/null
  [ "$(dscl_value /Groups/trading-public-collector PrimaryGroupID)" = 453 ] || die 'collector group ID drift'
  assert_primary_group_has_no_members trading-public-collector
  assert_baseline_supplementary_groups trading-public-collector 453
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
  assert_disabled_password_account trading-router-operator
  assert_generated_uid_unique /Users trading-router-operator >/dev/null
  assert_generated_uid_unique /Groups trading-router-operator >/dev/null
  [ "$(dscl_value /Groups/trading-router-operator PrimaryGroupID)" = 454 ] || die 'router operator group ID drift'
  assert_primary_group_has_no_members trading-router-operator
  assert_baseline_supplementary_groups trading-router-operator 454
}

assert_router_home_exact() {
  [ "$(/bin/realpath "$LIMA_HOME")" = "$LIMA_HOME" ] || die 'router operator home is non-canonical'
  assert_directory "$LIMA_HOME" 454 454 700
  assert_no_acl "$LIMA_HOME"
}

assert_unresolved_user_prefix() {
  prefix_account=$1
  prefix_uid=$2
  prefix_gid=$3
  prefix_home=$4
  [ "$(dscl_value "/Users/$prefix_account" UserShell)" = /usr/bin/false ] || \
    die "$prefix_account partial shell differs"
  [ "$(dscl_value "/Users/$prefix_account" NFSHomeDirectory)" = "$prefix_home" ] || \
    die "$prefix_account partial home differs"
  [ "$(dscl_value "/Users/$prefix_account" PrimaryGroupID)" = "$prefix_gid" ] || \
    die "$prefix_account partial primary group differs"
  [ "$(dscl_value "/Users/$prefix_account" IsHidden)" = 1 ] || \
    die "$prefix_account partial hidden flag differs"
  assert_disabled_password_account "$prefix_account"
  assert_generated_uid_unique /Users "$prefix_account" >/dev/null
  assert_directory_id_available_to_name /Users UniqueID "$prefix_uid" "$prefix_account"
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
  assert_platform_group_baseline
  assert_system_db_ancestors
  acquire_lock
  if [ -e "$COLLECTOR_IDENTITY_RECEIPT" ] || [ -L "$COLLECTOR_IDENTITY_RECEIPT" ]; then
    assert_collector_identity_exact
    assert_identity_receipt_exact "$COLLECTOR_IDENTITY_RECEIPT" collector trading-public-collector 453 453 /var/empty
    /bin/echo 'IDENTITY_COMPLETE exact disabled, hidden, no-home UID/GID 453'
    return 0
  fi
  if /usr/bin/id -u trading-public-collector >/dev/null 2>&1; then
    assert_collector_identity_exact
  else
    prepare_new_identity_birth "$COLLECTOR_BIRTH_MARKER" collector trading-public-collector 453 453 /var/empty
    /usr/bin/dscl . -create /Groups/trading-public-collector PrimaryGroupID 453
    /usr/bin/dscl . -create /Groups/trading-public-collector RealName 'Trading Desk Public Collector'
    assert_directory_id_singleton /Groups PrimaryGroupID 453 trading-public-collector
    assert_primary_group_has_no_members trading-public-collector
    assert_generated_uid_unique /Groups trading-public-collector >/dev/null
    /usr/bin/dscl . -create /Users/trading-public-collector UserShell /usr/bin/false
    /usr/bin/dscl . -create /Users/trading-public-collector Password '*'
    /usr/bin/dscl . -create /Users/trading-public-collector NFSHomeDirectory /var/empty
    /usr/bin/dscl . -create /Users/trading-public-collector PrimaryGroupID 453
    /usr/bin/dscl . -create /Users/trading-public-collector RealName 'Trading Desk Public Collector'
    /usr/bin/dscl . -create /Users/trading-public-collector IsHidden 1
    assert_unresolved_user_prefix trading-public-collector 453 453 /var/empty
    /usr/bin/dscl . -create /Users/trading-public-collector UniqueID 453
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
  assert_platform_group_baseline
  assert_system_db_ancestors
  acquire_lock
  if [ -e "$ROUTER_IDENTITY_RECEIPT" ] || [ -L "$ROUTER_IDENTITY_RECEIPT" ]; then
    assert_router_identity_exact
    assert_identity_receipt_exact "$ROUTER_IDENTITY_RECEIPT" router trading-router-operator 454 454 "$LIMA_HOME"
    assert_router_home_exact
    /bin/echo "ROUTER_IDENTITY_COMPLETE exact disabled UID/GID 454 lima_home=$LIMA_HOME"
    return 0
  fi
  if /usr/bin/id -u trading-router-operator >/dev/null 2>&1; then
    assert_router_identity_exact
  else
    prepare_new_identity_birth "$ROUTER_BIRTH_MARKER" router trading-router-operator 454 454 "$LIMA_HOME"
    /usr/bin/dscl . -create /Groups/trading-router-operator PrimaryGroupID 454
    /usr/bin/dscl . -create /Groups/trading-router-operator RealName 'Trading Desk Router Operator'
    assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator
    assert_primary_group_has_no_members trading-router-operator
    assert_generated_uid_unique /Groups trading-router-operator >/dev/null
    /usr/bin/dscl . -create /Users/trading-router-operator UserShell /usr/bin/false
    /usr/bin/dscl . -create /Users/trading-router-operator Password '*'
    /usr/bin/dscl . -create /Users/trading-router-operator NFSHomeDirectory "$LIMA_HOME"
    /usr/bin/dscl . -create /Users/trading-router-operator PrimaryGroupID 454
    /usr/bin/dscl . -create /Users/trading-router-operator RealName 'Trading Desk Router Operator'
    /usr/bin/dscl . -create /Users/trading-router-operator IsHidden 1
    assert_unresolved_user_prefix trading-router-operator 454 454 "$LIMA_HOME"
    /usr/bin/dscl . -create /Users/trading-router-operator UniqueID 454
    /usr/bin/dscacheutil -flushcache
    assert_router_identity_exact
  fi
  assert_router_identity_exact
  ensure_directory "$LIMA_HOME" 454 454 700 NONE
  assert_router_home_exact
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
    "$CHAT_SOCKET_PARENT" "$HANDOFF_CONFIG" "$HANDOFF_ROOT" \
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
