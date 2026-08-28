#!/bin/sh
set -eu
umask 077

ROOT=/private/var/db/trading-desk-testnet-remote-vpn-health
BASE_ROOT=/private/var/db/trading-desk-testnet-route-health
COLLECTOR_LOCK=$ROOT/collector.lock
LIBEXEC=/usr/local/libexec
SAMPLE=$LIBEXEC/trading-desk-testnet-remote-vpn-sample
PROBE=$LIBEXEC/trading-desk-testnet-remote-vpn-probe
HELPER_CONFIG=/etc/trading-desk/testnet-remote-vpn-helper.json
PUBLIC_WG=/etc/trading-desk/testnet-wg-exec-public.conf
PF_ANCHOR=/etc/pf.anchors/com.jawndiego.trading-desk-testnet-executor
SOURCE_SAMPLE=/opt/trading-desk/current/executor/.venv/bin/trading-desk-testnet-remote-vpn-sample
SOURCE_PROBE=/opt/trading-desk/current/executor/.venv/bin/trading-desk-testnet-remote-vpn-probe
RUNTIME_PYTHON=/opt/trading-desk/runtime/python-3.11.16/bin/python3.11
ROUTER_IDENTITY_RECEIPT=/etc/trading-desk/testnet-foreground-router-identity.receipt
BASELINE_SUPPLEMENTARY_GROUPS=
REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS=12,61,100,701
REVIEWED_DARWIN_GROUP_PRINCIPALS='12:everyone:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:none,61:localaccounts:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D:none,100:_lpoperator:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000064:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D+ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062,701:com.apple.sharepoint.group.1:EE977B55-20FF-44D2-81CD-3A51B6BBC5DC:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C'
RESEARCH_USER_GENERATED_UID=F142D892-254A-4D6A-AD46-642636A3779F
RESEARCH_GROUP_GENERATED_UID=DEB0100A-9EA4-4A8C-9FC0-42C4DD26C16A
EXECUTOR_USER_GENERATED_UID=9A28F3AD-315C-4913-BBC8-5B95DED8588E
EXECUTOR_GROUP_GENERATED_UID=7EB35DF7-1E26-4AD8-9E43-520F1F29CA5A
CONTROL_USER_GENERATED_UID=43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88
CONTROL_GROUP_GENERATED_UID=2DB06E8A-27DF-49F0-941D-E15142737975

die() { /bin/echo "ERROR: $*" >&2; exit 1; }
digest() { /usr/bin/openssl dgst -sha256 "$1" | /usr/bin/awk '{print $2}'; }
no_acl() {
  entries=$(/bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
  [ -z "$entries" ] || die "unexpected ACL: $1"
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
  user_matches=$(/usr/bin/printf '%s\n' "$user_results" | /usr/bin/awk -v generated_uid="$generated_uid" '$2 == generated_uid {print}')
  group_matches=$(/usr/bin/printf '%s\n' "$group_results" | /usr/bin/awk -v generated_uid="$generated_uid" '$2 == generated_uid {print}')
  user_count=$(/usr/bin/printf '%s\n' "$user_matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  group_count=$(/usr/bin/printf '%s\n' "$group_matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')
  [ "$((user_count + group_count))" = 1 ] || die "$generated_account GeneratedUID is not globally unique"
  case "$generated_node" in
    /Users)
      [ "$user_count" = 1 ] && [ "$group_count" = 0 ] && \
        [ "$(/usr/bin/printf '%s\n' "$user_matches" | /usr/bin/awk 'NF {print $1}')" = "$generated_account" ] || \
        die "$generated_account user GeneratedUID belongs to another record"
      ;;
    /Groups)
      [ "$group_count" = 1 ] && [ "$user_count" = 0 ] && \
        [ "$(/usr/bin/printf '%s\n' "$group_matches" | /usr/bin/awk 'NF {print $1}')" = "$generated_account" ] || \
        die "$generated_account group GeneratedUID belongs to another record"
      ;;
    *) die 'GeneratedUID node is invalid' ;;
  esac
  /usr/bin/printf '%s\n' "$generated_uid"
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
  if [ -z "$nested_lines" ]; then /bin/echo none; return 0; fi
  [ "$(/usr/bin/printf '%s\n' "$nested_lines" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 1 ] || \
    die "$reviewed_group reviewed nested-group value is ambiguous"
  canonical_uuid_set "${nested_lines#NestedGroups: }" || \
    die "$reviewed_group reviewed nested-group value is malformed"
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
  [ "$(/usr/bin/id -u "$role_account")" = "$role_uid" ] || die "$role_account UID drift"
  [ "$(/usr/bin/id -g "$role_account")" = "$role_uid" ] || die "$role_account primary GID drift"
  [ "$(dscl_value "/Users/$role_account" NFSHomeDirectory)" = /var/empty ] || die "$role_account home drift"
  [ "$(dscl_value "/Users/$role_account" UserShell)" = /usr/bin/false ] || die "$role_account shell drift"
  [ "$(dscl_value "/Users/$role_account" IsHidden)" = 1 ] || die "$role_account hidden flag drift"
  assert_disabled_password_account "$role_account"
  [ "$(assert_generated_uid_unique /Users "$role_account")" = "$expected_user_uuid" ] || die "$role_account user GeneratedUID drift"
  [ "$(assert_generated_uid_unique /Groups "$role_account")" = "$expected_group_uuid" ] || die "$role_account group GeneratedUID drift"
  assert_primary_group_has_no_members "$role_account"
  [ "$(supplementary_group_set "$role_account" "$role_uid")" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] || \
    die "$role_account supplementary groups differ from the reviewed Darwin set"
}

assert_router_group_baseline() {
  research_groups=$(supplementary_group_set trading-research 450)
  executor_groups=$(supplementary_group_set trading-executor 451)
  control_groups=$(supplementary_group_set trading-control 452)
  router_groups=$(supplementary_group_set trading-router-operator 454)
  [ "$research_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] && \
    [ "$executor_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] && \
    [ "$control_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] && \
    [ "$router_groups" = "$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS" ] || \
    die 'trading-router-operator supplementary groups differ from the reviewed Darwin set'
  assert_existing_role_identity trading-research 450 "$RESEARCH_USER_GENERATED_UID" "$RESEARCH_GROUP_GENERATED_UID"
  assert_existing_role_identity trading-executor 451 "$EXECUTOR_USER_GENERATED_UID" "$EXECUTOR_GROUP_GENERATED_UID"
  assert_existing_role_identity trading-control 452 "$CONTROL_USER_GENERATED_UID" "$CONTROL_GROUP_GENERATED_UID"
  assert_reviewed_supplementary_group_principals
  BASELINE_SUPPLEMENTARY_GROUPS=$REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS
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
  results=$(directory_id_inventory "$node" "$attribute") || \
    die "$node $attribute inventory failed"
  matches=$(/usr/bin/printf '%s\n' "$results" | \
    /usr/bin/awk -v numeric_id="$numeric_id" '$2 == numeric_id {print}')
  [ "$(/usr/bin/printf '%s\n' "$matches" | /usr/bin/awk 'NF {count += 1} END {print count + 0}')" = 1 ] || \
    die "$node $attribute $numeric_id is not unique"
  [ "$(/usr/bin/printf '%s\n' "$matches" | /usr/bin/awk 'NF {print $1}')" = "$expected_name" ] || \
    die "$node $attribute $numeric_id belongs to another name"
  [ "$(/usr/bin/printf '%s\n' "$matches" | /usr/bin/awk 'NF {print NF}')" = 2 ] || \
    die "$node $attribute list result is ambiguous"
}

disabled_account_variant() {
  disabled_account=$1
  user_record=$(/usr/bin/dscl . -read "/Users/$disabled_account" 2>/dev/null) || \
    die "$disabled_account directory-service record read failed"
  password_lines=$(/usr/bin/printf '%s\n' "$user_record" | /usr/bin/sed -n '/^Password: /p')
  [ "$password_lines" = 'Password: *' ] || die "$disabled_account password marker is not disabled"
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
  [ -z "$(/usr/bin/printf '%s\n' "$group_record" | /usr/bin/sed -n '/^GroupMembership:/p')" ] || \
    die "$member_group group has explicit members"
  [ -z "$(/usr/bin/printf '%s\n' "$group_record" | /usr/bin/sed -n '/^GroupMembers:/p')" ] || \
    die "$member_group group has explicit member UUIDs"
  [ -z "$(/usr/bin/printf '%s\n' "$group_record" | /usr/bin/sed -n '/^NestedGroups:/p')" ] || \
    die "$member_group group has nested groups"
}

assert_router_home_exact() {
  for ancestor in /private /private/var /private/var/db
  do
    [ -d "$ancestor" ] && [ ! -L "$ancestor" ] && \
      [ "$(/bin/realpath "$ancestor")" = "$ancestor" ] && \
      [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$ancestor")" = 0:0:755 ] || \
      die "router home ancestor differs: $ancestor"
    no_acl "$ancestor"
  done
  [ -d /private/var/db/trading-desk-lima ] && \
    [ ! -L /private/var/db/trading-desk-lima ] && \
    [ "$(/bin/realpath /private/var/db/trading-desk-lima)" = /private/var/db/trading-desk-lima ] && \
    [ "$(/usr/bin/stat -f '%u:%g:%Lp' /private/var/db/trading-desk-lima)" = 454:454:700 ] || \
    die 'router operator Lima home metadata differs'
  no_acl /private/var/db/trading-desk-lima
}

assert_router_identity_receipt() {
  [ -f "$ROUTER_IDENTITY_RECEIPT" ] && [ ! -L "$ROUTER_IDENTITY_RECEIPT" ] || \
    die 'router identity receipt is unavailable'
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$ROUTER_IDENTITY_RECEIPT")" = 0:0:400:1 ] || \
    die 'router identity receipt metadata differs'
  receipt_size=$(/usr/bin/stat -f %z "$ROUTER_IDENTITY_RECEIPT")
  [ "$receipt_size" -gt 0 ] && [ "$receipt_size" -le 2048 ] || \
    die 'router identity receipt size differs'
  no_acl "$ROUTER_IDENTITY_RECEIPT"
  user_generated_uid=$(assert_generated_uid_unique /Users trading-router-operator)
  group_generated_uid=$(assert_generated_uid_unique /Groups trading-router-operator)
  authentication_variant=$(disabled_account_variant trading-router-operator)
  expected_receipt=$(
    /usr/bin/printf '%s\n' \
      'schema_version=3' \
      'role=router' \
      'account=trading-router-operator' \
      'uid=454' \
      'gid=454' \
      "user_generated_uid=$user_generated_uid" \
      "group_generated_uid=$group_generated_uid" \
      'home=/private/var/db/trading-desk-lima' \
      'shell=/usr/bin/false' \
      'authentication=password-star-and-false-shell' \
      "authentication_authority=$authentication_variant" \
      'hidden=1' \
      "supplementary_groups=$BASELINE_SUPPLEMENTARY_GROUPS" \
      'supplementary_group_model=matches-existing-trading-role-baseline' \
      "supplementary_group_principals=$REVIEWED_DARWIN_GROUP_PRINCIPALS" \
      'primary_group_members=none' \
      'primary_group_nested_groups=none' \
      'credential_loaded=false' \
      'network_changed=false' \
      'service_started=false' \
      'venue_write_attempted=false' \
      'mainnet_authorized=false'
  )
  actual_receipt=$(/bin/cat "$ROUTER_IDENTITY_RECEIPT") || \
    die 'router identity receipt cannot be read'
  [ "$actual_receipt" = "$expected_receipt" ] || die 'router identity receipt differs'
}

assert_router_identity_exact() {
  assert_directory_id_singleton /Users UniqueID 454 trading-router-operator
  assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator
  [ "$(/usr/bin/id -u trading-router-operator)" = 454 ] || die 'trading-router-operator UID drift'
  [ "$(/usr/bin/id -g trading-router-operator)" = 454 ] || die 'trading-router-operator GID drift'
  assert_router_group_baseline
  [ "$(dscl_value /Users/trading-router-operator UserShell)" = /usr/bin/false ] || die 'trading-router-operator login shell is not disabled'
  [ "$(dscl_value /Users/trading-router-operator NFSHomeDirectory)" = /private/var/db/trading-desk-lima ] || die 'trading-router-operator home drift'
  [ "$(dscl_value /Users/trading-router-operator IsHidden)" = 1 ] || die 'trading-router-operator is not hidden'
  [ "$(dscl_value /Groups/trading-router-operator PrimaryGroupID)" = 454 ] || die 'trading-router-operator group ID drift'
  assert_disabled_password_account trading-router-operator
  assert_generated_uid_unique /Users trading-router-operator >/dev/null
  assert_generated_uid_unique /Groups trading-router-operator >/dev/null
  assert_primary_group_has_no_members trading-router-operator
  assert_router_identity_receipt
  assert_router_home_exact
}

assert_root_sealed_directory_chain() {
  sealed_cursor=$1
  case "$sealed_cursor" in /*) ;; *) die "sealed directory must be absolute: $sealed_cursor" ;; esac
  [ "$(/bin/realpath "$sealed_cursor")" = "$sealed_cursor" ] || die "sealed directory path is non-canonical: $sealed_cursor"
  while :
  do
    [ -d "$sealed_cursor" ] && [ ! -L "$sealed_cursor" ] || die "sealed directory is unavailable: $sealed_cursor"
    [ "$(/usr/bin/stat -f %u "$sealed_cursor")" = 0 ] || die "sealed directory is not root-owned: $sealed_cursor"
    [ "$(/usr/bin/stat -f %g "$sealed_cursor")" = 0 ] || die "sealed directory group is not wheel: $sealed_cursor"
    [ -z "$(/usr/bin/find "$sealed_cursor" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed directory is group/world writable: $sealed_cursor"
    no_acl "$sealed_cursor"
    [ "$sealed_cursor" = / ] && break
    sealed_cursor=$(/usr/bin/dirname "$sealed_cursor")
  done
}

assert_root_sealed_regular_file() {
  sealed_file=$1
  [ -f "$sealed_file" ] && [ ! -L "$sealed_file" ] || die "sealed file is unavailable: $sealed_file"
  [ "$(/bin/realpath "$sealed_file")" = "$sealed_file" ] || die "sealed file path is non-canonical: $sealed_file"
  [ "$(/usr/bin/stat -f %u "$sealed_file")" = 0 ] || die "sealed file is not root-owned: $sealed_file"
  [ "$(/usr/bin/stat -f %g "$sealed_file")" = 0 ] || die "sealed file group is not wheel: $sealed_file"
  [ "$(/usr/bin/stat -f %l "$sealed_file")" = 1 ] || die "sealed file is hard-linked: $sealed_file"
  [ -z "$(/usr/bin/find "$sealed_file" -maxdepth 0 -perm +022 -print -quit)" ] || die "sealed file is group/world writable: $sealed_file"
  no_acl "$sealed_file"
}

file_signature() {
  /usr/bin/stat -f '%d:%i:%u:%g:%Lp:%l:%z' "$1"
}

revalidate_source() {
  revalidate_path=$1
  revalidate_sha256=$2
  revalidate_signature=$3
  assert_root_sealed_directory_chain "$(/usr/bin/dirname "$revalidate_path")"
  assert_root_sealed_regular_file "$revalidate_path"
  [ "$(file_signature "$revalidate_path")" = "$revalidate_signature" ] || die "sealed source identity changed: $revalidate_path"
  [ "$(digest "$revalidate_path")" = "$revalidate_sha256" ] || die "sealed source bytes changed: $revalidate_path"
}

if [ "$#" -eq 0 ]; then
  /bin/echo 'PLAN_ONLY'
  /bin/echo 'Apply only with: --apply ABSOLUTE_ROOT_OWNED_SEALED_MEDIA EXPECTED_MEDIA_SHA256'
  /bin/echo 'Required media: helper-config.json, wg-exec-public.conf, pf-anchor.conf, base-expectation.json, remote-expectation.json.'
  /bin/echo 'Installs fixed helpers and root-owned expectation files; does not load PF, start Lima/WireGuard, create keys, start a service, read a credential, or call a venue.'
  exit 0
fi
[ "$#" -eq 3 ] && [ "$1" = --apply ] || die 'use --apply ABSOLUTE_ROOT_OWNED_SEALED_MEDIA EXPECTED_MEDIA_SHA256'
[ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || die 'run as real/effective root'
case "$0" in /*) ;; *) die 'apply requires an absolute sealed installer path' ;; esac
[ ! -L "$0" ] && [ "$(/bin/realpath "$0")" = "$0" ] || die 'installer path is non-canonical or symlinked'
assert_root_sealed_directory_chain "$(/usr/bin/dirname "$0")"
assert_root_sealed_regular_file "$0"
assert_router_identity_exact
media=$2
expected_media_hash=$3
case "$expected_media_hash" in *[!0-9a-f]*|'') die 'expected media hash is invalid' ;; esac
[ ${#expected_media_hash} -eq 64 ] || die 'expected media hash is invalid'
case "$media" in /*) ;; *) die 'media path must be absolute' ;; esac
assert_root_sealed_directory_chain "$media"
[ -z "$(/usr/bin/find "$media" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] || die 'media contains a non-regular entry'
[ "$(/usr/bin/find "$media" -mindepth 1 -maxdepth 1 -type f | /usr/bin/awk 'END {print NR+0}')" = 5 ] || die 'media inventory differs'
for name in helper-config.json wg-exec-public.conf pf-anchor.conf base-expectation.json remote-expectation.json
do
  path=$media/$name
  assert_root_sealed_regular_file "$path"
done
! /usr/bin/grep -Eq 'PrivateKey|BEGIN .*PRIVATE|api[_-]?wallet|approval[_-]?hmac|recovery[_-]?hmac|grant[_-]?hmac' "$media"/* || die 'secret-like material rejected'

base_expectation_source=$media/base-expectation.json
helper_config_source=$media/helper-config.json
pf_anchor_source=$media/pf-anchor.conf
remote_expectation_source=$media/remote-expectation.json
public_wg_source=$media/wg-exec-public.conf
base_expectation_signature=$(file_signature "$base_expectation_source")
helper_config_signature=$(file_signature "$helper_config_source")
pf_anchor_signature=$(file_signature "$pf_anchor_source")
remote_expectation_signature=$(file_signature "$remote_expectation_source")
public_wg_signature=$(file_signature "$public_wg_source")
base_expectation_sha=$(digest "$base_expectation_source")
helper_config_sha=$(digest "$helper_config_source")
pf_anchor_sha=$(digest "$pf_anchor_source")
remote_expectation_sha=$(digest "$remote_expectation_source")
public_wg_sha=$(digest "$public_wg_source")
actual_media_hash=$(
  {
    /bin/echo "base-expectation.json $base_expectation_sha"
    /bin/echo "helper-config.json $helper_config_sha"
    /bin/echo "pf-anchor.conf $pf_anchor_sha"
    /bin/echo "remote-expectation.json $remote_expectation_sha"
    /bin/echo "wg-exec-public.conf $public_wg_sha"
  } | /usr/bin/openssl dgst -sha256 | /usr/bin/awk '{print $2}'
)
[ "$actual_media_hash" = "$expected_media_hash" ] || die 'sealed media SHA-256 differs'
revalidate_source "$base_expectation_source" "$base_expectation_sha" "$base_expectation_signature"
revalidate_source "$helper_config_source" "$helper_config_sha" "$helper_config_signature"
revalidate_source "$pf_anchor_source" "$pf_anchor_sha" "$pf_anchor_signature"
revalidate_source "$remote_expectation_source" "$remote_expectation_sha" "$remote_expectation_signature"
revalidate_source "$public_wg_source" "$public_wg_sha" "$public_wg_signature"

[ -x "$SOURCE_SAMPLE" ] && [ ! -L "$SOURCE_SAMPLE" ] || die 'installed sample entrypoint unavailable'
[ -x "$SOURCE_PROBE" ] && [ ! -L "$SOURCE_PROBE" ] || die 'installed probe entrypoint unavailable'
SOURCE_SAMPLE=$(/bin/realpath "$SOURCE_SAMPLE")
SOURCE_PROBE=$(/bin/realpath "$SOURCE_PROBE")
assert_root_sealed_directory_chain "$(/usr/bin/dirname "$SOURCE_SAMPLE")"
assert_root_sealed_directory_chain "$(/usr/bin/dirname "$SOURCE_PROBE")"
assert_root_sealed_regular_file "$SOURCE_SAMPLE"
assert_root_sealed_regular_file "$SOURCE_PROBE"
source_sample_signature=$(file_signature "$SOURCE_SAMPLE")
source_probe_signature=$(file_signature "$SOURCE_PROBE")
source_sample_sha=$(digest "$SOURCE_SAMPLE")
source_probe_sha=$(digest "$SOURCE_PROBE")
revalidate_source "$helper_config_source" "$helper_config_sha" "$helper_config_signature"
revalidate_source "$base_expectation_source" "$base_expectation_sha" "$base_expectation_signature"
revalidate_source "$remote_expectation_source" "$remote_expectation_sha" "$remote_expectation_signature"
config_hash=$(/usr/bin/sed -n 's/.*"executor_config_hash"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$media/helper-config.json")
[ ${#config_hash} -eq 64 ] || die 'helper config hash missing or ambiguous'
/usr/bin/grep -Fq "\"sample_helper_sha256\": \"$source_sample_sha\"" "$media/helper-config.json" || die 'sample helper hash differs'
/usr/bin/grep -Fq "\"probe_helper_sha256\": \"$source_probe_sha\"" "$media/helper-config.json" || die 'probe helper hash differs'
/usr/bin/grep -Fq "\"executor_config_hash\": \"$config_hash\"" "$media/base-expectation.json" || die 'base expectation config differs'
/usr/bin/grep -Fq "\"executor_config_hash\": \"$config_hash\"" "$media/remote-expectation.json" || die 'remote expectation config differs'
[ "$public_wg_sha" = "$(/usr/bin/sed -n 's/.*"mac_wireguard_configuration_hash"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$media/remote-expectation.json")" ] || die 'public WireGuard hash differs'
[ "$pf_anchor_sha" = "$(/usr/bin/sed -n 's/.*"mac_pf_policy_hash"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$media/remote-expectation.json")" ] || die 'PF policy hash differs'

for target in "$BASE_ROOT/$config_hash/evidence.json" "$ROOT/$config_hash/evidence.json"
do
  [ ! -e "$target" ] && [ ! -L "$target" ] || die "target already exists: $target"
done
adopt_cache_root() {
  cache_root=$1
  optional_root_file=$2
  config_dir=$cache_root/$config_hash
  if [ -e "$cache_root" ] || [ -L "$cache_root" ]; then
    [ -d "$cache_root" ] && [ ! -L "$cache_root" ] || die "cache root is invalid: $cache_root"
    [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$cache_root")" = 0:0:755 ] || die "cache root metadata differs: $cache_root"
    no_acl "$cache_root"
    if [ "$optional_root_file" = NONE ]; then
      unexpected=$(/usr/bin/find "$cache_root" -mindepth 1 -maxdepth 1 ! -name "$config_hash" -print -quit)
    else
      [ "$optional_root_file" = collector.lock ] || die 'unexpected cache-root file allowance'
      unexpected=$(/usr/bin/find "$cache_root" -mindepth 1 -maxdepth 1 ! -name "$config_hash" ! -name "$optional_root_file" -print -quit)
    fi
    [ -z "$unexpected" ] || die "cache root contains another entry: $unexpected"
  else
    /bin/mkdir "$cache_root"
    /usr/sbin/chown root:wheel "$cache_root"
    /bin/chmod 0755 "$cache_root"
  fi
  if [ -e "$config_dir" ] || [ -L "$config_dir" ]; then
    [ -d "$config_dir" ] && [ ! -L "$config_dir" ] || die "cache config directory is invalid: $config_dir"
    [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$config_dir")" = 0:0:755 ] || die "cache config metadata differs: $config_dir"
    no_acl "$config_dir"
    unexpected=$(/usr/bin/find "$config_dir" -mindepth 1 -maxdepth 1 ! -name expectation.json -print -quit)
    [ -z "$unexpected" ] || die "cache config directory has an unexpected entry: $unexpected"
  else
    /bin/mkdir "$config_dir"
    /usr/sbin/chown root:wheel "$config_dir"
    /bin/chmod 0755 "$config_dir"
  fi
}
/bin/mkdir -p "$LIBEXEC" /etc/pf.anchors
for trusted_parent in /usr/local "$LIBEXEC" /etc/pf.anchors
do
  [ -d "$trusted_parent" ] && [ ! -L "$trusted_parent" ] || die "trusted parent is invalid: $trusted_parent"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$trusted_parent")" = 0:0:755 ] || die "trusted parent metadata differs: $trusted_parent"
  no_acl "$trusted_parent"
done
adopt_cache_root "$BASE_ROOT" NONE
adopt_cache_root "$ROOT" collector.lock
/usr/sbin/chown root:wheel "$BASE_ROOT" "$BASE_ROOT/$config_hash" "$ROOT" "$ROOT/$config_hash"
/bin/chmod 0755 "$BASE_ROOT" "$BASE_ROOT/$config_hash" "$ROOT" "$ROOT/$config_hash"
[ -x "$RUNTIME_PYTHON" ] || die 'sealed admin runtime is unavailable'
RUNTIME_PYTHON=$(/bin/realpath "$RUNTIME_PYTHON")
case "$RUNTIME_PYTHON" in /opt/trading-desk/runtime/python-3.11.16/*) ;; *) die 'sealed admin runtime escapes its root' ;; esac
assert_root_sealed_directory_chain "$(/usr/bin/dirname "$RUNTIME_PYTHON")"
assert_root_sealed_regular_file "$RUNTIME_PYTHON"

/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  "$RUNTIME_PYTHON" -I -c '
import fcntl
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except FileNotFoundError:
    descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
try:
    metadata = os.fstat(descriptor)
    named = os.lstat(path)
    identity = (
        metadata.st_mode, metadata.st_uid, metadata.st_gid,
        metadata.st_nlink, metadata.st_dev, metadata.st_ino, metadata.st_size,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or metadata.st_size != 0
        or identity != (
            named.st_mode, named.st_uid, named.st_gid,
            named.st_nlink, named.st_dev, named.st_ino, named.st_size,
        )
    ):
        raise RuntimeError("collector lock metadata differs")
    os.fsync(descriptor)
    fcntl.fcntl(descriptor, 51)
finally:
    os.close(descriptor)

parent = os.path.dirname(path)
parent_descriptor = os.open(
    parent,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    fcntl.fcntl(parent_descriptor, 51)
finally:
    os.close(parent_descriptor)
' "$COLLECTOR_LOCK" || die 'collector lock installation failed'
[ -f "$COLLECTOR_LOCK" ] && [ ! -L "$COLLECTOR_LOCK" ] || die 'collector lock is unavailable'
[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' "$COLLECTOR_LOCK")" = 0:0:600:1:0 ] || die 'collector lock metadata differs'
no_acl "$COLLECTOR_LOCK"

install_or_adopt() {
  install_source=$1
  install_target=$2
  install_mode=$3
  install_sha256=$4
  install_signature=$5
  revalidate_source "$install_source" "$install_sha256" "$install_signature"
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$RUNTIME_PYTHON" -I -c '
import fcntl
import hashlib
import os
import stat
import sys

source_path, target_path, mode_text, expected_sha256, signature_text = sys.argv[1:]
parts = signature_text.split(":")
if len(parts) != 7:
    raise RuntimeError("sealed source signature is invalid")
expected_source = (
    int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]),
    int(parts[4], 8), int(parts[5]), int(parts[6]),
)
target_mode = int(mode_text, 8)
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

def signature(value):
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode), value.st_nlink, value.st_size,
    )

def read_hash(descriptor, maximum=64 * 1024 * 1024):
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise RuntimeError("sealed source exceeds size bound")
        digest.update(chunk)
    return digest.hexdigest(), total

source = os.open(source_path, read_flags)
target = -1
created = False
created_identity = None
try:
    source_metadata = os.fstat(source)
    if not stat.S_ISREG(source_metadata.st_mode) or signature(source_metadata) != expected_source:
        raise RuntimeError("sealed source identity changed before descriptor copy")
    source_sha256, source_size = read_hash(source)
    if source_sha256 != expected_sha256 or source_size != source_metadata.st_size:
        raise RuntimeError("sealed source bytes changed before descriptor copy")
    os.lseek(source, 0, os.SEEK_SET)

    try:
        target = os.open(target_path, read_flags)
    except FileNotFoundError:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        create_flags |= getattr(os, "O_NOFOLLOW", 0)
        target = os.open(target_path, create_flags, 0o600)
        created = True
        created_metadata = os.fstat(target)
        created_identity = (created_metadata.st_dev, created_metadata.st_ino)
        while True:
            chunk = os.read(source, 64 * 1024)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(target, chunk[offset:])
                if written <= 0:
                    raise RuntimeError("descriptor copy failed")
                offset += written
        os.fchown(target, 0, 0)
        os.fchmod(target, target_mode)
        os.fsync(target)
        fcntl.fcntl(target, 51)
    else:
        target_metadata = os.fstat(target)
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or target_metadata.st_uid != 0
            or target_metadata.st_gid != 0
            or stat.S_IMODE(target_metadata.st_mode) != target_mode
            or target_metadata.st_nlink != 1
        ):
            raise RuntimeError("partial install target metadata differs")
        target_sha256, target_size = read_hash(target)
        if target_sha256 != expected_sha256 or target_size != source_metadata.st_size:
            raise RuntimeError("partial install target bytes differ")
except Exception:
    if created and target >= 0 and created_identity is not None:
        opened_identity = (os.fstat(target).st_dev, os.fstat(target).st_ino)
        try:
            named = os.lstat(target_path)
        except OSError:
            named = None
        if (
            opened_identity == created_identity
            and named is not None
            and (named.st_dev, named.st_ino) == created_identity
        ):
            os.unlink(target_path)
    raise
finally:
    if target >= 0:
        os.close(target)
    os.close(source)

parent = os.path.dirname(target_path)
parent_descriptor = os.open(
    parent,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    fcntl.fcntl(parent_descriptor, 51)
finally:
    os.close(parent_descriptor)
' "$install_source" "$install_target" "$install_mode" "$install_sha256" "$install_signature" || die "descriptor-pinned install failed: $install_target"
  revalidate_source "$install_source" "$install_sha256" "$install_signature"
  [ -f "$install_target" ] && [ ! -L "$install_target" ] || die "installed target is invalid: $install_target"
  [ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$install_target")" = "0:0:$install_mode:1" ] || die "installed target metadata differs: $install_target"
  no_acl "$install_target"
  [ "$(digest "$install_target")" = "$install_sha256" ] || die "installed target bytes differ: $install_target"
}

install_or_adopt "$SOURCE_SAMPLE" "$SAMPLE" 555 "$source_sample_sha" "$source_sample_signature"
install_or_adopt "$SOURCE_PROBE" "$PROBE" 555 "$source_probe_sha" "$source_probe_signature"
install_or_adopt "$helper_config_source" "$HELPER_CONFIG" 444 "$helper_config_sha" "$helper_config_signature"
install_or_adopt "$public_wg_source" "$PUBLIC_WG" 444 "$public_wg_sha" "$public_wg_signature"
install_or_adopt "$pf_anchor_source" "$PF_ANCHOR" 444 "$pf_anchor_sha" "$pf_anchor_signature"
install_or_adopt "$base_expectation_source" "$BASE_ROOT/$config_hash/expectation.json" 444 "$base_expectation_sha" "$base_expectation_signature"
install_or_adopt "$remote_expectation_source" "$ROOT/$config_hash/expectation.json" 444 "$remote_expectation_sha" "$remote_expectation_signature"
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$RUNTIME_PYTHON" -I -c '
import fcntl, os, sys
for path in sys.argv[1:]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.fcntl(descriptor, 51)
    finally:
        os.close(descriptor)
parents = sorted({os.path.dirname(path) for path in sys.argv[1:]})
for path in parents:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0))
    try:
        fcntl.fcntl(descriptor, 51)
    finally:
        os.close(descriptor)
' "$SAMPLE" "$PROBE" "$HELPER_CONFIG" "$PUBLIC_WG" "$PF_ANCHOR" "$BASE_ROOT/$config_hash/expectation.json" "$ROOT/$config_hash/expectation.json" "$COLLECTOR_LOCK"

/bin/echo "REMOTE_VPN_HEALTH_INSTALL_COMPLETE config_hash=$config_hash"
/bin/echo 'PF remains unloaded; VM/tunnels remain unchanged; collector not started; no credential or venue operation performed.'
