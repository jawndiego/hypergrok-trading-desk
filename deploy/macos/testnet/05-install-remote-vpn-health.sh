#!/bin/sh
set -eu
umask 077

ROOT=/private/var/db/trading-desk-testnet-remote-vpn-health
BASE_ROOT=/private/var/db/trading-desk-testnet-route-health
LIBEXEC=/usr/local/libexec
SAMPLE=$LIBEXEC/trading-desk-testnet-remote-vpn-sample
PROBE=$LIBEXEC/trading-desk-testnet-remote-vpn-probe
HELPER_CONFIG=/etc/trading-desk/testnet-remote-vpn-helper.json
PUBLIC_WG=/etc/trading-desk/testnet-wg-exec-public.conf
PF_ANCHOR=/etc/pf.anchors/com.jawndiego.trading-desk-testnet-executor
SOURCE_SAMPLE=/opt/trading-desk/current/executor/.venv/bin/trading-desk-testnet-remote-vpn-sample
SOURCE_PROBE=/opt/trading-desk/current/executor/.venv/bin/trading-desk-testnet-remote-vpn-probe
RUNTIME_PYTHON=/opt/trading-desk/runtime/python-3.11.16/bin/python3.11

die() { /bin/echo "ERROR: $*" >&2; exit 1; }
digest() { /usr/bin/openssl dgst -sha256 "$1" | /usr/bin/awk '{print $2}'; }
no_acl() {
  entries=$(/bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
  [ -z "$entries" ] || die "unexpected ACL: $1"
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
[ "$(/usr/bin/id -u trading-router-operator)" = 454 ] || die 'trading-router-operator UID drift'
[ "$(/usr/bin/id -g trading-router-operator)" = 454 ] || die 'trading-router-operator GID drift'
[ "$(/usr/bin/id -G trading-router-operator)" = 454 ] || die 'trading-router-operator has supplementary groups'
[ "$(/usr/bin/dscl . -read /Users/trading-router-operator UserShell | /usr/bin/awk '{print $2}')" = /usr/bin/false ] || die 'trading-router-operator login shell is not disabled'
[ "$(/usr/bin/dscl . -read /Users/trading-router-operator NFSHomeDirectory | /usr/bin/awk '{print $2}')" = /private/var/db/trading-desk-lima ] || die 'trading-router-operator home drift'
[ "$(/usr/bin/dscl . -read /Users/trading-router-operator IsHidden | /usr/bin/awk '{print $2}')" = 1 ] || die 'trading-router-operator is not hidden'
[ "$(/usr/bin/dscl . -read /Users/trading-router-operator AuthenticationAuthority | /usr/bin/cut -d ' ' -f 2-)" = ';DisabledUser;' ] || die 'trading-router-operator authentication is not disabled'
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
  config_dir=$cache_root/$config_hash
  if [ -e "$cache_root" ] || [ -L "$cache_root" ]; then
    [ -d "$cache_root" ] && [ ! -L "$cache_root" ] || die "cache root is invalid: $cache_root"
    [ "$(/usr/bin/stat -f '%u:%g:%Lp' "$cache_root")" = 0:0:755 ] || die "cache root metadata differs: $cache_root"
    no_acl "$cache_root"
    unexpected=$(/usr/bin/find "$cache_root" -mindepth 1 -maxdepth 1 ! -name "$config_hash" -print -quit)
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
adopt_cache_root "$BASE_ROOT"
adopt_cache_root "$ROOT"
/usr/sbin/chown root:wheel "$BASE_ROOT" "$BASE_ROOT/$config_hash" "$ROOT" "$ROOT/$config_hash"
/bin/chmod 0755 "$BASE_ROOT" "$BASE_ROOT/$config_hash" "$ROOT" "$ROOT/$config_hash"
[ -x "$RUNTIME_PYTHON" ] || die 'sealed admin runtime is unavailable'
RUNTIME_PYTHON=$(/bin/realpath "$RUNTIME_PYTHON")
case "$RUNTIME_PYTHON" in /opt/trading-desk/runtime/python-3.11.16/*) ;; *) die 'sealed admin runtime escapes its root' ;; esac
assert_root_sealed_directory_chain "$(/usr/bin/dirname "$RUNTIME_PYTHON")"
assert_root_sealed_regular_file "$RUNTIME_PYTHON"

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
' "$SAMPLE" "$PROBE" "$HELPER_CONFIG" "$PUBLIC_WG" "$PF_ANCHOR" "$BASE_ROOT/$config_hash/expectation.json" "$ROOT/$config_hash/expectation.json"

/bin/echo "REMOTE_VPN_HEALTH_INSTALL_COMPLETE config_hash=$config_hash"
/bin/echo 'PF remains unloaded; VM/tunnels remain unchanged; collector not started; no credential or venue operation performed.'
