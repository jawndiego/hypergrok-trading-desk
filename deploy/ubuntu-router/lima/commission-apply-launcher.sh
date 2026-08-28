#!/bin/sh
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

die() {
    /bin/echo "router_commission_launcher_failed: $*" >&2
    exit 2
}

assert_root_chain() {
    current=$1
    while :; do
        [ -e "$current" ] && [ ! -L "$current" ] || \
            die "sealed ancestor missing or symlinked: $current"
        [ "$(/usr/bin/stat -f %u "$current")" = 0 ] || \
            die "sealed ancestor is not root-owned: $current"
        [ -z "$(/usr/bin/find "$current" -maxdepth 0 -perm +022 -print -quit)" ] || \
            die "sealed ancestor is group/world writable: $current"
        acl=$(/bin/ls -led "$current" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
        [ -z "$acl" ] || die "sealed ancestor has a named ACL: $current"
        [ "$current" = / ] && break
        current=$(/usr/bin/dirname "$current")
    done
}

[ "$(/usr/bin/id -u)" = 0 ] && [ "$(/usr/bin/id -g)" = 0 ] || \
    die 'root apply launcher requires root:wheel'
case "$0" in /*) ;; *) die 'launcher path must be absolute' ;; esac
[ ! -L "$0" ] || die 'launcher symlink rejected'
launcher=$(/bin/realpath "$0")
[ "$launcher" = "$0" ] || die 'launcher path or ancestor is noncanonical'
controller=$(/usr/bin/dirname "$launcher")
script=$controller/commission-apply.py
runtime=/opt/trading-desk/runtime/python-3.11.16
python=$runtime/bin/python3.11
otool=/Library/Developer/CommandLineTools/usr/bin/llvm-otool
expected_python_sha256=b1e82855accbd41dc26f83a8722b3cdc745fb23484cfc645823bc8446144aa0f
expected_otool_sha256=61ff2c63cf68eeeadf9c4700dadb8271740ff4960f98500f30db82b31521c0de

ROOT_APPLY_ENABLED=1
if [ "$ROOT_APPLY_ENABLED" != 1 ]; then
    /bin/echo 'root_apply_enabled=false'
    /bin/echo 'blocker=sealed Python runtime lacks a pre-exec symlink and dynamic-library closure proof'
    exit 64
fi

for path in "$launcher" "$script" "$controller" "$runtime" "$python"; do
    [ -e "$path" ] && [ ! -L "$path" ] || die "sealed path missing or symlinked: $path"
    [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "sealed path is not root-owned: $path"
    [ -z "$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)" ] || \
        die "sealed path is group/world writable: $path"
    acl=$(/bin/ls -led "$path" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
    [ -z "$acl" ] || die "sealed path has a named ACL: $path"
done
[ -x "$python" ] || die 'sealed Python is not executable'
[ -f "$script" ] || die 'commission Python controller is not a regular file'
assert_root_chain "$controller"
assert_root_chain "$runtime"

first_nonroot=$(/usr/bin/find "$runtime" ! -user root -print -quit)
[ -z "$first_nonroot" ] || die "sealed Python tree has non-root owner: $first_nonroot"
first_writable=$(/usr/bin/find "$runtime" ! -type l -perm +022 -print -quit)
[ -z "$first_writable" ] || die "sealed Python tree is group/world writable: $first_writable"
first_acl=$(/usr/bin/find "$runtime" -acl -print -quit)
[ -z "$first_acl" ] || die "sealed Python tree has a named ACL: $first_acl"

escaped_link=$(
    /usr/bin/find "$runtime" -type l -exec /bin/sh -eu -c '
        runtime=$1
        shift
        for path do
            resolved=$(/bin/realpath "$path")
            case "$resolved" in
                "$runtime"/*) ;;
                *) /bin/echo "$path"; exit 0 ;;
            esac
        done
    ' sh "$runtime" {} +
)
[ -z "$escaped_link" ] || die "sealed Python symlink escapes its root: $escaped_link"
[ "$(/usr/bin/shasum -a 256 "$python" | /usr/bin/awk '{print $1}')" = \
    "$expected_python_sha256" ] || die 'sealed Python executable digest differs'
[ -f "$otool" ] && [ ! -L "$otool" ] || die 'pinned llvm-otool is unavailable'
assert_root_chain "$otool"
[ "$(/usr/bin/stat -f '%u:%g:%Lp:%l' "$otool")" = '0:0:755:1' ] || \
    die 'pinned llvm-otool metadata differs'
[ "$(/usr/bin/shasum -a 256 "$otool" | /usr/bin/awk '{print $1}')" = \
    "$expected_otool_sha256" ] || die 'pinned llvm-otool digest differs'
/usr/bin/codesign --verify --strict --test-requirement '=anchor apple' "$otool" \
    >/dev/null 2>&1 || die 'pinned llvm-otool signature differs'
python_loads=$(
    "$otool" -L "$python" | /usr/bin/sed '1d' | /usr/bin/awk '{print $1}' | \
        LC_ALL=C /usr/bin/sort
)
[ "$python_loads" = '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
/usr/lib/libSystem.B.dylib' ] || die 'sealed Python direct load closure differs'
if "$otool" -l "$python" | /usr/bin/grep -Fq 'LC_RPATH'; then
    die 'sealed Python has an unexpected runtime search path'
fi

case "${1-}" in
    qualify-runtime|apply-seal-media|apply-host-tools|apply-lima-home|apply-validate-fill|quarantine-incomplete) ;;
    *) die 'launcher accepts only reviewed host-preparation phases' ;;
esac

exec /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C LC_ALL=C \
    "$python" -I -B "$script" "$@"
