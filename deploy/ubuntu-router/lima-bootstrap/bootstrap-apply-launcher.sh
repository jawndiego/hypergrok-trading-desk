#!/bin/sh
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

die() {
    /bin/echo "router_bootstrap_launcher_failed: $*" >&2
    exit 2
}

assert_root_chain() {
    current=$1
    while :; do
        [ -e "$current" ] && [ ! -L "$current" ] || die "unsafe ancestor: $current"
        [ "$(/usr/bin/stat -f %u "$current")" = 0 ] || die "non-root ancestor: $current"
        [ -z "$(/usr/bin/find "$current" -maxdepth 0 -perm +022 -print -quit)" ] || \
            die "writable ancestor: $current"
        acl=$(/bin/ls -led "$current" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
        [ -z "$acl" ] || die "named ACL on ancestor: $current"
        [ "$current" = / ] && break
        current=$(/usr/bin/dirname "$current")
    done
}

[ "$(/usr/bin/id -u):$(/usr/bin/id -g)" = 0:0 ] || die 'root:wheel is required'
case "$0" in /*) ;; *) die 'launcher path must be absolute' ;; esac
[ ! -L "$0" ] || die 'launcher symlink rejected'
launcher=$(/bin/realpath "$0")
[ "$launcher" = "$0" ] || die 'launcher path is noncanonical'
controller=$(/usr/bin/dirname "$launcher")
case "${1-}" in
    recover-interrupted-first-boot) script=$controller/interrupted-recovery.py ;;
    apply-hardened-vm|check-airgap|apply-airgapped-first-boot|verify-stopped-after-airgap|recover-failed-prestart|recover-proven-preboot) script=$controller/bootstrap-apply.py ;;
    *) die 'launcher accepts only reviewed stopped-create/airgap phases' ;;
esac
runtime=/opt/trading-desk/runtime/python-3.11.16
python=$runtime/bin/python3.11
otool=/Library/Developer/CommandLineTools/usr/bin/llvm-otool

for path in "$launcher" "$script" "$controller" "$runtime" "$python"; do
    [ -e "$path" ] && [ ! -L "$path" ] || die "sealed path missing: $path"
    [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || die "sealed path owner differs: $path"
    [ -z "$(/usr/bin/find "$path" -maxdepth 0 -perm +022 -print -quit)" ] || \
        die "sealed path is writable: $path"
    acl=$(/bin/ls -led "$path" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
    [ -z "$acl" ] || die "sealed path has named ACL: $path"
done
assert_root_chain "$controller"
assert_root_chain "$runtime"
[ -x "$python" ] || die 'sealed Python is not executable'
[ -f "$script" ] || die 'bootstrap controller is not a regular file'
[ -z "$(/usr/bin/find "$runtime" ! -user root -print -quit)" ] || \
    die 'sealed Python tree owner differs'
[ -z "$(/usr/bin/find "$runtime" ! -type l -perm +022 -print -quit)" ] || \
    die 'sealed Python tree is writable'
[ -z "$(/usr/bin/find "$runtime" -acl -print -quit)" ] || \
    die 'sealed Python tree has a named ACL'
[ "$(/usr/bin/shasum -a 256 "$python" | /usr/bin/awk '{print $1}')" = \
    b1e82855accbd41dc26f83a8722b3cdc745fb23484cfc645823bc8446144aa0f ] || \
    die 'sealed Python digest differs'
[ "$(/usr/bin/shasum -a 256 "$otool" | /usr/bin/awk '{print $1}')" = \
    61ff2c63cf68eeeadf9c4700dadb8271740ff4960f98500f30db82b31521c0de ] || \
    die 'llvm-otool digest differs'
/usr/bin/codesign --verify --strict --test-requirement '=anchor apple' "$otool" \
    >/dev/null 2>&1 || die 'llvm-otool signature differs'
loads=$("$otool" -L "$python" | /usr/bin/sed '1d' | /usr/bin/awk '{print $1}' | LC_ALL=C /usr/bin/sort)
[ "$loads" = '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
/usr/lib/libSystem.B.dylib' ] || die 'sealed Python load closure differs'

exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
    "$python" -I -B "$script" "$@"
