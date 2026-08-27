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

ROOT_APPLY_ENABLED=0
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

case "${1-}" in
    apply-seal-media|apply-host-tools|quarantine-incomplete) ;;
    *) die 'launcher accepts only reviewed root media/host/quarantine phases' ;;
esac

exec /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C LC_ALL=C \
    "$python" -I -B "$script" "$@"
