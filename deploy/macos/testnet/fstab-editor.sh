#!/bin/sh
set -eu
umask 077

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || die "vifs editor requires exactly one target"
target=$1
candidate=${TRADING_DESK_FSTAB_CANDIDATE-}
expected=${TRADING_DESK_FSTAB_EXPECTED_SHA256-}

[ -n "$candidate" ] || die "candidate path is missing"
[ -n "$expected" ] || die "expected digest is missing"
[ -f "$candidate" ] || die "candidate is not a regular file"
[ ! -L "$candidate" ] || die "candidate symlink rejected"
[ -f "$target" ] || die "vifs target is not a regular file"
[ ! -L "$target" ] || die "vifs target symlink rejected"

actual=$(/usr/bin/openssl dgst -sha256 "$target" | /usr/bin/awk '{print $2}')
[ "$actual" = "$expected" ] || die "fstab changed before the locked edit"

/bin/cp "$candidate" "$target"
copied=$(/usr/bin/openssl dgst -sha256 "$target" | /usr/bin/awk '{print $2}')
wanted=$(/usr/bin/openssl dgst -sha256 "$candidate" | /usr/bin/awk '{print $2}')
[ "$copied" = "$wanted" ] || die "vifs candidate copy mismatch"
