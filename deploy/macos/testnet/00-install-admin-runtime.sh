#!/bin/sh
set -eu
umask 077

EXPECTED_SHA256=8d385a77e67d31ddd3bff6582e60f8cc6385188dfff3c84108e7ea080a0af74f
EXPECTED_OTOOL_SHA256=61ff2c63cf68eeeadf9c4700dadb8271740ff4960f98500f30db82b31521c0de
OTOOL=/Library/Developer/CommandLineTools/usr/bin/llvm-otool
FINAL=/opt/trading-desk/runtime/python-3.11.16
RUNTIME_PARENT=/opt/trading-desk/runtime
STAGE=/opt/trading-desk/.runtime-stage-python-3.11.16
RECEIPT_PARENT=/opt/trading-desk/runtime-install-receipts

script_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd)
archive=$script_dir/runtime/python-3.11.16-macos-arm64-root.tar.gz

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

assert_no_acl() {
  path=$1
  entries=$(/bin/ls -led "$path" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
  [ -z "$entries" ] || die "unexpected ACL on $path"
}

case "${1-plan}" in
  --apply) mode=apply ;;
  --resume-after-load-scan) mode=resume ;;
  plan)
    [ "$#" -eq 0 ] || die "plan takes no arguments"
    mode=plan
    ;;
  *) die "use --apply or --resume-after-load-scan" ;;
esac

if [ "$mode" = plan ]; then
  /bin/echo 'PLAN_ONLY'
  /bin/echo "Install the hash-pinned Python 3.11.16/OpenSSL 3.5.8 runtime at $FINAL."
  /bin/echo "Require direct Apple CLT llvm-otool sha256=$EXPECTED_OTOOL_SHA256."
  /bin/echo 'Run only the sealed, root-owned copy with --apply; no service is started.'
  /bin/echo 'A retained exact stage from the historical header-scan failure may use --resume-after-load-scan.'
  exit 0
fi

[ "$(/usr/bin/id -u)" -eq 0 ] || die "run as root"
[ "$(/usr/bin/id -u trading-research)" = 450 ] || die "trading-research UID drift"
[ "$(/usr/bin/id -u trading-executor)" = 451 ] || die "trading-executor UID drift"
[ "$(/usr/bin/id -u trading-control)" = 452 ] || die "trading-control UID drift"
[ "$(/usr/bin/id -nu 501)" = jawndiego ] || die "agent/admin UID 501 drift"
[ ! -L "$0" ] || die "script symlink rejected"
script_path=$(/bin/realpath "$0")
sealed_dir=$(/usr/bin/dirname "$script_path")
[ "$(/usr/bin/stat -f %u "$script_path")" = 0 ] || die "script must be root-owned"
[ "$(/usr/bin/stat -f %u "$sealed_dir")" = 0 ] || die "script directory must be root-owned"
first_writable=$(/usr/bin/find "$script_path" "$sealed_dir" -maxdepth 0 -perm +022 -print -quit)
[ -z "$first_writable" ] || die "script or directory is group/world writable: $first_writable"

[ -f "$OTOOL" ] && [ ! -L "$OTOOL" ] && [ -x "$OTOOL" ] || die "direct CLT llvm-otool unavailable"
[ "$(/bin/realpath "$OTOOL")" = "$OTOOL" ] || die "direct CLT llvm-otool path is non-canonical"
[ "$(/usr/bin/stat -f %u "$OTOOL")" = 0 ] || die "direct CLT llvm-otool is not root-owned"
[ "$(/usr/bin/stat -f %g "$OTOOL")" = 0 ] || die "direct CLT llvm-otool group is not wheel"
[ "$(/usr/bin/stat -f %l "$OTOOL")" = 1 ] || die "hard-linked direct CLT llvm-otool rejected"
otool_writable=$(/usr/bin/find "$OTOOL" -maxdepth 0 -perm +022 -print -quit)
[ -z "$otool_writable" ] || die "direct CLT llvm-otool is group/world writable"
assert_no_acl "$OTOOL"
[ "$(/usr/bin/openssl dgst -sha256 "$OTOOL" | /usr/bin/awk '{print $2}')" = "$EXPECTED_OTOOL_SHA256" ] || die "direct CLT llvm-otool SHA-256 mismatch"
/usr/bin/codesign --verify --strict --test-requirement '=anchor apple' "$OTOOL" || die "direct CLT llvm-otool Apple signature invalid"

[ ! -e "$FINAL" ] || die "final runtime path already exists: $FINAL"
[ -d /opt/trading-desk ] || die "missing /opt/trading-desk"
[ ! -L /opt/trading-desk ] || die "/opt/trading-desk symlink rejected"
[ "$(/usr/bin/stat -f %u /opt/trading-desk)" = 0 ] || die "/opt/trading-desk is not root-owned"
assert_no_acl /opt/trading-desk
parent_writable=$(/usr/bin/find /opt/trading-desk -maxdepth 0 -perm +022 -print -quit)
[ -z "$parent_writable" ] || die "/opt/trading-desk is group/world writable"

if [ -e "$RUNTIME_PARENT" ]; then
  [ -d "$RUNTIME_PARENT" ] || die "runtime parent is not a directory"
  [ ! -L "$RUNTIME_PARENT" ] || die "runtime parent symlink rejected"
  [ "$(/usr/bin/stat -f %u "$RUNTIME_PARENT")" = 0 ] || die "runtime parent is not root-owned"
  assert_no_acl "$RUNTIME_PARENT"
else
  /bin/mkdir "$RUNTIME_PARENT"
fi
/usr/sbin/chown root:wheel "$RUNTIME_PARENT"
/bin/chmod 0755 "$RUNTIME_PARENT"

if [ "$mode" = apply ]; then
  [ -f "$archive" ] || die "missing runtime archive: $archive"
  [ ! -L "$archive" ] || die "runtime archive symlink rejected"
  [ "$(/usr/bin/stat -f %u "$archive")" = 0 ] || die "runtime archive must be root-owned"
  archive_writable=$(/usr/bin/find "$archive" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$archive_writable" ] || die "runtime archive is group/world writable"
  actual_sha=$(/usr/bin/openssl dgst -sha256 "$archive" | /usr/bin/awk '{print $2}')
  [ "$actual_sha" = "$EXPECTED_SHA256" ] || die "runtime archive SHA-256 mismatch"
  [ ! -e "$STAGE" ] || die "runtime staging path already exists: $STAGE"
  /bin/mkdir "$STAGE"
  /usr/bin/tar -xzf "$archive" -C "$STAGE"
else
  [ -d "$STAGE" ] && [ ! -L "$STAGE" ] || die "retained runtime stage is unavailable"
  [ "$(/usr/bin/stat -f %u "$STAGE")" = 0 ] || die "retained runtime stage is not root-owned"
  [ "$(/usr/bin/stat -f %g "$STAGE")" = 0 ] || die "retained runtime stage group differs"
  [ "$(/usr/bin/stat -f %Lp "$STAGE")" = 700 ] || die "retained runtime stage mode differs"
  assert_no_acl "$STAGE"
fi
candidate=$STAGE/opt/trading-desk/runtime/python-3.11.16
[ -x "$candidate/bin/python3.11" ] || die "archive lacks expected Python executable"

/usr/sbin/chown -R root:wheel "$candidate"
/bin/chmod -R a+rX,go-w "$candidate"
first_nonroot=$(/usr/bin/find "$candidate" ! -user root -print -quit)
[ -z "$first_nonroot" ] || die "candidate contains non-root-owned path: $first_nonroot"
first_writable=$(/usr/bin/find "$candidate" -perm +022 -print -quit)
[ -z "$first_writable" ] || die "candidate contains group/world-writable path: $first_writable"

/usr/bin/find "$candidate" -type l -print | while IFS= read -r runtime_link
do
  target=$(/usr/bin/readlink "$runtime_link")
  case "$target" in
    /*) die "absolute runtime symlink rejected: $runtime_link" ;;
  esac
done

prior_otool_log=$STAGE/otool.log
otool_log=$STAGE/otool.payload.log
if [ "$mode" = resume ]; then
  [ -f "$prior_otool_log" ] && [ ! -L "$prior_otool_log" ] || die "retained otool log is unavailable"
  [ "$(/usr/bin/stat -f %u "$prior_otool_log")" = 0 ] || die "retained otool log owner differs"
  [ "$(/usr/bin/stat -f %l "$prior_otool_log")" = 1 ] || die "retained otool log link count differs"
else
  [ ! -e "$prior_otool_log" ] || die "unexpected prior otool log"
fi
[ ! -e "$otool_log" ] || die "unexpected payload-only otool log"
/usr/bin/find "$candidate" -type f \( -perm -111 -o -name '*.so' -o -name '*.dylib' \) -print | \
  while IFS= read -r binary
  do
    if /usr/bin/file "$binary" | /usr/bin/grep -q 'Mach-O'; then
      # Both otool modes print the inspected filename as line one.  That path
      # necessarily contains the staging prefix and is not a Mach-O load path.
      # Scan only the dependency/load-command payload below each header.
      "$OTOOL" -L "$binary" | /usr/bin/sed '1d'
      "$OTOOL" -l "$binary" | /usr/bin/sed '1d'
    fi
  done > "$otool_log"
if /usr/bin/grep -E '/Users/|/opt/homebrew|\.runtime-stage' "$otool_log" >/dev/null
then
  die "runtime contains a forbidden load path"
fi

if [ -e "$RECEIPT_PARENT" ]; then
  [ -d "$RECEIPT_PARENT" ] && [ ! -L "$RECEIPT_PARENT" ] || die "runtime receipt parent is invalid"
  [ "$(/usr/bin/stat -f %u "$RECEIPT_PARENT")" = 0 ] || die "runtime receipt parent owner differs"
  assert_no_acl "$RECEIPT_PARENT"
else
  /bin/mkdir -m 0755 "$RECEIPT_PARENT"
  /usr/sbin/chown root:wheel "$RECEIPT_PARENT"
fi
payload_receipt=$RECEIPT_PARENT/python-3.11.16-otool-payload.log
rejected_receipt=$RECEIPT_PARENT/python-3.11.16-rejected-header-scan.log
[ ! -e "$payload_receipt" ] || die "runtime payload receipt already exists"
if [ "$mode" = resume ]; then
  [ ! -e "$rejected_receipt" ] || die "runtime rejected-scan receipt already exists"
  /bin/mv "$prior_otool_log" "$rejected_receipt"
  /bin/chmod 0400 "$rejected_receipt"
  /usr/sbin/chown root:wheel "$rejected_receipt"
fi
/bin/mv "$otool_log" "$payload_receipt"
/bin/chmod 0400 "$payload_receipt"
/usr/sbin/chown root:wheel "$payload_receipt"

/bin/mv "$candidate" "$FINAL"
/bin/rmdir "$STAGE/opt/trading-desk/runtime" "$STAGE/opt/trading-desk" "$STAGE/opt"
/bin/rmdir "$STAGE"

/usr/bin/find "$FINAL" -type l -print | while IFS= read -r runtime_link
do
  resolved=$(/bin/realpath "$runtime_link")
  case "$resolved" in
    "$FINAL"/*) ;;
    *) die "installed runtime symlink escapes its root: $runtime_link" ;;
  esac
done

clean_path="$FINAL/bin:/usr/bin:/bin:/usr/sbin:/sbin"
/usr/bin/env -i PATH="$clean_path" LANG=C LC_ALL=C \
  "$FINAL/bin/python3.11" -I -c \
  'import pathlib,sqlite3,ssl,sys; assert sys.version_info[:3] == (3,11,16); assert sys.prefix == "/opt/trading-desk/runtime/python-3.11.16"; assert ssl.OPENSSL_VERSION.startswith("OpenSSL 3.5.8 "); p=ssl.get_default_verify_paths(); assert p.cafile == "/etc/ssl/cert.pem" and pathlib.Path(p.cafile).is_file(); print(sys.version); print(ssl.OPENSSL_VERSION); print(sqlite3.sqlite_version); print(p.cafile)'

smoke_root=$(/usr/bin/mktemp -d /private/tmp/trading-runtime-venv.XXXXXX)
case "$smoke_root" in
  /private/tmp/trading-runtime-venv.*) ;;
  *) die "unexpected smoke directory: $smoke_root" ;;
esac
/usr/bin/env -i PATH="$clean_path" LANG=C LC_ALL=C \
  "$FINAL/bin/python3.11" -I -m venv "$smoke_root/venv"
"$smoke_root/venv/bin/python" -I -c 'import ssl,sys; assert sys.version_info[:3] == (3,11,16); print(ssl.OPENSSL_VERSION)'
/bin/rm -rf "$smoke_root"

if /usr/bin/sudo -n -u '#501' -- /bin/test -w "$FINAL/bin/python3.11"
then
  die "agent/admin login UID 501 can write the runtime without elevation"
else
  uid501_probe_status=$?
  [ "$uid501_probe_status" = 1 ] || die "agent/admin runtime write probe failed"
fi
if /usr/bin/sudo -n -u trading-executor -- /bin/test -w "$FINAL"
then
  die "executor identity can write the runtime"
else
  executor_probe_status=$?
  [ "$executor_probe_status" = 1 ] || die "executor runtime write probe failed"
fi

/bin/echo "RUNTIME_INSTALL_COMPLETE sha256=$EXPECTED_SHA256 otool_sha256=$EXPECTED_OTOOL_SHA256"
/bin/echo "RUNTIME_LOAD_SCAN_RECEIPT $payload_receipt"
/bin/echo 'No application, config, credential, database, launchd service, or venue operation was performed.'
