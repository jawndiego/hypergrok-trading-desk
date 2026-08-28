#!/bin/sh
# Lima mode=system payload. The mode=boot hardener must have completed first.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

shutdown_armed=1
emergency_shutdown() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$shutdown_armed" = 1 ]; then
        /bin/echo 'first_boot_finalization_failed: emergency poweroff' >&2
        /usr/bin/systemctl poweroff --force --force >/dev/null 2>&1 || \
            /sbin/poweroff -f >/dev/null 2>&1 || true
    fi
    [ "$status" -ne 0 ] || status=2
    exit "$status"
}
trap emergency_shutdown 0 HUP INT TERM

STATE=/var/lib/trading-desk-router-bootstrap
EARLY_RECEIPT=$STATE/early-boot.json
RECEIPT=$STATE/first-boot.json
NFTABLES=/etc/nftables.conf
APT_PERIODIC=/etc/apt/apt.conf.d/99-trading-desk-disable-periodic
IPV6_SYSCTL=/etc/sysctl.d/99-trading-desk-bootstrap-disable-ipv6.conf
APT_UNITS='apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service'
ROUTER_KEY=/etc/wireguard/trading-desk-router.key

die() {
    /bin/echo "first_boot_finalization_failed: $*" >&2
    exit 2
}

assert_wireguard_empty() {
    if [ -e /etc/wireguard ] || [ -L /etc/wireguard ]; then
        [ -d /etc/wireguard ] && [ ! -L /etc/wireguard ] && \
            [ "$(/usr/bin/stat -c '%u:%g' /etc/wireguard)" = '0:0' ] || \
            die 'WireGuard directory is unsafe'
        directory_mode=$(/usr/bin/stat -c '%a' /etc/wireguard)
        [ $((0$directory_mode & 0022)) -eq 0 ] || \
            die 'WireGuard directory is writable'
        [ -z "$(/usr/bin/find /etc/wireguard -mindepth 1 -print -quit)" ] || \
            die 'WireGuard directory is not empty'
    fi
}

[ "$(/usr/bin/id -u)" = 0 ] && [ "$(/usr/bin/id -g)" = 0 ] || \
    die 'root:root is required'
[ "$(/usr/bin/uname -s)" = Linux ] && \
    [ "$(/usr/bin/uname -m)" = aarch64 ] || die 'Linux aarch64 is required'
[ -d "$STATE" ] && [ ! -L "$STATE" ] && \
    [ "$(/usr/bin/stat -c '%u:%g:%a' "$STATE")" = '0:0:700' ] || \
    die 'bootstrap state directory differs'
[ -f "$EARLY_RECEIPT" ] && [ ! -L "$EARLY_RECEIPT" ] && \
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' "$EARLY_RECEIPT")" = '0:0:400:1' ] || \
    die 'early-boot receipt metadata differs'
exec 9>"$STATE/.first-boot-finalize.lock"
/usr/bin/flock -n 9 || die 'first-boot finalizer lock is already held'

apt_sha=$(/usr/bin/sha256sum "$APT_PERIODIC" | /usr/bin/awk '{print $1}')
ipv6_sha=$(/usr/bin/sha256sum "$IPV6_SYSCTL" | /usr/bin/awk '{print $1}')
nft_sha=$(/usr/bin/sha256sum "$NFTABLES" | /usr/bin/awk '{print $1}')
nft_runtime_sha=$(/usr/sbin/nft --json list table inet trading_desk_bootstrap | \
    /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
early_sha=$(/usr/bin/sha256sum "$EARLY_RECEIPT" | /usr/bin/awk '{print $1}')

/usr/bin/python3 - "$EARLY_RECEIPT" "$apt_sha" "$ipv6_sha" "$nft_sha" \
    "$nft_runtime_sha" <<'EARLY_PY_EOF'
import json
from pathlib import Path
import sys

value = json.loads(Path(sys.argv[1]).read_bytes())
expected = {
    "apt_periodic_sha256": sys.argv[2],
    "apt_units_masked": [
        "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service",
        "apt-daily-upgrade.service", "unattended-upgrades.service",
    ],
    "external_airgap_verified_by_guest": False,
    "ipv6_sysctl_sha256": sys.argv[3],
    "kind": "trading-desk.router-bootstrap.early-boot",
    "mainnet_authorized": False,
    "network_reconnect_authorized": False,
    "nft_runtime_sha256": sys.argv[5],
    "nftables_sha256": sys.argv[4],
    "phase": "guest-early-boot-hardening",
    "requires_host_airgap_receipt": True,
    "router_key_present": False,
    "schema_version": 1,
    "venue_credentials_touched": False,
    "venue_writes_authorized": False,
}
if value != expected:
    raise SystemExit("early-boot receipt differs")
EARLY_PY_EOF

for unit in $APT_UNITS; do
    [ "$(/usr/bin/systemctl is-enabled "$unit" 2>/dev/null || true)" = masked ] || \
        die "APT unit is not masked: $unit"
    active=$(/usr/bin/systemctl is-active "$unit" 2>/dev/null || true)
    [ "$active" = inactive ] || [ "$active" = failed ] || \
        die "APT unit remains active: $unit"
done
[ "$(/usr/bin/systemctl is-enabled nftables.service)" = enabled ] || \
    die 'nftables service is not enabled'
/usr/bin/systemctl show nftables.service --property=Before --value | \
    /usr/bin/grep -qw network-pre.target || \
    die 'nftables is not ordered before network-pre.target'
for disable in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [ -f "$disable" ] && [ "$(/bin/cat "$disable")" = 1 ] || \
        die 'IPv6 remains enabled'
done
if /usr/bin/pgrep -x 'apt|apt-get|dpkg|unattended-upgrade' >/dev/null 2>&1; then
    die 'an APT or dpkg process remains active'
fi
package_sha=$(/usr/bin/python3 <<'PACKAGE_PY_EOF'
import fcntl
import hashlib
import os
import subprocess

descriptors = []
try:
    for path in ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"):
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        descriptors.append(descriptor)
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    audit = subprocess.run(
        ["/usr/bin/dpkg", "--audit"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=20,
        check=False,
    )
    if audit.returncode != 0 or audit.stdout or audit.stderr:
        raise SystemExit("dpkg audit is not clean")
    query = subprocess.run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\\t${db:Status-Status}\\t${Version}\\n",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=20,
        check=False,
    )
    if query.returncode != 0 or query.stderr:
        raise SystemExit("dpkg-query failed")
    print(hashlib.sha256(b"".join(sorted(query.stdout.splitlines(keepends=True)))).hexdigest())
finally:
    for descriptor in descriptors:
        os.close(descriptor)
PACKAGE_PY_EOF
) || die 'package-state lock/audit failed'

/usr/sbin/usermod --lock root
/usr/sbin/usermod --lock routeradmin
for account in root routeradmin; do
    password=$(/usr/bin/awk -F: -v account="$account" \
        '$1 == account { print $2 }' /etc/shadow)
    case "$password" in '!'*|'*'*) ;; *) die "$account password is not locked";; esac
done

assert_wireguard_empty
/usr/bin/python3 - "$RECEIPT" "$early_sha" "$apt_sha" "$ipv6_sha" \
    "$nft_sha" "$nft_runtime_sha" "$package_sha" <<'FINAL_PY_EOF'
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
value = {
    "account_passwords_locked": ["root", "routeradmin"],
    "apt_periodic_sha256": sys.argv[3],
    "apt_units_masked": [
        "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service",
        "apt-daily-upgrade.service", "unattended-upgrades.service",
    ],
    "dpkg_audit_clean": True,
    "early_boot_receipt_sha256": sys.argv[2],
    "external_airgap_verified_by_guest": False,
    "ipv6_sysctl_sha256": sys.argv[4],
    "kind": "trading-desk.router-bootstrap.first-boot",
    "mainnet_authorized": False,
    "network_reconnect_authorized": False,
    "nft_runtime_sha256": sys.argv[6],
    "nftables_sha256": sys.argv[5],
    "package_state_sha256": sys.argv[7],
    "passwordless_sudo_bootstrap_still_enabled": True,
    "phase": "guest-first-boot-hardening",
    "requires_host_airgap_receipt": True,
    "router_key_present": False,
    "schema_version": 1,
    "venue_credentials_touched": False,
    "venue_writes_authorized": False,
}
content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
pending = path.parent / f".{path.name}.pending"

def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("zero-length receipt write")
        view = view[written:]

if path.exists() or path.is_symlink():
    if path.is_symlink() or path.read_bytes() != content:
        raise SystemExit("existing first-boot receipt differs")
elif pending.exists() or pending.is_symlink():
    if pending.is_symlink() or pending.read_bytes() != content:
        raise SystemExit("pending first-boot receipt differs")
else:
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        write_all(fd, content)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)
if not path.exists():
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(pending), -100, os.fsencode(path), 1) != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise SystemExit("first-boot receipt destination exists")
        raise OSError(number, os.strerror(number))
metadata = path.lstat()
if (metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o777, metadata.st_nlink) != (0, 0, 0o400, 1):
    raise SystemExit("first-boot receipt metadata differs")
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(f"first_boot_receipt={path}")
print(f"first_boot_receipt_sha256={hashlib.sha256(content).hexdigest()}")
FINAL_PY_EOF

verifier=/usr/local/libexec/trading-desk-verify-first-boot
[ -f "$verifier" ] && [ ! -L "$verifier" ] && \
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' "$verifier")" = '0:0:500:1' ] && \
    [ "$(/usr/bin/sha256sum "$verifier" | /usr/bin/awk '{print $1}')" = \
        '__VERIFY_FIRST_BOOT_SHA256__' ] || die 'root verifier differs'
"$verifier"
shutdown_armed=0
trap - 0 HUP INT TERM
/bin/echo 'network_reconnect_authorized=false'
/bin/echo 'passwordless_sudo_bootstrap_still_enabled=true'
/bin/echo 'router_key_present=false'
