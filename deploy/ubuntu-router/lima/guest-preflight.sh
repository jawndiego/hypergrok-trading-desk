#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

fail() {
    printf '%s\n' "guest_preflight_failed: $1" >&2
    exit 1
}

mode=${1---pre-key}
[ "$#" -le 1 ] || fail 'only one qualification mode is accepted'
case "$mode" in
    --pre-key|--post-netplan) ;;
    *) fail 'mode must be --pre-key or --post-netplan' ;;
esac
[ "$(uname -m)" = 'aarch64' ] || fail 'guest architecture is not aarch64'
grep -qx 'ID=ubuntu' /etc/os-release || fail 'guest OS is not Ubuntu'
grep -Eq '^VERSION_ID="?24\.04"?$' /etc/os-release || fail 'guest release is not 24.04'

actual_interfaces=$(
    for path in /sys/class/net/*; do
        name=${path##*/}
        [ "$name" = 'lo' ] || printf '%s\n' "$name"
    done | LC_ALL=C sort
)
interface_count=$(printf '%s\n' "$actual_interfaces" | sed '/^$/d' | wc -l | tr -d ' ')
[ "$interface_count" = 2 ] || fail 'guest must expose exactly two non-loopback interfaces'

check_mac() {
    interface_name=$1
    expected_mac=$2
    [ -r "/sys/class/net/${interface_name}/address" ] || fail "missing interface ${interface_name}"
    actual_mac=$(cat "/sys/class/net/${interface_name}/address")
    [ "$actual_mac" = "$expected_mac" ] || fail "MAC mismatch for ${interface_name}"
}

check_mac __INGRESS_INTERFACE_SHELL__ __INGRESS_MAC_SHELL__

wan_interface=$(
    printf '%s\n' "$actual_interfaces" |
        awk -v ingress=__INGRESS_INTERFACE_SHELL__ '$0 != ingress { print }'
)
[ -n "$wan_interface" ] || fail 'WAN interface was not discovered'
[ "$(printf '%s\n' "$wan_interface" | wc -l | tr -d ' ')" = 1 ] || \
    fail 'WAN interface discovery was ambiguous'
[ -r "/sys/class/net/${wan_interface}/address" ] || fail 'WAN MAC is unavailable'
wan_mac=$(cat "/sys/class/net/${wan_interface}/address")
printf '%s\n' "$wan_mac" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' || \
    fail 'WAN MAC is not canonical'

default_routes=$(ip -4 route show default)
[ "$(printf '%s\n' "$default_routes" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || \
    fail 'exactly one IPv4 default route is required'
default_route_interface=$(printf '%s\n' "$default_routes" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
[ "$default_route_interface" = "$wan_interface" ] || \
    fail 'IPv4 default route does not use the discovered WAN'
default_route_gateway=$(printf '%s\n' "$default_routes" | awk '{for (i=1;i<=NF;i++) if ($i=="via") print $(i+1)}')
[ -n "$default_route_gateway" ] || fail 'IPv4 default route gateway is absent'
printf '%s\n' "$default_route_gateway" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || \
    fail 'IPv4 default route gateway is not canonical'

command -v findmnt >/dev/null 2>&1 || fail 'findmnt is unavailable'
if findmnt -rn -t 9p,virtiofs,fuse.sshfs >/dev/null 2>&1; then
    fail 'host filesystem mount detected'
fi

for variable_name in \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy \
    SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSLKEYLOGFILE \
    SSH_AUTH_SOCK
do
    variable_value=$(printenv "$variable_name" 2>/dev/null || true)
    [ -z "$variable_value" ] || fail "ambient override is set: ${variable_name}"
done

ipv6_default_routes=$(ip -6 route show default)
[ -z "$ipv6_default_routes" ] || fail 'IPv6 default route detected'
ipv6_global_routes=$(ip -6 route show scope global)
[ -z "$ipv6_global_routes" ] || fail 'IPv6 global route detected'

check_package() {
    package_name=$1
    expected_version=$2
    actual_record=$(dpkg-query -W -f='${Status}\t${Version}' "$package_name" 2>/dev/null) || \
        fail "required package is absent: ${package_name}"
    expected_record=$(printf 'install ok installed\t%s' "$expected_version")
    [ "$actual_record" = "$expected_record" ] || \
        fail "package status/version mismatch: ${package_name}"
}

__PINNED_GUEST_PACKAGE_CHECKS__

archive_keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[ -f "$archive_keyring" ] && [ ! -L "$archive_keyring" ] || \
    fail 'Ubuntu archive keyring is missing or unsafe'
[ "$(stat -c '%u' "$archive_keyring")" = 0 ] || \
    fail 'Ubuntu archive keyring is not root-owned'
[ "$(stat -c '%h' "$archive_keyring")" = 1 ] || \
    fail 'Ubuntu archive keyring has an unsafe link count'
actual_keyring_sha256=$(sha256sum "$archive_keyring" | awk '{print $1}')
[ "$actual_keyring_sha256" = __APT_KEYRING_SHA256_SHELL__ ] || \
    fail 'Ubuntu archive keyring digest differs from the pin'

expected_kernel=__RUNNING_KERNEL_RELEASE_SHELL__
running_kernel=$(uname -r)
[ "$running_kernel" = "$expected_kernel" ] || \
    fail 'running kernel differs from the reboot-qualified pin'
check_package "linux-image-${running_kernel}" __RUNNING_KERNEL_PACKAGE_VERSION_SHELL__

[ ! -e /etc/wireguard/trading-desk-router.key ] || \
    fail 'router key already exists during pre-key qualification'

if [ "$mode" = '--post-netplan' ]; then
    ip link show dev __INGRESS_INTERFACE_SHELL__ | \
        grep -Eq '<([^>,]+,)*UP(,[^>,]+)*>' || fail 'ingress link is not up'
    observed_ingress_ipv4=$(
        ip -o -4 address show dev __INGRESS_INTERFACE_SHELL__ |
            awk '{print $4}' | LC_ALL=C sort
    )
    [ "$observed_ingress_ipv4" = '__INGRESS_STATIC_CIDR_VALUE__' ] || \
        fail 'post-netplan ingress IPv4 set differs from the exact static address'
    ingress_address_line="observed_ingress_static_cidr=__INGRESS_STATIC_CIDR_VALUE__"
    evidence_status=awaiting_router_keys
else
    ingress_address_line="planned_ingress_static_cidr=__INGRESS_STATIC_CIDR_VALUE__"
    evidence_status=awaiting_router_spec_and_keys
fi

printf '%s\n' \
    'guest_preflight_passed=true' \
    'network_interface_count=2' \
    'ingress_interface=__INGRESS_INTERFACE_VALUE__' \
    'ingress_mac=__INGRESS_MAC_VALUE__' \
    "$ingress_address_line" \
    "wan_interface=${wan_interface}" \
    "wan_mac=${wan_mac}" \
    "wan_default_route_gateway=${default_route_gateway}" \
    'shared_mounts_detected=false' \
    "running_kernel_release=${running_kernel}" \
    'router_key_present=false' \
    "evidence_status=${evidence_status}"
