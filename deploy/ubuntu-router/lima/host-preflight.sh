#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail() {
    printf '%s\n' "host_preflight_failed: $1" >&2
    exit 1
}

lima_home=__LIMA_HOME_PATH_SHELL__
default_state=__DEFAULT_YAML_STATE_SHELL__
default_sha256=__DEFAULT_YAML_SHA256_SHELL__
override_state=__OVERRIDE_YAML_STATE_SHELL__
override_sha256=__OVERRIDE_YAML_SHA256_SHELL__
expected_networks_sha256=__NETWORKS_SHA256_SHELL__
expected_effective_sha256=__EFFECTIVE_CONFIG_SHA256_SHELL__
expected_lima_version=__PINNED_LIMA_VERSION_SHELL__
expected_limactl_sha256=__PINNED_LIMACTL_SHA256_SHELL__
expected_socket_vmnet_sha256=__PINNED_SOCKET_VMNET_SHA256_SHELL__
expected_socket_vmnet_client_sha256=__PINNED_SOCKET_VMNET_CLIENT_SHA256_SHELL__

if [ "$#" -eq 1 ] && [ "$1" = '--plan' ]; then
    printf '%s\n' \
        'apply_enabled=false' \
        "lima_home=${lima_home}" \
        'lima_home_required_mode=0700' \
        "default_yaml_state=${default_state}" \
        "override_yaml_state=${override_state}" \
        "networks_yaml_sha256=${expected_networks_sha256}" \
        "effective_config_sha256=${expected_effective_sha256}" \
        'required_validation=limactl validate --fill' \
        'evidence_status=awaiting_lima_home_and_effective_config_attestation'
    exit 0
fi

[ "$#" -eq 2 ] && [ "$1" = '--check' ] || \
    fail 'use --plan or --check /absolute/path/to/limactl'
limactl_path=$2
case "$limactl_path" in
    /*) ;;
    *) fail 'limactl path must be absolute' ;;
esac
[ -f "$limactl_path" ] && [ ! -L "$limactl_path" ] || \
    fail 'limactl must be a real regular file'
[ -x "$limactl_path" ] || fail 'limactl is not executable'
[ "$(stat -f '%l' "$limactl_path")" = 1 ] || fail 'limactl has an unsafe link count'
[ "$(stat -f '%u' "$limactl_path")" = "$(id -u)" ] || \
    fail 'limactl is not owned by the invoking operator'
[ -z "$(find "$limactl_path" -maxdepth 0 -perm +022 -print -quit)" ] || \
    fail 'limactl is group/world writable'
actual_limactl_sha256=$(shasum -a 256 "$limactl_path" | awk '{print $1}')
[ "$actual_limactl_sha256" = "$expected_limactl_sha256" ] || \
    fail 'limactl binary digest differs'
codesign --verify --strict "$limactl_path" >/dev/null 2>&1 || \
    fail 'limactl code signature is invalid'

check_root_tool() {
    tool_path=$1
    expected_sha256=$2
    tool_label=$3
    [ -f "$tool_path" ] && [ ! -L "$tool_path" ] || \
        fail "${tool_label} must be a real regular file"
    [ "$(stat -f '%l' "$tool_path")" = 1 ] || \
        fail "${tool_label} has an unsafe link count"
    [ "$(stat -f '%u' "$tool_path")" = 0 ] || \
        fail "${tool_label} is not root-owned"
    [ -z "$(find "$tool_path" -maxdepth 0 -perm +022 -print -quit)" ] || \
        fail "${tool_label} is group/world writable"
    actual_sha256=$(shasum -a 256 "$tool_path" | awk '{print $1}')
    [ "$actual_sha256" = "$expected_sha256" ] || \
        fail "${tool_label} binary digest differs"
    codesign --verify --strict "$tool_path" >/dev/null 2>&1 || \
        fail "${tool_label} code signature is invalid"
}

check_root_tool /opt/socket_vmnet/bin/socket_vmnet \
    "$expected_socket_vmnet_sha256" socket_vmnet
check_root_tool /opt/socket_vmnet/bin/socket_vmnet_client \
    "$expected_socket_vmnet_client_sha256" socket_vmnet_client

[ -d "$lima_home" ] && [ ! -L "$lima_home" ] || \
    fail 'dedicated LIMA_HOME is missing or unsafe'
[ "$(stat -f '%Lp' "$lima_home")" = 700 ] || fail 'LIMA_HOME mode is not 0700'
[ "$(stat -f '%u' "$lima_home")" = "$(id -u)" ] || \
    fail 'LIMA_HOME is not owned by the invoking operator'

config_dir="${lima_home}/_config"
[ -d "$config_dir" ] && [ ! -L "$config_dir" ] || \
    fail 'LIMA_HOME _config is missing or unsafe'
[ "$(stat -f '%Lp' "$config_dir")" = 700 ] || fail '_config mode is not 0700'
[ "$(stat -f '%u' "$config_dir")" = "$(id -u)" ] || \
    fail '_config is not owned by the invoking operator'

check_optional_config() {
    config_name=$1
    expected_state=$2
    expected_sha256=$3
    config_path="${config_dir}/${config_name}"
    if [ "$expected_state" = absent ]; then
        [ ! -e "$config_path" ] && [ ! -L "$config_path" ] || \
            fail "${config_name} must be absent"
        return
    fi
    [ "$expected_state" = sha256 ] || fail "${config_name} policy is invalid"
    [ -f "$config_path" ] && [ ! -L "$config_path" ] || \
        fail "${config_name} is not a real regular file"
    [ "$(stat -f '%l' "$config_path")" = 1 ] || \
        fail "${config_name} has an unsafe link count"
    [ "$(stat -f '%u' "$config_path")" = "$(id -u)" ] || \
        fail "${config_name} is not owned by the invoking operator"
    [ -z "$(find "$config_path" -maxdepth 0 -perm +022 -print -quit)" ] || \
        fail "${config_name} is group/world writable"
    actual_sha256=$(shasum -a 256 "$config_path" | awk '{print $1}')
    [ "$actual_sha256" = "$expected_sha256" ] || \
        fail "${config_name} digest differs"
}

check_optional_config default.yaml "$default_state" "$default_sha256"
check_optional_config override.yaml "$override_state" "$override_sha256"

networks_path="${config_dir}/networks.yaml"
[ -f "$networks_path" ] && [ ! -L "$networks_path" ] || \
    fail 'networks.yaml is not a real regular file'
[ "$(stat -f '%l' "$networks_path")" = 1 ] || \
    fail 'networks.yaml has an unsafe link count'
[ "$(stat -f '%Lp' "$networks_path")" = 600 ] || \
    fail 'networks.yaml mode is not 0600'
[ "$(stat -f '%u' "$networks_path")" = "$(id -u)" ] || \
    fail 'networks.yaml is not owned by the invoking operator'
[ -z "$(find "$networks_path" -maxdepth 0 -perm +022 -print -quit)" ] || \
    fail 'networks.yaml is group/world writable'
actual_networks_sha256=$(shasum -a 256 "$networks_path" | awk '{print $1}')
[ "$actual_networks_sha256" = "$expected_networks_sha256" ] || \
    fail 'networks.yaml digest differs'

unexpected=$(
    find "$config_dir" -mindepth 1 -maxdepth 1 \
        ! -name networks.yaml \
        ! -name default.yaml \
        ! -name override.yaml -print
)
[ -z "$unexpected" ] || fail 'unexpected LIMA_HOME global config entry exists'

case "$expected_effective_sha256" in
    REVIEW_REQUIRED_*) fail 'effective validate --fill digest is not retained' ;;
esac
reported_version=$("$limactl_path" --version)
printf '%s\n' "$reported_version" | grep -F "$expected_lima_version" >/dev/null || \
    fail 'limactl version differs from the pin'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
effective_file=$(mktemp -t trading-desk-lima-effective)
cleanup() {
    rm -f "$effective_file"
}
trap cleanup EXIT HUP INT TERM
LIMA_HOME="$lima_home" "$limactl_path" validate --fill \
    "${script_dir}/lima.yaml" > "$effective_file"
actual_effective_sha256=$(shasum -a 256 "$effective_file" | awk '{print $1}')
[ "$actual_effective_sha256" = "$expected_effective_sha256" ] || \
    fail 'effective limactl validate --fill digest differs'

printf '%s\n' \
    'host_preflight_passed=true' \
    "lima_home=${lima_home}" \
    "networks_yaml_sha256=${actual_networks_sha256}" \
    "effective_config_sha256=${actual_effective_sha256}" \
    'apply_enabled=false' \
    'evidence_status=awaiting_immutable_public_input_replay_and_vm_guest_preflight'
