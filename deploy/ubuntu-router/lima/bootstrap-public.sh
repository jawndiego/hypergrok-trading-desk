#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# This artifact is deliberately plan-only. A later reviewed commissioning step
# must implement installation after image, package, host, and effective Lima
# configuration evidence has been retained.
if [ "$#" -ne 1 ] || [ "$1" != "--plan" ]; then
    printf '%s\n' 'bootstrap_apply_disabled: only --plan is accepted' >&2
    exit 64
fi

printf '%s\n' \
    'apply_enabled=false' \
    'network_changes_performed=false' \
    'packages_installed=false' \
    'apt_install_source_status=__APT_INSTALL_SOURCE_STATUS__' \
    'router_keys_generated=false' \
    'venue_credentials_touched=false' \
    'evidence_status=awaiting_signed_apt_snapshot_and_guest_package_install'
__PINNED_GUEST_PACKAGE_PLAN__
