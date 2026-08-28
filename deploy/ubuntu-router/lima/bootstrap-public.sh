#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# This artifact is deliberately plan-only. The separate root-sealed launcher
# owns the enabled venue-credential-free stopped-VM preparation phases.
if [ "$#" -ne 1 ] || [ "$1" != "--plan" ]; then
    printf '%s\n' 'bootstrap_apply_disabled: only --plan is accepted' >&2
    exit 64
fi

printf '%s\n' \
    'apply_enabled=false' \
    'network_changes_performed=false' \
    'packages_installed=false' \
    'host_tool_downloads_performed=false' \
    'host_tool_install_apply_enabled=true' \
    'separate_commission_apply_artifact_present=true' \
    'separate_runtime_qualification_enabled=true' \
    'separate_media_seal_apply_enabled=true' \
    'separate_host_tool_apply_enabled=true' \
    'separate_lima_home_apply_enabled=true' \
    'separate_validate_fill_apply_enabled=true' \
    'separate_vm_management_key_apply_enabled=true' \
    'separate_local_image_apply_enabled=true' \
    'separate_vm_create_apply_enabled=true' \
    'separate_vm_start_apply_enabled=false' \
    'separate_guest_mutation_apply_enabled=false' \
    'host_tool_attestation_required=true' \
    'lima_source_url=__PINNED_LIMA_SOURCE_URL__' \
    'lima_archive_sha256=__PINNED_LIMA_ARCHIVE_SHA256__' \
    'lima_attestation_repository=__PINNED_LIMA_ATTESTATION_REPOSITORY__' \
    'socket_vmnet_source_url=__PINNED_SOCKET_VMNET_SOURCE_URL__' \
    'socket_vmnet_archive_sha256=__PINNED_SOCKET_VMNET_ARCHIVE_SHA256__' \
    'socket_vmnet_attestation_repository=__PINNED_SOCKET_VMNET_ATTESTATION_REPOSITORY__' \
    'apt_install_source_status=__APT_INSTALL_SOURCE_STATUS__' \
    'apt_snapshot_url=__APT_SNAPSHOT_URL__' \
    'apt_signed_by_path=__APT_SIGNED_BY_PATH__' \
    'apt_keyring_sha256=__APT_KEYRING_SHA256_VALUE__' \
    'commission_lock_sha256=__COMMISSION_LOCK_SHA256__' \
    'immutable_public_input_verifier=commission-public.py --plan|--verify-inputs' \
    'apt_snapshot_gate_passed=false' \
    'router_keys_generated=false' \
    'venue_credentials_touched=false' \
    'evidence_status=awaiting_immutable_public_input_replay_and_guest_preflight'
__PINNED_GUEST_PACKAGE_PLAN__
