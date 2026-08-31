# Attended air-gap bootstrap continuation

This continuation consumes only the commissioned receipt-07 VM whose digest is
`1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601`.
Its first phase retained that never-booted instance and created a hardened
replacement that remains stopped. Receipt 08 is
`8ea55aa7a05534b91e40d42e70034162575f2dae3d568be06f6c8433ee1d39b6`.
The second phase permits one attended, physically air-gapped first boot and
returns the VM to `Stopped`. Neither phase accesses credentials or a venue.

Render and replay-check as the desktop operator:

```sh
python3 scripts/render_ubuntu_router_bootstrap.py \
  --hardware-profile /absolute/gitignored/airgap-hardware-profile.json \
  --output-dir /absolute/new/review-directory

manifest_sha256=$(shasum -a 256 \
  /absolute/new/review-directory/bundle-manifest.json | awk '{print $1}')

python3 scripts/render_ubuntu_router_bootstrap.py \
  --hardware-profile /absolute/gitignored/airgap-hardware-profile.json \
  --check-bundle /absolute/new/review-directory \
  --expected-manifest-sha256 "$manifest_sha256" \
  --require-owner-uid 501
```

The real profile is host-local and ignored by Git because it contains interface
MAC addresses and exact inert-utun link-local identities. The committed
`.example` is not a usable profile. Profiled inert utuns do not authorize
Internet reachability: only their exact scoped IPv6 defaults are accepted,
and the global IPv6 route/NWI probes must still prove no externally reachable
interface. During the host-only phase, only exact local `bridge100`
reachability at `192.168.106.1` is permitted.
The exact macOS-scoped IPv4 row `default link#N UCSIg bridge100 !` is also
permitted only in that phase and remains topology-hashed; every gateway-bearing,
physical, altered or non-host-only default still aborts.
The fixed dormant Apple-local classes (`awdl0`, `llw0`, `ipsec0`) must first
be taken down; their one canonical link-local is session-bound and only their
exact local multicast/link-local route shapes are accepted.
The current lock contains one exact check-only rotation from retained session
`bca4e4...` to session `0fbd65...`. Check runs a write-free base probe. Apply
publishes the target base once and immediately continues through PREPARING,
host-only validation, watchdog arming and the single boot in the same call.

The recovery profile is also host-local and ignored by Git. It contains no
secret and no caller-selected path: it binds the exact prior/failed/fresh
session chain and the metadata hashes of one proven-prestart failure. Its
committed example is deliberately impossible at runtime. Render without the
`--prestart-recovery-profile` option only for a recovery-disabled review bundle;
an actual recovery and its separately pinned successor must both use the same
reviewed profile by adding:

```sh
--prestart-recovery-profile /absolute/gitignored/prestart-recovery-profile.json
```

Do not start the replacement manually. From a local Terminal—not SSH, tmux or
screen—disable all network services, turn Wi-Fi off, physically disconnect
Ethernet/USB/Thunderbolt uplinks, and close VPN/sharing software. Run the sealed
controller's write-free `check-airgap --attest-physical-airgap`, then
`apply-airgapped-first-boot --attest-physical-airgap` without reconnecting in
between. Apply captures its own target-session base once and never reuses the
check's dynamic observation. The controller continuously monitors the complete
topology, verifies the guest over vsock, and stops it again.

The sealed controller verifies its 15-tool ACL/network/process/privilege
allowlist by exact System-volume device/flags, owner, mode (including setuid),
link count, size and a stable `O_NOFOLLOW` file-descriptor SHA-256. `/bin/ls`
is verified before it performs the ACL checks; the allowlist also includes the
execute-only `sudo` and `visudo` binaries and requires no online trust service.
Capture commands use file-backed, process-group-bounded execution. The live
watchdog extinguishes surviving command groups inside its 250 ms sample budget,
so a child timeout cannot silently freeze monitoring.

Restore host networking only after the command prints both:

```text
vm_status=Stopped
host_uplink_restore_safe_while_vm_stopped=true
```

If the first-boot command fails, keep every uplink disabled and run the sealed
controller's `verify-stopped-after-airgap` phase from the same local Terminal.
That phase cannot start the VM; it only permits reconnection after independently
proving the VM is stopped, UID 454 and all UIDs have no VM/socket process, and
the temporary sudo authority is absent. An exact inert socket/PID residual may
remain only after repeated current-session metadata, ACL, provenance and stale-
PID proofs; it grants no guest reconnect or retry authority. Restore networking
only if the phase prints the same literal
`host_uplink_restore_safe_while_vm_stopped=true`. Host-only capture failures
print only a fixed allowlisted reason code.
For a post-start `UNKNOWN`, this output remains reconnect-only: automatic retry,
VM reuse, guest reconnect and venue writes stay false because the disk may have
changed.

This does not authorize another guest boot. A later stopped migration must
remove bootstrap passwordless sudo and per-boot provisioning first.
