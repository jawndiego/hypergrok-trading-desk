# macOS TESTNET infrastructure artifacts

These artifacts prepare final-path storage and application bytes without
credentials or venue access. They are not a transaction-readiness claim and
must be copied into an externally hash-pinned, root-owned sealed pack before a
privileged phase is reviewed or run.

Every mutating shell script prints a plan when invoked without arguments. No
privileged phase has been run by repository tests.

## Fixed v1 layout

- Executor APFS volume: 16 GiB quota, 8 GiB reserve, mounted at
  `/var/db/trading-desk-volumes/executor`.
- Research APFS volume: 8 GiB quota, no reserve, mounted at
  `/var/db/trading-desk-volumes/research`.
- Executor warning/shutdown usage: 4 GiB / 6 GiB.
- Research warning/shutdown usage: 6 GiB / 7 GiB.
- Executor-private SQLite shutdown size: 896 MiB per main or exact sidecar.
- Shared-learning SQLite shutdown size: 64 MiB per main or exact sidecar.

The executor shutdown threshold deliberately leaves 10 GiB inside its quota;
the APFS reserve protects 8 GiB from sibling-volume competition. These values
remain unqualified until post-reboot research-ENOSPC and executor WAL/recovery
headroom probes pass under the real service UIDs.

## TESTNET chat-approval addition — not in the apply scripts yet

The reviewed offline channel uses the fixed socket
`/private/var/run/trading-desk/testnet-chat-approval.sock` and requires a
separate canonical UID-452-owned mode-0700 control-state parent, proposed as
`/private/var/db/trading-desk/control-private/chat-approval`. Its SQLite main,
WAL and SHM are mode 0600, regular, single-link and unavailable to UID 501.
The socket parent may grant UID 501 only the exact traversal/connect rights;
it may not grant state read/list/create/delete/rename/replace rights.

The current storage/ACL scripts do not create or verify either path, the
separate presentation namespace or the config-hash-bound handoff namespace,
or the ID-only ready-index namespace,
and no script installs or launches a broker. The application wheel includes the
dormant stdio MCP entry point, but the installer does not register or enable it
in Codex, the plugin descriptor, OpenCode or launchd. A later exact-head pack
must add named-ACL inspection, stale socket refusal, broker-generation evidence,
restart/crash probes, authenticated evidence collectors, same-process issuance,
installation/enablement of the offline artifact-first publisher, ID-only ready
index and cached executor consumer, marker archival/GC, and negative UID tests
before these paths are applied. The router VM receives none of this state.
The adjacent `TESTNET_CHAT_ISSUANCE_PROVENANCE_PLAN.md` is inert design only;
its proposed UID 453 collector and grant/executor receipt pipelines do not
exist and authorize no identity, ACL, network or service change.

## Irreversible operator choice

`01-provision-apfs-storage.sh` creates volumes only through the conspicuous
`--apply-create-unencrypted-testnet` phase. That choice creates unencrypted
APFS volumes. It supplies no passphrase and contains no volume-deletion path.

If the state/order metadata must have independent volume encryption, stop.
Design and qualify unattended boot unlock first, create the encrypted volumes
outside this credential-free script, and add a separately reviewed encrypted
adoption path. Do not pass an encryption secret through argv, environment,
repository files, chat, or this pack.

Creating an empty APFS volume can be rolled back only by deleting that exact
volume; deletion becomes destructive as soon as data exists. No delete command
is included. The quota/reserve sizes also require an explicit review because a
later resize changes the tested resource boundary.

## Attended sequence

1. Seal an exact inventory and retain an external manifest digest.
2. Run the existing root audit and this storage script's `--audit` mode.
3. Decide encryption. If unencrypted TESTNET storage is accepted, run the
   create phase. An interrupted first/second-volume creation is recorded and
   resumable; the explicit mounted-volume adoption phase handles the narrow
   crash window before a receipt is written.
4. Run `--apply-persist` with the exact observed fstab SHA-256 or `ABSENT`.
   The edit is serialized through `vifs`, retains an exact backup/absence
   receipt, and uses volume UUIDs rather than volatile disk identifiers.
   Both entries use `nodev,nosuid,noexec,nobrowse,nofollow`: active data cannot
   host executable binaries or effective set-ID/device nodes, Finder does not
   advertise the volumes, and mount-time lookup refuses a symlinked target.
   `noowners` is deliberately omitted because the UID/ACL boundary depends on
   real ownership.
5. Reboot first, prove the same UUIDs, quota, reserve, mountpoints and retained
   `nodev,nosuid,noexec,nobrowse` flags, and only then run `--apply-layout`.
   `nofollow` is a mount-time lookup rule rather than a retained mount flag;
   the script separately rejects symlink mountpoints. Layout creation is split
   into five root-owned receipt steps; an interrupted run adopts only exact
   empty directories, exact pending markers and exact pending receipts.
6. Run `02-apply-final-preinit-acls.sh --apply-preinit` only while every state
   parent is empty. It grants no cross-UID `delete_child` and future files do
   not inherit delete before initialization.
7. After installing and sealing the pinned Python runtime, run
   `04-install-merged-main.sh --apply ABSOLUTE_SEALED_MEDIA` for the first
   install only. It builds venvs at permanent commit-versioned paths, verifies
   the exact offline media/freeze/shebang/tree, full-syncs the payload, changes
   `.INSTALLING` to `.READY`, and exclusively promotes the relative
   `/opt/trading-desk/current` pointer. It refuses any existing `current` and
   implements no upgrade. An interrupted non-current release may only be moved
   intact with `--quarantine-incomplete EXACT_RECEIPT_SHA256`; it is never
   deleted. All transitions retain `fsync`/`F_FULLFSYNC` ordering and negative
   create/delete/rename/replace probes for UIDs 501/450/451/452.
   The same sealed media must contain the two reproducibly built hardened
   readers from `build-keychain-role-readers.sh --build-release` in a canonical
   root-owned, non-writable, ACL-free sealed source tree and sealed output
   parent. Its `--build-development` output is explicitly untrusted and is not
   eligible for sealing or installation. The release builder pins its source,
   direct compiler and SDK settings, independently reproduces each arm64
   artifact, statically checks symbols and system-only load paths, and requires
   the same authoritative hashes already bound below. The installer hash-pins and
   code-signature-verifies them, then installs immutable copies at
   `/opt/trading-desk/libexec/trading-keychain-reader-executor-v1` and
   `/opt/trading-desk/libexec/trading-keychain-reader-control-v1` as
   `root:trading-executor`/`root:trading-control`, mode `0510`. The installer is
   bound to application commit `2b29ab7823132a1e1b58f4a376320368f76d865c`
   and its exact archive, schema-v3 wheel, dependency manifest and readers.
   Apply is valid only from the separately sealed replacement pack after its
   binding commit passes exact-head CI. The separate
   [attended System Keychain provisioning plan](KEYCHAIN_PROVISIONING_PLAN.md)
   describes the fixed-slot, non-exporting native provisioner and its removal
   after qualification. Its harmless probe records must pass the sealed
   [nonprinting role-probe runner](KEYCHAIN_ROLE_PROBE_PLAN.md) matrix before
   any production secret is entered. Neither ephemeral native tool is part of
   reader installation or installer apply.
8. Render the two storage-guard JSON examples with the retained public volume
   UUIDs and stable APFS container UUID. Install them root-owned, non-writable by service UIDs, with narrow
   read ACLs. The guarded plist examples intentionally exit successfully after
   a deliberate threshold stop so `KeepAlive/SuccessfulExit=false` does not
   restart into a full volume. Disk identity/configuration validation failures
   stop the child but exit nonzero so launchd retries rather than treating
   transient Disk Arbitration failure as an intentional shutdown.
9. Render public TESTNET config, run credential-free `validate`, and retain the
   empty-state evidence. `init` is a later attended checkpoint, not performed
   by these artifacts.
10. Only after a successful one-time `init`, run
    `03-apply-final-postinit-acls.sh --apply-postinit`. It proves all durable
    mains are byte/inode/ACL unchanged and adds delete only to future sidecar
    inheritance. Both ACL phases retain original ACEs in
    `/etc/trading-desk/acl-recovery` until restoration is re-read and proven
    exact. A failed proof creates `ACL-RECOVERY-REQUIRED` and deliberately
    preserves the recovery directory for attended root review.

The headroom guard is not log rotation. The guarded launchd examples still
write stdout/stderr to regular files, so bounded rotation/reopen and retention
must be implemented and qualified before any LaunchDaemon installation or
always-on claim. The first TESTNET harness write also remains blocked. The
qualification GTC/query/cancel/close lifecycle, signer/verifier, dormant sender,
terminal reservation release and direct-terminal fallback now exist offline,
but submission is compiled off and live evidence is absent. The chat approval
CAS/wire/stdio MCP, typed issuer/presentation, schema-v13 atomic admission,
schema-v14 signer/outcome fences, schema-v15 verified handoff reader/scope and
schema-v16 full canonical delivery evidence are likewise offline. They still
need authenticated collectors, same-process
issuance and grant provenance, fixed listener and all named ACLs, installation
and enablement of the implemented publisher/ready-index/consumer chain,
archival before its 1,024-entry cap, and live end-to-end qualification. WebSocket live recovery, real
response-loss injection and the signed qualification artifact remain incomplete.
