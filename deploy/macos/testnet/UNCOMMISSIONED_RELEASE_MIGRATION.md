# Uncommissioned release migration

`07-migrate-uncommissioned-release.sh` is a narrow recovery wrapper for the
already-installed but never-commissioned application release
`a0f82d5928e57c43e511127a490ecbcf48110684`. It exists because the replacement
must change fixed runtime paths and venv symlink hardening while the first-install
installer correctly refuses to overwrite `/opt/trading-desk/current`.

The checked-in script is plan-only without an argument and is bound to the
reviewed replacement application, release receipt and sibling-installer hash.
Its literal rebind gate is zero only in the binding commit. Exact-head CI must
pass before an attended root operator seals or runs it.

The migration accepts only:

- `--apply ABSOLUTE_ROOT_OWNED_SEALED_MEDIA`, which atomically parks the exact
  old `current` symlink beside its original location and delegates replacement
  release construction to the hash-pinned sibling
  `04-install-merged-main.sh`; and
- `--restore-old`, which can move the exact parked old symlink back only while
  `current` is absent.

The parked link stays directly below `/opt/trading-desk`, so its relative
`releases/a0f82d...` target remains resolvable. Every transition uses
`RENAME_EXCL`, `fsync` and Darwin `F_FULLFSYNC`. The wrapper never deletes or
overwrites a link and never writes a regular file. An incomplete replacement is
retained for the existing sibling `04 --quarantine-incomplete` flow. If a new
`current` appears before an installer error, restoration is forbidden pending
exact root review.

Before the first park and on every resume, the script proves that collector and
router identities 453/454, foreground config and receipts, databases, broker
socket, handoff/ready/presentation/evidence roots, VPN route caches, Lima state,
fixed LaunchDaemons/jobs and isolated role processes are absent. It does not
inspect or provision Keychain values, initialize state, start a service, change
networking or contact Hyperliquid.
