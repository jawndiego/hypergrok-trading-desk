# Commissioned foreground release migration

`08-migrate-commissioned-release.sh` is the only reviewed path for replacing
the immutable application release after the foreground TESTNET profile and
SQLite stores have been commissioned. Do not use the uncommissioned migration,
edit an installed virtual environment, or replace `/opt/trading-desk/current`
by hand.

The script is inert without an explicit action. Its bound `--apply` path:

1. verifies the exact old READY release, sibling installer, sealed media,
   identities, public config/profile, pre/post-init receipts and initialized
   database ownership;
2. requires all trading launchd jobs and UIDs 450–454 to be quiescent;
3. snapshots persistent file identity, hashes, ACLs and namespace inventory;
4. parks the old relative `current` symlink without deleting it and delegates
   construction of the new immutable release to the first-install-only sibling
   installer;
5. runs the new release's credential-free `status` and `dry-run` under UID 451;
6. requires shared learning, the config binding, dry-run non-mutation flags and
   the complete persistent snapshot to match; and
7. retains the old symlink under its fixed rollback name.

`status` and `dry-run` may create and remove private SQLite verification
directories and update SQLite SHM lock state. Their final namespace and every
SHM owner/mode/link/size/ACL must remain exact; SHM bytes and inode are
transient. No authoritative database or WAL byte, inode, owner, mode or ACL may
change. Any mismatch prints only its path and changed field names before the
old release is restored.

## Recovery states

- `--restore-old` is valid only when `current` is absent and the exact old link
  is parked. It never overwrites another link.
- `--rollback-new` is valid only while the new current is still unqualified and
  the exact old link is parked. It uses Darwin `RENAME_SWAP`, restores the old
  current atomically, and retains the new link under a failure name.
- `--retry-failed` is valid only for that exact retained failure link. It moves
  no application bytes, atomically re-presents the same READY release, and
  repeats the complete credential-free qualification after the blocker is
  repaired. For the retained legacy-sidecar failure it additionally requires
  the exact root-owned sidecar-ACL repair receipt.
- `--quarantine-incomplete` delegates the exact non-deleting quarantine to the
  sibling installer while current is absent. Run `--restore-old` afterward.
- Unexpected link/release combinations stop for root review. No force or delete
  action exists.

The migration never initializes or migrates a database, reads or provisions a
credential, starts a service, changes networking, or calls Hyperliquid.
