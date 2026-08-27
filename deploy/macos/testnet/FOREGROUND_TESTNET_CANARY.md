# Foreground macOS TESTNET canary

`06-commission-foreground-testnet.sh` is the short path to the first attended
TESTNET canary. It keeps the exact UID and ACL boundaries but deliberately
does not require APFS quota volumes, storage headroom automation, or launchd.
Those remain production hardening work; this layout must not be described as
always-on or mainnet-ready.

The commissioner is plan-only without an argument. Its apply phases never run
`init`, read or provision Keychain, change PF/WireGuard/routes, start a service,
or call Hyperliquid. Run apply only from an externally reviewed, root-owned,
non-writable, ACL-free sealed copy containing the shell script,
`render-foreground-executor-config.py`, and
`init-foreground-chat-store.py` in the same directory.

## Fixed layout

Executor SQLite state uses ordinary local APFS beneath:

```text
/private/var/db/trading-desk-testnet-foreground/
  execution/execution.sqlite3
  nonce/nonce.sqlite3
  daily-loss/daily-loss.sqlite3
  learning/learning.sqlite3
  learning/staging.sqlite3
  executor-socket/executor.sock
```

The script also creates the source-enforced fixed chat paths for control state,
the broker socket, presentations, handoffs, ready markers, UID-453 evidence and
quotes, and UID-451 preregistration. Local and remote route-health cache roots
remain root-owned mode 0755 and ACL-free under their existing config-hash
namespaces. It creates directories only; it does not fabricate either route
expectation or health evidence.

The broker socket parent is the UID/GID-452 directory
`/private/var/db/trading-desk-testnet-chat-socket`. It is deliberately below
root-owned `/private/var/db`, not macOS's GID-`daemon`-writable
`/private/var/run`.

The Lima control plane uses a separate non-agent identity,
`trading-router-operator` UID/GID 454. Its only home is the ACL-free,
UID/GID-454 mode-0700 `/private/var/db/trading-desk-lima`. It has no login,
supplementary group, harness state, Keychain slot, or venue authority. UID 453
remains the distinct public-data collector and never owns Lima state.

The public executor config is always
`/etc/trading-desk/testnet-executor.toml`. It is root-owned mode 0400 and has
read-only ACLs for UIDs 450–453. `/etc/trading-desk` grants those identities
search only. The input profile is fixed at
`/etc/trading-desk/testnet-foreground-profile.json`, root-owned mode 0400 and
ACL-free. It contains public addresses, account scope, and limits—not a private
key, HMAC, endpoint, or free filesystem path.

## Attended sequence

1. Copy `testnet-foreground-profile.json.example` to a private working file,
   replace both address placeholders with lowercase public addresses, and
   review the limits, instrument, Hyperliquid asset ID, and recovery CLOID.
   Install those public bytes at the fixed profile path as root:wheel 0400,
   with no named ACL.
2. From the sealed commissioner directory, run the collector identity phase. This
   creates only the exact hidden, disabled, no-home
   `trading-public-collector` identity at UID/GID 453, or verifies an exact
   existing identity:

   ```sh
   sudo /absolute/sealed/path/06-commission-foreground-testnet.sh --apply-identity
   ```

3. Run the separate router-operator identity phase. It creates or exactly
   adopts only disabled UID/GID 454 and its private Lima home; it does not
   create a VM or change networking:

   ```sh
   sudo /absolute/sealed/path/06-commission-foreground-testnet.sh --apply-router-identity
   ```

4. Run the pre-init phase and retain its config hash. Every state parent is
   still empty when this phase completes:

   ```sh
   sudo /absolute/sealed/path/06-commission-foreground-testnet.sh --apply-preinit
   ```

5. Run the installed executor’s credential-free `validate`, then its one-time
   `init`, as `trading-executor` with an empty environment and the fixed config.
   This creates only local SQLite state; inspect its JSON result before
   continuing:

   ```sh
   sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor validate --config /etc/trading-desk/testnet-executor.toml
   sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor init --config /etc/trading-desk/testnet-executor.toml
   ```
6. Run the sealed `init-foreground-chat-store.py` once with the installed
   executor venv Python as UID/GID 452 and an empty environment. The helper
   accepts no arguments, requires the exact empty database namespace, creates
   only the fixed chat store, verifies owner/group/mode/link/ACL, and reopens it
   with `must_exist=True`. Do not start the broker yet.

   ```sh
   sudo -u trading-control -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/python -B -I /absolute/sealed/path/init-foreground-chat-store.py
   ```
7. Run the post-init phase. It verifies every authoritative main database and
   the private chat database, snapshots their
   bytes/inodes/modes/owners/links/ACLs, changes only future sidecar inheritance
   on the execution and learning parents, probes cross-role sidecar removal,
   and proves the mains did not change:

   ```sh
   sudo /absolute/sealed/path/06-commission-foreground-testnet.sh --apply-postinit
   ```

8. Only after the post-init receipt exists, run collectors, broker, bridge, and
   executor one at a time in foreground terminals. Route expectation/evidence,
   remote VPN/PF qualification, Keychain reader/provisioner qualification, and
   the minimum-size canary remain separate attended gates.

Do not improvise the chat-store initialization with a user-owned checkout or
an ad-hoc `PYTHONPATH`. The installed release/helper must be root-owned and
hash-bound first. Failure before either receipt is an operator-review stop; do
not delete or overwrite an unexplained path.
