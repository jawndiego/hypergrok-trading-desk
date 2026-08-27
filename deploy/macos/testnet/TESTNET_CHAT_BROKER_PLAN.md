# TESTNET chat broker deployment plan

Status: **credential-free and plan-only; no apply script, listener enable,
LaunchDaemon install, ACL mutation, database initialization or venue action is
authorized**.

The machine-readable companion is `testnet-chat-broker-plan.json.example`. The plist
is an inert example with `Disabled=true`, `RunAtLoad=false` and
`KeepAlive=false`. The Python service also has the literal
`TESTNET_CHAT_BROKER_SERVICE_ENABLED = False` gate before identity or path I/O.

The inert plist names the dedicated future control runtime
`/opt/trading-desk/current/control/.venv/bin/python`. That path is intentionally
absent from the current installer and is neither the research nor executor
venv. Creating, populating, sealing and exact-head verifying that separate
runtime is a mandatory future commissioner step; changing the plist to reuse an
existing role's venv is not an allowed workaround.

## Fixed identities and paths

- broker: `trading-control`, UID/GID 452;
- connecting Codex bridge: local UID 501;
- socket: `/private/var/run/trading-desk/testnet-chat-approval.sock`;
- approval database:
  `/private/var/db/trading-desk/control-private/chat-approval/chat-approval.sqlite3`;
- immutable generation receipts:
  `/private/var/db/trading-desk/control-private/chat-approval/broker-generations`.
- future handoff root:
  `/private/var/db/trading-desk-testnet-chat-handoffs`, with one
  executor-config-hash child directory.

No path, account, environment, endpoint, action or credential is accepted on
argv or from an environment variable. The service imports no Keychain reader,
signer, executor, admission, HTTP or venue module.

## Proposed ACL shape

The dedicated socket parent is UID/GID 452 and mode `0700`. Its sole named ACE
is UID 501 `allow search` (rendered by Darwin `acl_to_text` as
`allow:execute`). That ACE grants no list, read, write, add-file,
add-subdirectory, delete, delete-child, rename, ACL-write or ownership right.

The socket is UID/GID 452, mode `0622`, single-link and has no named ACL. The
parent search ACE is therefore the narrow name-resolution capability; UID 501
can reach the known socket name but cannot list or mutate its directory. Both
ends additionally call Darwin `getpeereid`: the broker requires the exact
session-bound UID/GID 501, and the bridge requires the OS-observed UID/GID 452
before sending a request byte.

The state and generation parents are UID/GID 452, mode `0700`, and ACL-free.
Database, WAL, SHM and generation files are mode `0600`, regular, single-link
and ACL-free. UID 501 receives no traversal or file capability there.

## Required attended proof before promotion

Do not derive ACL commands from this document and do not flip the compiled
gate. A later exact-head, root-owned sealed commissioner must atomically create
and verify the paths and dedicated control runtime, then run a sacrificial
matrix proving:

1. UID 501 can connect to the exact socket but cannot list, create, delete,
   rename or replace anything in either parent;
2. research UID 450 and executor UID 451 cannot traverse or connect;
3. unexpected, symlinked, hard-linked, wrong-owner, wrong-mode, inherited-ACL
   and stale socket nodes all prevent startup;
4. restart creates one new 256-bit broker generation, preserves old immutable
   receipts, and reconciles an acknowledgement-loss replay without another
   approval transition;
5. SIGTERM stops accept within the bounded poll interval and removes only the
   exact socket inode created by that generation; and
6. reboot preserves the negative access results and does not auto-enable the
   disabled plist.

The listener remains non-capital even after these checks. Trusted proposal
issuance/presentation, schema-v13 atomic consume/reserve/outbox admission,
schema-v14 signer/outcome fencing, schema-v15 config-bound verified handoff
reading and schema-v16 canonical delivery-evidence persistence exist as offline
source boundaries. The reader requires `/private`, `/private/var` and
`/private/var/db` to be root:wheel mode 0755 and ACL-free; the dedicated root
and config-hash child to be 452:452 mode 0700 with only UID 451 `execute`; and
each handoff file to be 452:452 mode 0400 with only UID 451 `read`. These source
checks do not close the deployment gates: authenticated account/market
collectors, same-process issuer/listener
lifecycle, presentation ACL/configuration, a UID-452 create-only canonical
handoff publisher, an installed UID-451 reader/consumer loop, the handoff
namespace ACL matrix and live end-to-end qualification remain mandatory.
Mainnet never uses this chat provenance.
