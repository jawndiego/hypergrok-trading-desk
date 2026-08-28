# Always-on research and isolated TESTNET operation

Status: deployable research node plus an isolated, mainnet-impossible TESTNET
worker. No account is configured or live-qualified by the repository, and no
installed agent tool can approve, sign, or submit an order.

The first always-on process is the credential-free, research-only node. It polls
registered assets, writes immutable research artifacts and heartbeats to one
explicit SQLite database, and exits cleanly on `SIGINT` or `SIGTERM`. The
current CLI deliberately has no execution command and no network/account
environment toggle.

## Trust boundary

Run the research node under a dedicated, non-administrator OS identity. That
identity may read the installed application and write only its research state
and log directories. It must not have a Hyperliquid private key, API wallet,
X bearer token, browser profile, approval key, signer socket, shell startup
file containing credentials, or access to the execution database.

The TESTNET signer/executor is a separate deployment, not another argument to
the research service. Its checked-in supervisor templates must be installed
only after foreground validation. Provision it under a different non-login OS
identity with its own reviewed binary, state directory, Keychain ACL, egress
policy and service definition. ChatGPT, Codex, OpenCode and the research/MCP
process must fail negative-access tests against the API-wallet and recovery
Keychain items.

Testnet and mainnet execution must use separate:

- OS users and service names;
- API wallets and secret-storage policies;
- nonce/command/OMS databases and backup sets;
- account IDs, deployment grants and approval trust roots;
- state, logs, monitoring and incident records.

Do not select mainnet with an environment variable such as `NETWORK=mainnet`
or by editing the research service. The execution service must bind its
network, account, database and signer identity in a separately reviewed,
environment-specific configuration and deployment grant. Success on testnet
does not authorize mainnet.

## Install a reviewed build with Python 3.11

Use a reviewed commit or release in a root/admin-owned installation directory;
do not run a mutable checkout owned by the service account. The macOS installer
builds both locked environments at their permanent versioned paths and promotes
the first-install `current` pointer used below. Do not recreate or mutate that
venv in place. A manual or Linux installation needs its own reviewed immutable
path and locked, offline dependency build before these commands apply.

```sh
cd /opt/trading-desk/current/research
./.venv/bin/trading-harness doctor
```

`doctor` must report Python `>=3.11`, `live_trading: false`, venue writes
disabled and credential loading disabled. The research node itself does not
need MCP. The separate Codex/OpenCode service does, so its dependencies must be
present in the reviewed research lock and sealed build before promotion. Never
use an online or in-place `pip install` to change `/opt/trading-desk/current`.

Create the state and log directories before starting a supervisor. The
research user owns those directories with mode `0700`; the database and backup
files use `0600`. The installed repository and virtual environment should be
read-only to that identity. Do not use `/tmp`, a home-directory shortcut,
relative paths or a network-mounted SQLite database.

Run once in the foreground before installing a service:

```sh
sudo -u trading-research -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/research/.venv/bin/trading-harness node run --state-db /var/db/trading-desk/research/research.sqlite3 --node-id trading-desk-research --poll-seconds 1 --history-bars 1200
```

Press `Ctrl-C` to exercise graceful shutdown. Then inspect persisted state:

```sh
sudo -u trading-research -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/research/.venv/bin/trading-harness node status --state-db /var/db/trading-desk/research/research.sqlite3 --node-id trading-desk-research
```

The status response is the application-level view. Supervisor status, process
existence and logs are separate operational evidence.

## macOS always-on computer (preferred first deployment)

Use a system LaunchDaemon for an unattended Mac; a LaunchAgent depends on an
interactive login. Start from
`deploy/launchd/com.jawndiego.trading-desk-research.plist.example` and render a
new file outside the repository. Replace every placeholder exactly once:

| Placeholder | Required reviewed value |
| --- | --- |
| `__REVIEWED_RESEARCH_USER__` | Dedicated non-admin research account |
| `__REVIEWED_RESEARCH_GROUP__` | Dedicated research group |
| `__REVIEWED_REPO_DIR__` | Absolute, admin-owned installed source directory |
| `__REVIEWED_VENV_BIN__` | Absolute virtual-environment `bin` directory |
| `__REVIEWED_STATE_DIR__` | Absolute local state directory owned by research user |
| `__REVIEWED_LOG_DIR__` | Absolute local log directory owned by research user |

Do not add `EnvironmentVariables`, credentials, a shell wrapper or a network
argument. Confirm no placeholder remains and validate the rendered plist
before placing it in `/Library/LaunchDaemons`:

```sh
rg -n '__REVIEWED_[A-Z_]+__' /absolute/path/to/rendered-research.plist
plutil -lint /absolute/path/to/rendered-research.plist
```

The `rg` command must return no matches. Review ownership and permissions, then
install using the site's administrative change process. The relevant launchd
operations are:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.jawndiego.trading-desk-research.plist
sudo launchctl print system/com.jawndiego.trading-desk-research
sudo launchctl kickstart -k system/com.jawndiego.trading-desk-research
sudo launchctl kill SIGTERM system/com.jawndiego.trading-desk-research
sudo launchctl bootout system /Library/LaunchDaemons/com.jawndiego.trading-desk-research.plist
```

The template starts at boot, restarts only after failure, waits at least ten
seconds between restarts, sends a normal termination signal on stop, fixes the
working directory and writes stdout/stderr to explicit files. A clean stop is
not automatically restarted. Configure rotation and retention for both log
files using the host's standard facility; never log credentials or raw social
session data.

For this macOS layout, use a local state path such as
`/var/db/trading-desk/research/research.sqlite3` and a log directory such as
`/var/log/trading-desk/research`. Do not share either with the isolated executor.

## Linux/systemd alternative

Render `deploy/systemd/trading-desk-research.service.example` using the same
six reviewed placeholders. A typical Linux state path is
`/var/lib/trading-desk/research/research.sqlite3`; use a separate local log
directory such as `/var/log/trading-desk/research`.

The example uses a dedicated user/group, fixed working directory, explicit
database and log paths, `Restart=on-failure`, a ten-second restart delay,
`SIGTERM`, restrictive umask, no capabilities, a read-only host filesystem and
write access only to state/log paths. Confirm the installed Python and SQLite
runtime work with those hardening settings before enabling at boot.

After rendering and review:

```sh
systemd-analyze verify /absolute/path/to/trading-desk-research.service
sudo systemctl daemon-reload
sudo systemctl enable --now trading-desk-research.service
sudo systemctl status trading-desk-research.service
sudo systemctl kill --signal=SIGTERM trading-desk-research.service
sudo systemctl stop trading-desk-research.service
```

Application status remains:

```sh
sudo -u trading-research -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/research/.venv/bin/trading-harness node status --state-db /var/lib/trading-desk/research/research.sqlite3 --node-id trading-desk-research
```

## Local Ubuntu VM router lab

The repository can render a private-key-field-free Ubuntu 24.04 ARM64 router
bundle from
`deploy/ubuntu-router/router-spec.json.example`. This VM is network-only; the
executor, signer, System Keychain, control plane and every SQLite database stay
on macOS. Follow [`ubuntu_vm_router.md`](ubuntu_vm_router.md) and retain the
rendered bundle manifest with the deployment record.

`local_nat_lab` is intentionally narrow. It creates a Mac-to-VM WireGuard
full-tunnel path and default-drop VM forwarding, but exits through the same
home/office connection. It does not change the public IP, stop macOS host
bypass or supply a remote VPN peer. The application now has a
short-lived local/remote route gates before normal entry preparation and final
submission authority. The remote collector, helpers and durable authority
binding are implemented, but their expectation/PF/VM artifacts are not installed.
Reader completion is re-timed and must leave the full two-second PRE_SEND
window. A transient preparation denial can only requeue the same active
proven-unsent command; pre-preview maintenance normalizes expired claims and
releases queued risk at the earliest ticket/leg expiry.
If the selected route blackholes after durable authority consumption, the
attempt remains unknown and must reconcile without retry. If macOS removes the
route, traffic may instead bypass the VM and succeed directly; no application
fallback exists, but host fallback remains possible. Success alone does not
prove VM traversal.

Router preparation is venue-credential-free. Generate WireGuard private keys
on their owning machines before rendering public-key inputs; never place one in
the public profile, repository, chat, cloud-init, environment or argv. The VM
receives no API-wallet, approval secret, account config, repository mount,
shared state, MCP server or agent runtime.

Before relying on the lab, update macOS to a current security release, reboot,
qualify both VM NICs and interface names, verify IPv4/IPv6 and DNS behavior,
exercise VM/tunnel/hypervisor loss, and prove a read-only TESTNET `/info` call.
Do not install launchd or queue a command merely to test routing. The remaining
machine and live-workflow gaps are tracked in
[`testnet_commissioning.md`](testnet_commissioning.md).

## Isolated TESTNET learning worker

This worker exists to collect trustworthy execution evidence. It does not
claim that the registered strategy is profitable, and every grant/ticket
records `profitability_qualified: false` and `mainnet_authorized: false`.

Install the `execution` extra in a separately reviewed Python 3.11 virtual
environment. Render
`deploy/config/testnet-executor.toml.example` to an absolute owner-only file,
replace every placeholder, and leave the compiled default risk-policy hash
unchanged unless the code and policy change together. Executor config schema
v3 requires exact numeric `executor_uid`, `research_uid`, and `control_uid`
values 451, 450, and 452. The identities are part of the canonical config hash and
durable state binding; they are not looked up from an ambient username or
environment variable. The four Keychain items must be distinct:

- API-wallet secp256k1 private key, readable only by the executor identity;
- approval HMAC key, readable only by the attended control identity;
- recovery HMAC key, readable only by the executor identity;
- learning-grant HMAC key, readable only by the grant issuer and attended
  control identities, never the research/MCP identity.

HMAC items are independent nonzero random 32-byte values stored as 64 hex
characters. Never put any of these values in TOML, an environment variable, a
shell argument, a log, chat, or the repository. Verify Keychain access under
each final service identity—including negative tests—before live use.

For a boot-time macOS LaunchDaemon, every credential stanza must name the
explicit `/Library/Keychains/System.keychain`; do not rely on a login-keychain
search list or `HOME`. Do **not** provision a real credential with the
`security add-generic-password` CLI. On the supported macOS release its
interactive password form cannot also bind an explicit positional keychain:
putting the keychain before the final prompt option exits with usage, while
omitting the keychain can silently select the operator's login keychain.

Trusting `/usr/bin/security` in a Keychain item ACL is also not an OS-user
boundary: the ACL identifies the shared executable, while executor, research,
control and the desktop user can all invoke it. Real credential provisioning
therefore remains blocked until the reviewed deployment installs a
role-restricted, root-owned Keychain helper, the provider is bound to that
exact helper, and sacrificial positive/negative UID probes pass before and
after reboot. Keychain Access may be used only to create the sacrificial test
item during that attended qualification; never use it to work around the
helper gate with a real signer or HMAC value.

The reviewed reader contract uses two different hardened native applications,
both installed below a root-owned, non-writable `/opt/trading-desk/libexec`:

| Reader | Required identity | Fixed slots and Keychain labels |
| --- | --- | --- |
| `trading-keychain-reader-executor-v1` | executor UID/GID 451 only | `signer` = `com.jawndiego.trading-desk.testnet-signer` / `hyperliquid-api-wallet`; `recovery` = `com.jawndiego.trading-desk.testnet-recovery` / `recovery-hmac` |
| `trading-keychain-reader-control-v1` | control UID/GID 452 only | `approval` = `com.jawndiego.trading-desk.testnet-approval` / `approval-hmac`; `grant` = `com.jawndiego.trading-desk.testnet-grant` / `grant-hmac` |

The helper derives role from real/effective UID and accepts only `read SLOT`;
service, account and keychain path are not caller inputs. UID 450, desktop UID
501 and either cross-role invocation are denied. Executor config schema v3
requires the fixed `macos_system_keychain_role_helper_v1` provider, all four
canonical labels and the literal System Keychain path. The reader has no
provision, update, delete, list or terminal-output mode.

The signer is a 32-byte API-wallet key encoded as 64 hex characters; the other
three items are separately generated nonzero 32-byte HMAC keys in the same
encoding. Before installing launchd, positively test each permitted helper
lookup under its final UID with the explicit keychain path, and negatively test
every other service and desktop UID. Do not proceed if a forbidden UID can
execute the helper, if a permitted LaunchDaemon cannot read its intended item
after reboot, or if any lookup depends on unlocking a login session.

Use three different local directory classes: executor-private state for
execution, nonce, daily-loss and the configured control-socket path;
learning-shared state for only `staging.sqlite3` and `learning.sqlite3`
(including their WAL/SHM sidecars); and research-private state for research
data. Never put these files under one
writable parent: directory write access permits unlink/replacement even when a
database is mode `0600`. The research/MCP identity must have no read or write
access to executor-private state. In particular, it must never open the
authoritative daily-loss database; agent quotes mark daily loss as deferred and
the executor performs the mandatory same-cycle refresh before any entry send.

Keep the reviewed config admin/root-owned, mode `0400`, and grant exact read
ACLs to the executor and attended-control identities. The loader accepts an
admin-owned file but rejects group/world mode bits. Its path-overlap schema
check is deliberately lexical and I/O-free so UID 452 never probes the
executor-only nonce, loss or socket parents. UID 451 separately rejects
physical parent or main-file device/inode aliases before initialization and on
state reopen; this proof is not delegated to control or research. Create four
distinct writable parents beneath the executor-private root: `execution/`,
`nonce/`,
`daily-loss/` and `socket/`. Own them as the executor UID with mode `0700`.
Give attended control the inherited SQLite rights it needs only on
`execution/`; it must have no directory capability on the other three. Create
the learning-shared parent owned by the executor UID with mode `0700` and
narrow per-identity ACLs for only research, executor and control. Run
`init` as the executor UID, never as root, so capital-state files have the final
owner. Do not run Codex/OpenCode as the executor or control UID.

A reviewed macOS layout is, for example:

- `/var/db/trading-desk/executor-private/execution/`: execution SQLite and
  sidecars; executor RW, attended control narrowly RW, research no access;
- `/var/db/trading-desk/executor-private/nonce/`,
  `/var/db/trading-desk/executor-private/daily-loss/` and
  `/var/db/trading-desk/executor-private/socket/`: executor only;
- `/var/db/trading-desk/learning-shared/`: staging and learning SQLite files;
  research, executor and control receive only the required ACL entries;
- `/var/db/trading-desk/control-private/grants/`: original signed grants;
  attended control only, mode `0700` parent and generation-specific `0600` files;
- `/var/db/trading-desk/research/`: research SQLite; research only.

The v3 owner policy is exact and distinguishes durable main files from
transient SQLite sidecars:

| Configured artifact | Main-file owner | Allowed `-wal`/`-shm`/`-journal` owners |
| --- | --- | --- |
| Execution database | Executor UID | Executor or attended-control UID |
| Nonce database | Executor UID | Executor UID only |
| Daily-loss database | Executor UID | Executor UID only |
| Staging database | Executor UID | Executor, attended-control, or research UID |
| Learning database | Executor UID | Executor, attended-control, or research UID |

`init` creates all five main databases as the configured executor UID. A main
database owned by control, research, root, or an unknown UID is invalid; the
multi-owner sets apply only to those three exact SQLite sidecar suffixes. The
configured control-socket path and its parent remain executor-only.

This distinction is required by measured macOS behavior, not convenience. In
the reviewed sacrificial probe, the main execution database stayed
executor-owned in both orderings. With an executor-first WAL session its WAL
and SHM were executor-owned. With a control-first WAL session they were
control-owned, while the executor still had the exact inherited read/write ACL
and successfully wrote the database. A process-owned-only sidecar check would
therefore reject a valid crash/restart state. The v3 policy accepts that exact
control-owned execution sidecar without admitting control ownership of the
main database or any control/research ownership in nonce or daily-loss state.

Use inheritable ACLs on the exact shared directories so newly created SQLite
WAL/SHM sidecars receive the same narrow rights. Do not grant `delete_child`
to control or research: that right also permits deletion and replacement of a
durable main file. Before `init`, grant the permitted roles inherited
file-level `read,write,readattr` only, while direct directory entries grant only
`list,search,add_file,add_subdirectory,readattr` (listing supports stale-snapshot
detection; the subdirectory right is only for
private colocated verification snapshots), plus an inherit-only directory ACE
granting each permitted role `delete` on the verification directory it creates.
Do not grant parent `delete_child`. This makes each
exclusively reserved main non-deleteable as soon as it appears. Immediately
after `init`, extend only the directories' inherit-only file ACEs with `delete`.
Existing mains do not inherit that later right; future sidecars do, so any
permitted writer can clean up a sidecar created by another permitted writer.
Prove cross-owner sidecar cleanup,
then prove every non-executor role is denied unlink, rename and replacement of
all three durable mains. Also prove the research UID cannot list,
read, create, unlink or replace anything in `executor-private`, and prove the
control UID cannot do so in the nonce, daily-loss or socket parents.

Keep every learning/staging main and sidecar below its enforced live 64 MiB cap.
The 1 GiB private-file check is a reopen ceiling, not a live transaction quota;
configure an executor-volume quota and alert/shutdown threshold comfortably
below it. Archive immutable learning evidence before bounds are approached;
never delete a hot WAL. If shared learning
is oversized, corrupt, drifted or unavailable, the executor opens only its
independently verified core state. New entries and learning projection remain
blocked, but startup reconciliation, protection, reduce-only flatten,
owned-CLOID cancellation and same-nonce fencing remain available. Treat this as
a degraded incident and repair/restore shared learning separately—never weaken
core validation to clear it. `status` and `dry-run` expose
`shared_learning_available=false` and
`entry_blocked_by_shared_learning=true` in this lane. Urgent safety ticks skip
both pre- and post-step learning scans so a large valid ledger cannot delay the
next reconciliation or recovery action. An entry tick requires both a complete
same-tick loss refresh and a successful same-tick learning synchronization with
room for the next bounded projection; prior learning references cannot borrow
authority after projection becomes unavailable.

These file caps are not an OS quota. Place the research-private database,
research/MCP logs, shared-learning state and research temporary directory on a
separately quota-limited APFS volume (or an equivalently enforced storage
class). Keep executor-private state and its emergency WAL headroom on a reserve
the research UID cannot consume. Qualify both research and executor quotas,
private-state shutdown thresholds, log rotation and temporary-file cleanup
under the real daemon UIDs and after reboot. If the Mac
cannot enforce this separation, stop; do not claim always-on readiness.
The verifier never uses ambient `TMPDIR`: it creates a mode-`0700` temporary
directory next to the source DB and removes it after the read-only check. Budget
quota headroom for one snapshot copy and fail closed for any crash-left
`.trading-sqlite-verify-*`, `.execution-store-verify-*`, or
`.executor-runtime-verify-*` directory; runtime validation detects those names
and stops until root reviews and removes them.

Validate and initialize without credential or network access:

```sh
sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor validate --config /etc/trading-desk/testnet-executor.toml
sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor init --config /etc/trading-desk/testnet-executor.toml
```

Pause here for the attended root ACL finalization described above: add delete
to future-file inheritance without modifying existing mains. Record the
main-file ACLs and the negative unlink/rename/replacement probes; do not open a
control or research database connection before they pass. Then continue as the
executor UID:

```sh
sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor status --config /etc/trading-desk/testnet-executor.toml
sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor dry-run --config /etc/trading-desk/testnet-executor.toml
```

`validate`, `init`, `status`, and `dry-run` do not load Keychain items or call
Hyperliquid. `init` refuses missing/insecure parent directories, binds every
database to the exact config, and enforces the schema-v3 main/sidecar owner policy.
`status` and `dry-run` require complete current schemas, migration histories,
durable bindings and integrity chains for core execution, nonce and daily-loss
state. Shared learning is verified separately and is reported as degraded if it
fails. Existing-state open is verification-only: it never creates, migrates,
repairs or binds a database. Any migration is a separate reviewed checkpoint.
These commands make no runtime state transition or venue call.

The executor CLI sets umask `0077` before dispatching every command, including
attended control commands. Do not replace it with a wrapper that creates or
pre-opens state under a weaker ambient umask. A control-first WAL/SHM must be
mode `0600` and carry only the reviewed inherited executor/control ACLs.
Except for credential-free `validate`, executor commands require the configured
executor UID, attended commands require the configured control UID, and the
configured learning MCP requires the configured research UID before it reads
the signed-grant copy. The MCP entry point also establishes umask `0077` for
its full server lifetime so foreground qualification has the same sidecar mode
invariant as launchd.

Config schemas v1 and v2 are rejected. `init` requires all configured state directories
to be empty, exclusively reserves all five exact main-file names, and rejects
reruns and partially populated layouts. An interrupted reservation or schema
build remains invalid partial state for root review; it is never auto-repaired.
There is no silent earlier-schema-to-v3 state migration and
no automatic rebinding of an existing database to new UIDs or a new config
hash. On a new machine, initialize anew only after proving the target state
directories contain no real harness state (sacrificial ACL probe files are not
harness state and must be removed by their reviewed probe). If any v1-bound or
otherwise nonempty state exists, stop, preserve the complete main/WAL/SHM set,
and require a separately reviewed migration; do not run `init` over it.

Issue a short-lived infrastructure-learning grant in a direct terminal:

```sh
sudo -u trading-control -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor issue-grant --config /etc/trading-desk/testnet-executor.toml --output /var/db/trading-desk/control-private/grants/learning-grant-g1.json --grant-id testnet-learning-001 --ttl-seconds 3600
```

The command opens `/dev/tty` and requires the exact displayed confirmation. It
does not accept confirmation through stdin or an argument and never overwrites
an existing artifact. A PTY is not proof of human identity: the control UID
must never run Codex/OpenCode or expose an agent shell, and its Keychain ACLs
must be tested independently.

Run the configured agent-facing MCP service under the research identity:

```sh
sudo -u trading-research -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/research/.venv/bin/trading-harness-mcp --transport streamable-http --host 127.0.0.1 --port 8765 --learning-executor-config /etc/trading-desk/research-testnet-profile.toml --learning-research-db /var/db/trading-desk/research/research.sqlite3 --learning-grant /var/db/trading-desk/research/learning-grant-g1.json
```

Before startup, use a research-readable root-owned config and a root-owned
mode-`0400` signed-grant copy with narrow read ACLs for the research identity.
The config and grant copies must have exact bytes/hashes matching their
control-plane artifacts; never make the control copy writable by research.
Research uses the signed grant only as a quote scope and does not receive its
symmetric HMAC key. Its fifteen tools can analyze and stage, but still
cannot approve, reserve, load the API wallet, sign, or write to `/exchange`.
It also cannot open the executor daily-loss database: staged quotes explicitly
defer that value, and an entry requires a complete authoritative loss refresh
in the exact executor tick that is allowed to dispatch.

Point Codex at the configured loopback service, not an ambient `python3`
process. The [official Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
supports a URL-backed server; for this endpoint:

```sh
codex mcp add tradingDesk --url http://127.0.0.1:8765/mcp
```

The checked-in plugin MCP descriptor uses the same URL. [OpenCode MCP configuration](https://opencode.ai/docs/mcp-servers/)
uses a remote
entry with `"type": "remote"` and
`"url": "http://127.0.0.1:8765/mcp"`. Confirm the service is running and list
the tools from the actual client before relying on it; a config edit does not
make a server callable in an already-running agent session.
After Codex/ChatGPT returns
a staged document ID, review and authorize it from the separate attended
terminal:

```sh
sudo -u trading-control -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor show-stage --config /etc/trading-desk/testnet-executor.toml --document-id stg_REVIEWED_ID
sudo -u trading-control -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor authorize-stage --config /etc/trading-desk/testnet-executor.toml --grant /var/db/trading-desk/control-private/grants/learning-grant-g1.json --document-id stg_REVIEWED_ID --approver-id local-operator
```

### Separate TESTNET chat approval path — offline only

The repository now contains an unregistered stdio MCP whose sole tool is
`approve_testnet_trade(command_text)`. It runs only as UID 501, accepts no
socket/account/action/environment argument, verifies the fixed AF_UNIX peer as
the OS-observed UID 452 before sending, forwards one bounded request and never
retries. The broker handler independently verifies UID/GID 501 before reading,
accepts only exact `execute trade <proposal-id>`, and can atomically record one
approval in the separate control-owned SQLite store. All results keep
`human_message_attested`, `mainnet_authorized`, `execution_performed` and
`venue_write_attempted` false.

That code is not yet installed or added to the plugin MCP descriptor. No
fixed-path listener, named-ACL verifier, broker-generation record or trusted
read-only proposal presentation path exists. The approval receipt is also not
imported into `ExecutionStore`; normal bracket signing lacks the qualification
path's fresh PRE_KEY/PRE_SEND `userRole` fences. Therefore the chat path cannot
currently queue or submit an order.

After those gates are implemented and commissioned, the intended TESTNET UX
is: Codex displays the exact control-produced proposal (entry, size, stop,
target, maximum loss, account and expiry); the user replies exactly
`execute trade <proposal-id>`; the isolated bridge records approval; and the
executor independently refreshes account/market/policy state before atomic
admission. `/dev/tty` remains an administrative fallback, not the primary
remote UX. Mainnet never uses this weaker chat provenance.

After the configured MCP passes in the foreground, render the matching
`deploy/launchd/com.jawndiego.trading-desk-learning-mcp.plist.example` or
`deploy/systemd/trading-desk-learning-mcp.service.example`. It binds only to
numeric loopback and is not an authenticated public service.

The grant is loaded once at MCP startup. Renew it by issuing a new,
non-overwriting artifact with an incremented generation, verifying/copying its
exact bytes to a new root-owned mode-`0400` research-readable path, updating
the rendered MCP service to that path, and restarting only the MCP service.
Keep the matching control copy for `authorize-stage`; never overwrite or reuse
an expired generation.

Only then run the worker in the foreground. It synchronizes exact fills and
funding, refuses stale/incomplete daily-loss coverage, performs startup
reconciliation before READY, serializes safety ahead of new entry, always uses
the three-leg mandatory-stop group, and drains bounded safety work on SIGTERM:

```sh
sudo -u trading-executor -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor run --config /etc/trading-desk/testnet-executor.toml --worker-id isolated-testnet-worker
```

After foreground qualification on macOS, render
`deploy/launchd/com.jawndiego.trading-desk-executor.plist.example`. It contains
no shell, environment override, credential value, mainnet switch, or agent
interface. A supervisor restart never bypasses startup reconciliation. Linux
execution is unsupported until a reviewed non-Keychain secret provider exists;
the systemd templates in this repository are for credential-free research/MCP
processes, not the executor.

Install the rendered executor and learning-MCP plists with admin ownership and
mode `0644`, then use their exact system labels:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.jawndiego.trading-desk-learning-mcp.plist
sudo launchctl print system/com.jawndiego.trading-desk-testnet-executor
sudo launchctl print system/com.jawndiego.trading-desk-learning-mcp
sudo launchctl kickstart -k system/com.jawndiego.trading-desk-testnet-executor
sudo launchctl kill SIGTERM system/com.jawndiego.trading-desk-testnet-executor
sudo launchctl kill SIGTERM system/com.jawndiego.trading-desk-learning-mcp
sudo launchctl bootout system /Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.jawndiego.trading-desk-learning-mcp.plist
```

If a transient internal failure leaves a sticky halt after the owning service
lease has expired, inspect `status`, then acknowledge only its exact revision
and reason from the attended control terminal:

```sh
sudo -u trading-control -- /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /opt/trading-desk/current/executor/.venv/bin/trading-harness-executor acknowledge-halt --config /etc/trading-desk/testnet-executor.toml --expected-revision REVIEWED_REVISION --expected-reason internal_error
```

The command requires an exact `/dev/tty` phrase, loads no credential, performs
no venue write and leaves the risk gate HALTED. It opens only the execution
database, so the attended control identity needs no nonce, daily-loss or
control-socket access. Restart still has to complete startup reconciliation
before READY.

## Health, restart and graceful-stop checks

An operator check should verify all of the following:

1. Supervisor reports one running process, without a restart loop.
2. `trading-harness doctor` remains fail-closed.
3. `trading-harness node status` reports `capability: research_only`, venue
   writes disabled, credential loading disabled, an active lease and fresh
   heartbeats for registered assets.
4. The research-private database and research logs remain owned by the research
   identity and are not group/world writable; shared learning mains remain
   executor-owned.
5. Filesystem usage, log growth, request errors and clock offset remain within
   locally declared limits.
6. `trading-harness-executor status` shows one current fenced lease, a fresh
   heartbeat, exact config binding, complete fresh loss coverage, and no
   unresolved reconciliation/protection work before it can report READY.
7. The executor log contains no address, Keychain label, secret, raw venue
   payload, approval token, or browser evidence; status uses fingerprints.
8. The learning review advances with command/fill evidence, or explicitly
   reports missing path/outcome evidence; it never silently declares profit.
9. Mainnet remains absent from config, signer, store, transport and service
   arguments.

Stop through launchd/systemd or send `SIGTERM`; do not use `kill -9` during
normal operation. A signal received before the final entry submission guard
prevents the send; once that guard has consumed the one-shot authority, the
bounded send is the point of no return and is reconciled before shutdown. The
CLI signal handler completes the current bounded cycle,
marks runtime `stopping` then `stopped`, and releases its lease. After the
supervisor reports stopped, run the applicable node/executor status command and
retain the result with the change record.

## Backup and recovery

Define an RPO, RTO, retention period and restore owner before unattended use.
SQLite uses WAL mode, so copying only `research.sqlite3` while the process is
running can create an inconsistent backup. Prefer one of these procedures:

1. Gracefully stop the node, verify it is stopped, then copy the database with
   mode `0600`; or
2. Use the SQLite CLI's online backup operation against the explicit database:

```sh
sqlite3 /var/db/trading-desk/research/research.sqlite3 ".backup '/absolute/backup/research-YYYYMMDDTHHMMSSZ.sqlite3'"
sqlite3 /absolute/backup/research-YYYYMMDDTHHMMSSZ.sqlite3 "PRAGMA integrity_check;"
```

`PRAGMA integrity_check` must return `ok`. Store backups outside the live state
directory with access limited to the research backup operator. Do not put
executor keys, authorization tokens or browser/X credentials in this
backup set.

Back up execution, nonce, daily-loss, staging and learning databases as one
documented consistency set after a graceful executor stop. Never restore only
the outbox without its nonce/reconciliation state, copy a live WAL database as
a lone main file, or reuse a restored API wallet against two active executor
instances. Grant artifacts and config contain no raw secret but remain
owner-only deployment authority and belong in a separately controlled backup.

For a restore drill: stop the service, preserve the failed database and WAL
sidecars for investigation, restore a verified backup to a new file, set the
reviewed owner/mode, point a staging node at it, run `node status`, then start
one cycle under observation. Never start two nodes against copied states with
the same production node identity. Record achieved RPO/RTO and reconcile gaps
from source evidence; do not silently forward-fill missing candles.

## Clock discipline

All evidence, expiry, lease and freshness decisions use UTC instants. Enable
the host's supported network-time service and alert on loss of synchronization
or excessive offset. On macOS inspect network time with:

```sh
sudo systemsetup -getusingnetworktime
sudo systemsetup -getnetworktimeserver
```

On systemd-based Linux inspect and enable synchronization with:

```sh
timedatectl status
sudo timedatectl set-ntp true
```

After sleep, reboot or a large clock correction, confirm synchronization and
fresh node heartbeats before relying on new research output. Clock uncertainty
must halt freshness-sensitive decisions; changing the wall clock is not a
recovery technique.

## Qualification terminal boundary

`trading-harness-qualification` is installed separately from the MCP and the
ordinary executor CLI. Its credential-free `collect` and `verify` commands and
executor-only `status`/`recover` inspection do not enable venue writes. Fresh
attended canary authorization collects and exports evidence in the same
control-UID process before reading the fixed approval-HMAC slot from the
control role helper; confirmation is accepted only from `/dev/tty`. Do not put
that confirmation, an HMAC, worker identity, action, nonce, endpoint or payload
in argv, stdin or an environment variable.

The full signed envelope artifact is a bearer-sensitive relay capability. Its
fixed hashed name, pending file, final file and completion receipt live only in
the executor-owned nonce parent. That parent and every artifact must have no
named ACL; runtime checks owner/mode/ACL and applies file plus directory
`F_FULLFSYNC` around exclusive publication. Retain terminal artifacts for
audit; never copy them into the execution/control-shared parent.

The public split prepare/sign commands are disabled, and `run` fails before
config/state/Keychain/network while qualification submission remains compiled
off. The full bounded run now composes place, paired CLOID/OID reads, cancel and
terminal reconciliation. An expired proven-unsent cancel retains reservation;
one fresh attended, read-proven-open same-CLOID successor may use a new permit,
action, envelope and global nonce. It never becomes a blind retry. Both PRE_KEY
and PRE_SEND require fresh paired `userRole` reads bound through attempt
evidence and submission authority. Live promotion still requires enabling the
compiled gate through review and exercising this complete path against TESTNET.

## Promotion boundary

The research deployment proves continuous evidence collection. The isolated
worker can separately prove TESTNET mechanics and produce learning evidence;
that does not establish strategy profitability or mainnet safety. Do not add a
private key or execution command to a research/agent template. Install the
TESTNET service only after the live checklist in
`docs/testnet_qualification.md` passes. Mainnet remains a separate future
architecture and is hard-disabled in this build.
