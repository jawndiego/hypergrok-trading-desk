# Security

## Current status

This branch has no configured or qualified live account. It contains an armed
TESTNET-only signer, one-shot transport, entry/recovery dispatchers, typed
reconciliation, and a macOS Keychain reader. Mainnet is hard-disabled and no
installed Codex/MCP tool can reach the execution boundary.

The packaged ChatGPT/Codex plugin and OpenCode connection expose fifteen
bounded research/learning tools. Five write only local research, analysis,
sentiment or all-false-authority staging state. They cannot create a trusted
approval, reserve execution risk, reach the signer, submit, modify, or cancel
an exchange order.

No released version is currently supported for capital-bearing use.

## Report a vulnerability

Use this fork's GitHub **Report a vulnerability** flow to open a private security advisory. Never place private keys, seed phrases, signatures, wallet exports, authorization tokens, account payloads, or exploitable details in a public issue.

## Trust boundaries

- Agents, prompts, webpages, imported repositories, generated code, research data, and external messages are untrusted.
- An agent role or `writes_to_exchange` label is not an authorization boundary.
- Agents must never receive exchange signing credentials or direct venue-write capability.
- MCP tool annotations are advisory; authorization and validation are repeated inside every handler. Local research writes confer no capital authority.
- A separate, unregistered TESTNET stdio MCP has one raw `command_text` field
  and can only forward one request to a fixed local AF_UNIX approval broker. It
  is not in the research plugin/OpenCode surface and cannot access proposal
  economics, credentials, execution state, admission, signing or venue I/O.
- The signer code must run under a separate security principal with a narrow typed API, explicit account/network/asset/recovery-CLOID/action allowlists, restricted egress, and managed key storage. Checked-in service templates do not provision or qualify that principal.
- The optional Ubuntu VM is a network-only local router. It receives no venue
  credential, executor state, repository mount or authority. Its
  `local_nat_lab` profile keeps the existing public IP and cannot prevent a
  macOS process from bypassing the VM; it is not a VPN or capital boundary.
- Capital HTTP clients ignore ambient urllib proxy discovery, and executor
  config rejects proxy, CA-bundle and TLS-key-log environment variables. Route
  selection and trust roots may not be silently replaced by a login shell.
- Human approval must bind the exact staged risk ticket. The current installed
  TESTNET CLI reads confirmation directly from `/dev/tty`. The offline weaker
  chat lane recognizes only exact `execute trade <proposal-id>` for an already
  stored, fully bound proposal; bare/free-form/piped text is invalid, and its
  receipt always records `human_message_attested=false`.
- `/dev/tty` is an attended TESTNET gesture, not cryptographic proof of a
  human. Running an agent shell under the control/executor UID is unsupported;
  production separation depends on distinct OS identities, file ACLs and
  Keychain ACLs. Mainnet would require independent hardware-backed user
  presence/MFA rather than this HMAC/TTY mechanism.
- Risk admission, authorization consumption, portfolio reservation, and durable outbox creation must be atomic before network I/O.
- Execution-store schema v13 adds explicit non-HMAC chat provenance, atomic
  ticket/risk/command/legs/outbox admission and normal PRE_KEY/PRE_SEND role
  rows. Schema v14 binds the signer account addresses and signing interval into
  signed evidence, and binds each normal transport outcome to the exact
  submission authority and PRE_SEND evidence with causal timing checks.
  Schema v15 accepts chat admission only from the fixed UID-451 verified-file
  reader and persists the exact executor-config scope plus delivery source
  hashes. Schema v16 additionally persists and revalidates the complete
  canonical ancestor, owner/mode/inode, named-ACL and file-byte evidence; the
  public store API accepts only a handoff ID and invokes the fixed reader
  itself. None of these offline schema boundaries installs a publisher,
  listener, credential or venue capability.
- Unknown venue outcomes remain reserved and must be reconciled; they are never blindly resent.
- A prepared attempt, fresh dispatch attestation, nonce, action hash and wire hash are durable before the one permitted send. Recovery actions are limited to reduce-only close, owned-CLOID cancel and same-nonce noop fencing.
- Entry submission additionally holds a revocable runtime guard across final
  authority consumption and the bounded one-shot send. Shutdown/halt before
  that point blocks transmission; afterward the attempt is allowed to finish
  and must be reconciled as the point of no return.
- Recovery close, role-aware cancel and same-nonce noop use the same durable
  permit/outbox/attempt/transport/reconciliation path. Every result still
  requires fresh venue/account reconciliation and unknown outcomes are never retried.
- Signer, approval, recovery and grant Keychain items are distinct. Dynamic
  entry/stop/target CLOIDs are trusted only from the immutable three-leg plan;
  recovery-close CLOIDs are independently derived from the incident and fresh
  position snapshot and revalidated inside the live signer.
- `/usr/bin/security` is not a credential-provider path. Two native hardened
  readers compile distinct executor/control UID, path and slot allowlists and
  expose only pipe-bound retrieval from the explicit System Keychain. Config
  schema v3 binds their fixed labels. Real provisioning and execution remain
  blocked until the hash-pinned helpers are installed and sacrificial positive,
  negative, cross-role and post-reboot probes pass.
- The agent/MCP identity cannot open executor-private execution, nonce,
  daily-loss or control-socket state. Only staging and learning databases live
  in the narrowly ACL-scoped shared-learning directory; agent quotes defer the
  authoritative daily-loss decision to the executor's same-cycle refresh.
- The attended control identity may write the execution database and shared
  staging/learning state required for exact authorization, but it receives no
  directory capability for nonce, daily-loss or control-socket state.
- The chat proposal database is separate control-plane state. Its adapter
  requires a canonical current-UID mode-0700 parent and mode-0600 regular
  single-link database/WAL/SHM files. Live use remains forbidden until named
  ACLs, the fixed socket parent/node, stale-node handling and broker generation
  are verified so UID 501 can connect but cannot read, create, replace or
  delete control state.

### Config-bound state ownership

Executor config schema v3 binds three distinct, non-root numeric identities:
`executor_uid`, `research_uid`, and `control_uid`. They are included in the
canonical config hash; a v1 config or v1-bound state set is not silently
migrated, rebound, or recreated.

| SQLite artifact | Allowed owner UID |
| --- | --- |
| Every main execution, nonce, daily-loss, staging, or learning database | Executor only |
| Execution `-wal`, `-shm`, or `-journal` | Executor or attended control |
| Staging/learning `-wal`, `-shm`, or `-journal` | Executor, attended control, or research |
| Nonce/daily-loss `-wal`, `-shm`, or `-journal` | Executor only |

The sidecar exceptions are not a general shared-owner rule. An empirical
macOS WAL probe showed that an executor-created main database remains
executor-owned while a control-first WAL session creates control-owned WAL and
SHM files; the executor could read and write those files through the exact
inherited ACL. Rejecting them solely because their owner differs would turn a
valid attended write into a restart failure. Main database ownership therefore
never widens, and no sidecar owned by root, an unknown UID, or research in the
execution-private directory is accepted.

Mode `0600` alone does not describe named macOS ACL access. Deployment must
also prove the exact reviewed ACLs and negative access for the research UID.
Cross-UID SQLite parents remain executor-owned mode `0700` and grant no
`delete_child`. Before executor `init`, inherited file ACEs deliberately omit
`delete`, so exclusively reserved mains cannot be swapped during schema
composition. Only after `init` are the inherit-only directory ACEs extended
with file-level `delete`; that applies to future sidecars, not existing mains.
Unlink/rename/replacement denial is tested under every non-owner role. This
prevents a shared-state writer from swapping a checked main path into an
executor confused-deputy open.

Strict verification creates a mode-`0700` temporary directory beside the
source database, not under ambient `TMPDIR`, and removes it on completion.
Cross-UID parent ACLs therefore allow `list,add_subdirectory` but still no
`delete_child`; an inherit-only directory ACE grants each permitted role
`delete` on the verification directory it creates so normal cleanup works.
Quota headroom includes one bounded snapshot copy. Runtime validation detects a
crash-left verification directory and stops for root review/removal.
The attended CLI and MCP entry points set umask `0077` before state composition
so control-first or research-first SQLite sidecars cannot inherit an ambient
`0022` mode. The identity policy also fail-closes role drift: non-validation
executor commands require
`executor_uid`, attended commands require `control_uid`, and configured MCP
startup requires `research_uid`. None of this enables mainnet; mainnet remains
hard-disabled in config, store, signer, and transport.

Existing-state opens are verification-only before use: they require current
schema, migration history, durable binding and integrity and never create,
migrate, repair, or bind an existing file. `init` requires every configured
state directory to be empty and rejects reruns or partial layouts.

Each shared learning/staging main or sidecar has a live 64 MiB application cap.
The 1 GiB private-file limit is a strict existing-open ceiling; live private
growth is bounded operationally by the executor volume quota and a lower
shutdown threshold. Shared verification failure enters a recovery-capable
degraded composition.
Learning projection and all entries fail closed, while reconciliation and
account-safety lanes continue from independently verified execution, nonce and
daily-loss state. Urgent reconciliation/recovery ticks skip learning scans
entirely; projection resumes only after the safety lane clears. Entry dispatch
also requires successful same-tick learning synchronization and bounded append
headroom, alongside the existing same-tick daily-loss refresh. Once a venue
write is attempted, post-step learning is skipped until reconciliation clears
the safety-priority lane.

Application caps do not bound the research-private database, logs, or every
filesystem write by the research UID. Deployment MUST put all research-writable
growth on a separately quota-limited volume and retain an executor-private
capacity reserve that research cannot consume. Until that quota and an
exhaustion probe pass after reboot, resource isolation is unqualified and
always-on operation is forbidden.

The local router and machine setup do not make the live checklist executable.
The qualification-only GTC/query/cancel, retained snapshot, attended-close and
fresh same-CLOID cancel-successor semantics have a separate TESTNET-only
durable core, pinned SDK signer/recovery verifier, dormant sender and bounded
foreground lifecycle; submission remains compiled off. The chat proposal CAS,
mutually peer-checked protocol/client, stdio MCP, typed issuer/presentation,
verified handoff reader and schema-v13-v16 admission/fencing boundaries likewise
remain offline. They still lack authenticated account/market collector
composition, same-process issuer/listener lifecycle, installed presentation and
handoff publishers/consumers, exact named ACLs, Keychain qualification and live
end-to-end evidence. The first harness order write is forbidden until these and
the commissioning sequence in
[`docs/testnet_commissioning.md`](docs/testnet_commissioning.md) are closed.

The normative requirements are in [`docs/trading_harness_spec.md`](docs/trading_harness_spec.md).

## Forbidden until explicit qualification

- Any harness-originated TESTNET order/cancel/recovery write before its exact
  qualification step, and any mainnet exchange write.
- Treating the separately attended out-of-band `approveAgent` registration as
  harness qualification evidence. API-wallet registration is an account
  prerequisite and still must occur outside agents/chat/repository.
- Treating the local testnet HMAC approval helper as suitable for mainnet; mainnet requires a later independently reviewed hardware-backed/asymmetric authority.
- Enabling the TESTNET chat MCP/broker before its fixed listener, socket/state/
  presentation/handoff ACLs, authenticated collectors, same-process issuance,
  installed handoff publisher/consumer and live schema-v14 send-time identity
  and outcome fences are commissioned; using it for mainnet is always forbidden.
- Loading an API-wallet or main-wallet key.
- Transfers, withdrawals, bridges, vault/subaccount fund movement, builder fees, or staking actions.
- Enabling an adapter by environment variable alone.
- Running copied upstream snippets against an account.
- Treating an agent, backtest, indicator match, or social post as deployment authorization.

## If a credential is exposed

1. Revoke it at the venue immediately.
2. Halt new admission and preserve existing protective exits.
3. Reconcile orders, fills, positions, and non-funding ledger changes from the last known-good point.
4. Rotate affected credentials and service identities.
5. Preserve redacted evidence and open a private incident review.

## Supported versions

| Version | Capital-bearing support |
| --- | --- |
| Unreleased foundation | No |
