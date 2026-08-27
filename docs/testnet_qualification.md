# Hyperliquid testnet qualification

Status: **offline capital core, credential-free signer-envelope, pinned SDK
0.24.0 signer/independent recovery verifier, dormant one-shot sender,
advisory WebSocket decoder/local response-drop harness and schema-v12
result/workflow persistence plus a role-bound full-lifecycle direct-terminal
orchestration surface implemented; submission promotion, commissioning and live
adapter gaps remain; live venue qualification not run**.

The ordinary isolated TESTNET executor contains a real write boundary. The
qualification worker is complete but its submission authority is compiled
off. No account, API wallet or worker service is configured by the repository,
and no Codex/MCP tool can invoke either capital path.

This checklist is a release gate, not a setup shortcut. Unit tests, local paper
fills and valid SDK signatures do not prove that an API wallet is registered to
the intended account or that venue recovery works.

The current attended approval-HMAC path reads exact confirmation from
`/dev/tty` and remains the administrative fallback. A separate future TESTNET
provenance lane is reserved for the exact `execute trade <proposal-id>` command
over an immutable, short-lived proposal binding entry, size, stop, target,
maximum loss, account and policy. It is not implemented; a bare command or
free-form chat is invalid, and no chat-facing surface may receive the signer or
execution store.

## User-provided prerequisites

Provision outside Codex/chat and outside the repository:

- a dedicated Hyperliquid testnet main/subaccount address;
- a newly registered API wallet used only by the isolated testnet signer;
- fresh `userRole`/agent evidence that the API wallet still maps to the
  intended main account/subaccount and has not been pruned or replaced;
- testnet collateral/faucet eligibility;
- a dedicated non-login OS identity and private credential store;
- separate file-backed execution, nonce, daily-loss, staging and learning
  databases, with execution/nonce/daily-loss/socket in distinct writable
  parents so attended-control SQLite access cannot reach the other
  executor-private artifacts;
- explicit account, asset, notional, loss and 2x leverage caps;
- the standard `default`/`disabled` account mode, not unified or portfolio margin.
- a currently supported macOS security release, followed by reboot and runtime
  requalification;
- a qualified network path. The checked-in local Ubuntu router profile is only
  `local_nat_lab`: it preserves the existing public IP and does not prevent
  host bypass.

Never paste the API-wallet private key into a task, config committed to Git,
environment variable visible to the agent, issue, log or test fixture. The
research/MCP/Codex OS identity must not be able to read the signer or recovery
credentials. Approval and grant HMAC items are also distinct from the signer.

For a boot-time macOS LaunchDaemon, use the explicit System keychain configured
in every credential stanza. Do not use `security add-generic-password` for a
real secret: its interactive form cannot safely combine a final prompt option
with the explicit positional System keychain, and omitting that path can select
the desktop login keychain. Do not trust `/usr/bin/security` as the Keychain
application ACL either; every local role can invoke that shared executable.

Provisioning remains blocked until a reviewed, root-owned role-restricted
helper is installed and bound into the provider. First qualify the helper with
a sacrificial value: positively test the intended executor/control UID,
negatively test all other service and desktop UIDs, reboot, and repeat. Only
then provision the signer plus independent approval, recovery and grant HMAC
items. Do not rely on a login-keychain search list or `HOME` in a LaunchDaemon.
The executor reader admits only UID/GID 451 slots `signer` and `recovery`; the
control reader admits only UID/GID 452 slots `approval` and `grant`. Labels are
fixed by executor config schema v3 and the native binaries; UID 450, UID 501
and cross-role calls must fail before Keychain access.

The harness only reads that item, verifies the derived public signer address,
and zeroes its command-output buffers. It has no credential provisioning,
export, environment-variable, or plaintext-file path.

Install the reviewed commit non-editably into the sealed, root-owned Python
3.11 execution environment using the hash-checked wheelhouse described in
[`always_on_operation.md`](always_on_operation.md). Do not run the service from
an editable checkout or a user-writable Homebrew runtime. Installing
dependencies does not enable execution.

Render the strict executor config from
`deploy/config/testnet-executor.toml.example`. Schema v3 requires the exact
numeric UIDs of three distinct non-root executor, research, and attended-control
identities. Validate and initialize it with `trading-harness-executor validate`
and `init` under the configured executor UID. Retain the redacted config hash
and confirm `status`/`dry-run` load no credential and make no network call.

Before `init`, retain a root-reviewed directory/ACL report. After `init`, the
required ownership matrix is:

| Database | Main-file owner | Allowed sidecar owners |
| --- | --- | --- |
| Execution | Executor | Executor or attended control |
| Nonce | Executor | Executor only |
| Daily loss | Executor | Executor only |
| Staging | Executor | Executor, attended control, or research |
| Learning | Executor | Executor, attended control, or research |

“Sidecar” means only the exact `-wal`, `-shm`, or `-journal` path for that
configured main database. Every artifact must remain a regular, single-link,
mode-`0600` file with the reviewed ACL. The owner exception never applies to a
main database. The control socket remains executor-only.

Retain the macOS first-writer probe as evidence: executor-first execution WAL
and SHM files are executor-owned; control-first WAL and SHM files are
control-owned while remaining readable and writable by executor through the
exact inherited ACL. Reopen the control-first database under the executor UID.
The attended CLI and configured MCP must establish umask `0077` even when
launched from a shell whose ambient umask is `0022`.
Prove wrong-UID executor/control command dispatch and wrong-UID configured MCP
startup fail before a database, grant, Keychain item, or venue client is opened.

On the execution and learning-shared parents, prove control/research have no
`delete_child`. Before `init`, inherit read/write/read-attribute but no delete;
after `init`, add delete only to future-file inheritance so existing durable
mains remain non-deleteable and new SQLite sidecars are cross-cleanable. Retain
negative unlink, rename and atomic-replacement probes for execution, staging
and learning mains, plus positive cross-owner WAL/SHM cleanup. Do not proceed
if main-path replacement is possible under either non-executor identity.
Permit only the additional direct `list,add_subdirectory` rights required for
stale-snapshot detection and a
mode-`0700` verification snapshot beside each DB. Prove snapshots never use
ambient system temp, clean up normally, remain inside the intended quota, and
receive only the inherit-only directory `delete` ACE needed to remove their own
snapshot. They must leave a crash artifact that causes an attended root-review
stop detected by runtime validation; parent `delete_child` remains forbidden.

Config schemas v1 and v2 are rejected, and the exact v3 UIDs are bound into the
canonical config hash. There is no silent state migration, config rebinding,
or empty-database recreation.
On this new machine, run `init` only after proving no harness state exists. If
any v1-bound or other nonempty state is discovered, preserve its main and
sidecar files and stop for a separately reviewed migration.
Execution schema v12 also refuses automatic migration of any nonempty
schema-v11 qualification lane, including retained snapshots without a command.
Preserve and quarantine such a database; require a separately reviewed
migration or a proved-empty new deployment, never an in-place rewrite.
The single global nonce database now initializes only at schema v2 and binds
qualification nonces atomically to their action and signing authority. An
existing nonce schema-v1 database fails closed pending an explicit migration;
no such migration exists, and no nonce database exists on this machine.

## Known blockers before the live sequence

The target live sequence below is intentionally stronger than the currently
exposed CLI. Do not skip its first steps by sending the already-armed bracket.
The GTC/cancel/close semantics, dedicated signer-envelope validator and durable
schema-v12 result coordinator now exist. The exact pinned SDK 0.24.0 signer and
independently reconstructed EIP-712 recovery verifier are golden-tested for all
three action shapes and use the schema-v2 global nonce authority. The separate
`trading-harness-qualification` CLI exposes fixed control-UID
collect/verify/fresh attended authorization and executor-UID
status/recover/reconciliation phases. Its `run` command checks the compiled-off
submission gate before config, state, Keychain or network access; split
prepare/sign commands are not public. The dormant worker composes the full
bounded place, paired-query, cancel and terminal reconciliation lifecycle. The
following promotion, live integrations and observable tests remain:

- promotion and attended exercise of the implemented full `run` lifecycle;
  until then its compiled gate makes it operator-inaccessible;
- attended live exercise of the implemented one-successor cancel path. An
  expired proven-unsent cancel retains reservation; only a newly attended,
  read-proven-open same-CLOID action with a durable issued-to-consumed permit,
  new envelope and new global nonce may follow it;
- attended live exercise of the implemented two-read
  `userRole(api_wallet)` attestations immediately before key use and send. The
  complete PRE_KEY/attempt/PRE_SEND chain and PRE_SEND expiry are durable; a
  pause past that fence after authority records UNKNOWN and performs no HTTP;
- attended live qualification of the implemented `userRole` reader and
  owner-only account/metadata/order artifact export;
- live attended integration for the ordinary bounded reduce-only canary close;
  its signer and offline terminal-flat release are implemented;
- a live adapter and durable integration for the credential-free advisory
  WebSocket client/decoder, followed by an attended disconnect/fill/REST
  recovery exercise; official `orderUpdates`/`userEvents` carry no gap-free
  sequence, so the offline monitor deliberately requires REST after connect,
  every event and every disconnect; timestamp-less variants remain advisory
  even after a later REST request with a strictly advancing server watermark;
- attended fault injection that forwards one real exact request while dropping
  its response; the bounded loopback accept/drop/crash/no-resend harness passes
  offline but is not evidence of a live forwarded request;
- optional application-level router health if router readiness is to be an
  admission gate rather than an OS-only failure boundary.
- installed and empirically qualified free-space shutdown guards plus a
  deterministic qualification artifact builder/signing workflow.

The ordinary always-on signer still accepts only the mandatory three-leg
`normalTpsl` group with IOC entry. The separate qualification
envelope/recovery-verifier and full worker remain compiled-off offline
contracts, and runtime monitoring is REST polling.
Machine setup and credentials alone therefore do not make the
first harness order write responsible. API-wallet `approveAgent` registration
is a separate attended out-of-band account-provisioning write, not harness
order qualification. See
[`testnet_commissioning.md`](testnet_commissioning.md).

## Offline gates

Before connecting the signer process, retain passing evidence for:

1. exact plan/ticket/approval/preflight hash round trips;
2. one-time approval and one nonterminal command for the dedicated account;
3. concurrent nonce uniqueness and restart/clock rollback;
4. official SDK 0.24.0 golden signer recovery;
5. persist-before-send and one-shot unknown-outcome behavior, including the
   qualification lane's exact account/API-wallet envelope, one action/nonce/wire
   per phase, response-loss and post-authority crash reconciliation with no
   retry, paired CLOID/OID action/economic identity, bound cancel, and
   venue-watermark-ordered terminal-flat canary reservation release;
6. full, partial and unfilled paper IOC cases;
7. rejected/disappearing/undersized stop detection;
8. reduce-only close, owned-CLOID cancel and same-nonce noop construction;
9. crash-before-send, crash-after-attempt and tamper tests;
10. research strategy and deployment authority remaining independent.
11. single-use recovery signing/submission authority, exact noop-default
    response persistence, expired-unsent permit terminalization, and parent
    risk release only after terminal-flat reconciliation.
12. complete fills/funding coverage from UTC midnight to a fresh exact query
    watermark, with retention, pagination, schema and clock gaps failing closed;
13. staged-ticket, approval, command, parent/recovery fill, fee, latency and
    venue-reported PnL projection into the immutable learning ledger,
    including incomplete-read replay;
14. exact venue-server fill-window watermarks, canonical cross-lane fill
    attribution, parent-stop/recovery-close interleaving, and late recovery
    requests remaining blocked until signed expiry plus settlement grace;
15. the research/MCP UID failing read/write access to execution, nonce and
    daily-loss state, while every entry requires a complete same-tick loss
    refresh even across an IDLE-preview/admission race.
16. the exact v3 UID binding and main/sidecar owner matrix, including a
    control-first execution WAL/SHM followed by a successful executor reopen;
17. ambient-`0022` attended CLI launch still producing mode-`0600` SQLite
    sidecars, with extra ACL principals, wrong owners, hard links, and
    symlinks all failing closed;
18. config v1/v2 and nonempty earlier-schema state being rejected without mutation,
    credential loading, database recreation, or venue I/O.
19. `init` rejecting both a complete rerun and every partial existing/missing
    state mixture without changing any inode or byte;
20. existing-only opens rejecting zero-byte, schema-less, wrong-role, drifted
    or integrity-invalid databases without creating, migrating or rebinding them.
21. oversized and integrity-invalid shared learning failing fast, blocking all
    entries, and still allowing core startup reconciliation and each documented
    account-safety recovery lane from independently verified private state.
22. exhausting the research UID's dedicated storage quota without consuming
    executor-private reserve or preventing a nonce/daily-loss/execution WAL
    commit; and independently approaching the executor-volume shutdown
    threshold must halt before the 1 GiB reopen ceiling while retaining tested
    emergency WAL/recovery headroom, both before and after reboot.
23. executor config rejecting upper/lowercase proxy variables, CA-bundle
    overrides and TLS key logging, while the real urllib info/exchange openers
    contain an explicit empty `ProxyHandler` before their redirect-deny handler;
24. the rendered Ubuntu router manifest and nftables/WireGuard state matching,
    with no `PrivateKey` field, retained public-key provenance, and explicit
    evidence that local mode retains the host public IP and permits host bypass;
25. VM stop, WireGuard loss, hypervisor stop, sleep/wake, DHCP renewal, reboot,
    IPv6, alternate DNS and QUIC paths, including durable unknown-outcome
    behavior and no resend when routing fails around a write.

## Live testnet sequence

Run only after the known blockers above are closed, with minimum notional and
a hard operator stop condition. Persist every request identity, response hash,
account snapshot, router manifest/health result and reconciliation result.

1. Retain clock offset, fresh API-wallet `userRole`, `userAbstraction`, metadata,
   account state and frontend-order evidence. Verify the signer maps to the
   intended account, the account is flat and there are no foreign orders.
2. With the ordinary attended reduce-only close already qualified, place a far
   non-marketable GTC test order with an owned 128-bit CLOID, query it by
   CLOID/OID, and cancel it within a bounded timeout. If it fills unexpectedly,
   halt and flatten through the prequalified close path; prove terminal-flat.
3. Only after the canary is terminal, issue a short-lived
   `profitability_qualified: false` infrastructure grant, run one Codex/ChatGPT
   analysis, stage its exact hash, and prove every staging authority flag is
   false. Review and authorize it through the current direct-terminal
   administrative fallback; a future proposal-ID chat lane may replace this
   step only after its separate durable provenance is implemented and
   qualified. Preserve the learning cycle and command IDs.
4. Submit a minimum-size long IOC + reduce-only SL + TP as `normalTpsl`.
   Accept only a full entry plus an independently visible stop covering the
   exact signed position.
5. Reduce-only close to exactly flat; verify children/orphans are terminal.
6. Repeat the full lifecycle short.
7. Create a tightly bounded partial IOC. Prove the children are not relied on,
   a critical incident is durable, and the priority reduce-only flatten leaves
   the account flat.
8. Drop a real HTTP response after forwarding. Recover by CLOID/account state;
   do not send a replacement entry. Exercise the same-original-nonce noop only
   through its durable incident-bound recovery command. Treat only the exact
   documented `{"status":"ok","response":{"type":"default"}}` body as an
   accepted fence; every other body remains unknown.
9. Disconnect WebSocket monitoring across a fill, then recover through REST
   without duplicate events or fills.
10. Simulate stop rejection/disappearance and prove account-wide new risk is
   halted before recovery.
11. Restart every worker at its documented crash points. Finish with zero
    position, zero open/orphan orders, zero unresolved attempts, zero reserved
    risk, verified event chains and reconciled fills.
12. Review the final learning cycle and exact-version aggregate. Confirm that
    missing market-path/funding/close evidence is flagged rather than inferred,
    and that no report upgrades the experiment into a profitability claim.

Do not use Hyperliquid `scheduleCancel` while a position depends on a venue
stop: it cancels all open orders, including protection.

## Qualification artifact

The signed review artifact must identify the reviewed commit, SDK/package lock,
testnet account and API-wallet public addresses, database identities, asset
metadata hashes, Ubuntu image/hypervisor and rendered router-bundle hashes,
observed egress IP, each test command/CLOID/nonce, UTC times,
raw-response hashes, final account snapshot, incidents and reviewer identities.
It contains no private key or reusable approval token.

Any unresolved or contradictory state fails qualification. Re-running after a
code, dependency, account-mode, signer, policy or venue-contract change creates
a new artifact.

## Mainnet boundary

Testnet qualification proves mechanics only. It does not establish strategy
profitability or mainnet execution quality. Mainnet remains hard-disabled until:

- testnet passes this complete sequence;
- a strategy independently passes historical and prospective shadow gates;
- a separate mainnet OS identity, API wallet, database and asymmetric/hardware
  approval authority are reviewed;
- a capped account and 0.10% equity-risk canary policy are approved.
