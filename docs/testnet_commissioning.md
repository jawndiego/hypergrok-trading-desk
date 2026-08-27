# TESTNET commissioning and first-write gap register

Status: **offline engine, schema-v12 qualification core/result coordinator,
credential-free signer-envelope, pinned SDK 0.24.0 signer and independent
recovery verifier, dormant one-shot sender, advisory WebSocket decoder and
local response-drop/crash harness, machine plans and guest/VM renderers
and role-bound full-lifecycle qualification orchestration implemented; the
separate TESTNET chat proposal/store/wire/stdio-MCP foundation is implemented;
submission promotion, live qualification, machine apply and network
qualification incomplete; first harness order write remains blocked**.

This document records the remaining work from a reviewed source commit to the
first responsible harness-originated Hyperliquid TESTNET order. It is not
authorization to provision a venue credential, initialize state, start a
worker or call `/exchange`.
The normative live sequence remains `docs/testnet_qualification.md`.

## What is already true

- Mainnet is hard-disabled in configuration, state, signer and transport.
- The executor can sign and submit only its reviewed TESTNET action families.
- Admission, authorization consumption, reservation, outbox and attempt
  persistence are durable before network I/O.
- Unknown outcomes remain reserved and are reconciled; no write is blindly
  resent.
- Python 3.11/3.12/3.13 and pinned MCP/SDK suites have passed on the reviewed
  baseline.
- Three disabled local identities exist in the current machine plan: research
  UID 450, executor UID 451 and control UID 452.
- A private-key-field-free local Ubuntu router profile and deterministic
  renderer exist; operator public-key provenance is still required.
- A separate TESTNET-only qualification core durably represents the retained
  account/agent snapshot, fixed GTC canary, bound cancel and full-residual
  attended close. Its credential-free envelope/injected recovery-verifier
  contract and offline one-shot/result/query/terminal/crash transitions exist.
  Its exact SDK 0.24.0 signer and independently reconstructed EIP-712 recovery
  verifier are golden-tested. Its exact TESTNET one-shot HTTP sender acquires
  authority only from the durable store and atomically records response or
  unknown transitions, but submission authority remains compiled off, so the
  full foreground `run` path cannot reach the sender or a credential. The
  dormant worker already composes place, paired queries, cancel and terminal
  reconciliation under one absolute read deadline.
- `trading-harness-qualification` is a separate non-MCP entry point. Control
  UID 452 may collect/verify an owner-only review artifact and perform fresh
  same-process `/dev/tty` approval-HMAC authorization as an administrative
  fallback. Its issued permit is durably registered and atomically consumed.
  Executor UID 451 may inspect, normalize and reconcile persisted
  qualification state. Public split
  prepare/sign commands are absent. `run` remains dormant and fails before
  reading config or state while submission is compiled off.
- Credential-free final-path APFS/ACL/install and storage-guard artifacts exist
  under `deploy/macos/testnet`; none has been applied.
- A pinned Lima/VZ VM plan exists under `deploy/ubuntu-router/lima`; its apply
  path is absent. The signed snapshot/cloud-image inputs, offline host
  attestations and 116-package no-recommends closure are locked with a
  read-only replay verifier. A root media/host-tool specification is
  implemented but its launcher/apply gates remain false; writable Lima state,
  guest installation and preflight are also disabled.
- A TESTNET-only proposal-v2 model binds the staging document, ticket,
  protected plan, grant, displayed economics, account identity, policy,
  account/market snapshots, broker session and expiry. A separate control
  SQLite adapter durably performs its single-use approval CAS. The bounded
  AF_UNIX handler and client mutually verify UID/GID before request bytes, and
  a separate stdio MCP exposes only `approve_testnet_trade(command_text)`. No
  listener, ACL install, trusted display path or executor admission exists, so
  this is not yet a callable or capital-bearing path.

These facts do not make the machine transaction-ready.

## Venue-credential-free machine work

Complete and retain evidence for every item before provisioning a venue or
Keychain secret. Router-only WireGuard keys are generated during item 6 on
their owning machines because their derived public keys are renderer inputs.

1. **macOS security update.** Completed on the current host on 2026-08-26:
   macOS was updated from 15.3.1 to 26.6.2 build 25G83 and rebooted. On that
   updated host, the pinned Python 3.11.16/OpenSSL 3.5.8 runtime and the current
   1,134-test suite were requalified on Python 3.11, 3.12 and 3.13. Retain that
   evidence and repeat this gate after any later OS/runtime change.
2. **Root inventory.** Seal the exact-commit deployment pack and retain owner,
   mode, ACL, mount, LaunchDaemon and empty-state evidence from an attended
   root console.
3. **Storage quota apply.** Review and seal
   `deploy/macos/testnet/01-provision-apfs-storage.sh`, decide encrypted
   attended unlock versus the script's explicit unencrypted-TESTNET-only
   acceptance, then apply its resumable create/adopt, UUID mount and layout
   phases. Reboot and prove quota/reserve/mount flags. The storage guard exists
   but still needs rendered root-owned config, live threshold and log-retention
   qualification.
4. **Final-path ACL apply.** Review and seal the rollback-safe pre-init and
   post-init scripts under `deploy/macos/testnet`. Apply only the pre-init phase
   before `init`; nonce, daily-loss and socket remain executor-only and no
   cross-UID parent receives `delete_child`.
5. **Admin installation.** Use the exact merged-main offline installer under
   `deploy/macos/testnet` with the sealed runtime and pack. Prove UID 501 and all
   service identities cannot modify or replace source, runtime or venv paths.
6. **Ubuntu router lab.** First render and verify the pinned Lima/VZ VM plan,
   replay the immutable public-input lock and retain only its informational
   receipt. Close and promote the sealed-runtime root launcher before any
   media/host-tool apply; then resolve the non-agent Lima owner, local-image
   config and first-boot APT blockers before provisioning any VM.
   Pass guest preflight before generating the VM and Mac WireGuard private keys
   on their owning machines, derive and
   attest the public keys, then render and qualify `local_nat_lab` using
   `docs/ubuntu_vm_router.md`. It does not change the public IP and does not
   prevent host bypass. Do not call it VPN-qualified. A separately reviewed
   macOS PF/Network Extension or non-bypassable physical router remains a later
   egress-isolation gate; if absent during an attended functional TESTNET
   canary, the qualification artifact must say network isolation is unqualified.
7. **Proxy/trust environment.** Prove the executor rejects ambient proxy and CA
   override variables and that its urllib openers install an empty proxy
   handler. Retain the root-owned CA path and TLS hostname-verification
   evidence.
8. **Public config plan.** Review asset/instrument mapping, recovery CLOID
   allowlist, exact risk caps, UIDs and final state paths. Final account/API
   wallet addresses and config hash are bound after attended API-wallet
   registration. Use MCP port 8765 consistently in service and client configs.
9. **Quota and recovery headroom.** Fill only the isolated research probe to
   ENOSPC and prove executor execution/nonce/daily-loss WAL commits and one
   verification snapshot still succeed. Prove the executor shutdown threshold
   leaves recovery headroom.
10. **Chat-control storage and socket.** Render a separate UID-452-owned
    mode-0700 proposal-store parent and dedicated fixed AF_UNIX socket parent.
    Prove UID 501 can only traverse/connect to the socket and cannot create,
    replace, list or read control state. Add named-ACL inspection, stale-node
    refusal, restart/crash evidence and broker-generation persistence before
    installing either the broker or its unregistered stdio MCP client.

No `init`, venue/Keychain secret, grant issuance, launchd installation or
harness venue write belongs in this phase.

## Remaining promotion and live-evidence gaps

Machine commissioning alone cannot satisfy the published live checklist. The
following rows distinguish implemented-but-unpromoted contracts from remaining
code and attended-evidence gaps:

| Required qualification behavior | Current gap |
| --- | --- |
| Far non-marketable GTC canary, exact query and cancel | Schema-v12 typed envelope, pinned SDK signing/independent recovery, one-shot HTTP sender, response/crash-unknown persistence, paired queries, full foreground loop and terminal-flat release exist offline. A proven-unsent expired cancel retains reservation and permits exactly one fresh attended, read-proven-open same-CLOID successor with a new action/envelope/global nonce. Submission promotion and an attended live exercise remain absent |
| Retained pre-write account/metadata/order snapshot | Exact retained evidence/tamper checks, owner-only artifact export and distinct two-read `userRole` attestations immediately before key use and send are bound through the attempt and durable submission authority. They are implemented and adversarially tested offline but not live-qualified |
| Ordinary attended reduce-only close, including an unexpected GTC-canary fill | Full-residual envelope/result/query, pinned SDK signer/recovery, attended CLI authorization/reconciliation and terminal-flat source-reservation release exist offline; submission promotion and live exercise remain absent; general bracket-parent close is intentionally unsupported |
| WebSocket disconnect/fill/recovery exercise | An injected, credential-free exact TESTNET client/decoder accepts only `orderUpdates` and `userEvents` (`channel: user`) and forces a REST request begun after the causal boundary whose receipt/server watermark covers the event after connect, every advisory event and every disconnect because the official feed has no gap-free sequence; timestamp-less events require strict server-time advance; no live connector, durable event integration or attended exercise exists |
| Forward request but drop the real response | A bounded loopback HTTP harness proves accept-then-drop, crash normalization, reservation retention and no resend; no live forwarding proxy or attended real-request exercise exists |
| Router health as an admission capability | No application router-health field or pre-admission guard exists |
| Executor free-space shutdown threshold | External fail-closed guard and launchd templates exist; root-owned config, real APFS `statvfs`, shutdown and restart behavior are not installed/qualified |
| Signed qualification artifact | No artifact builder/signing workflow exists; the deliverable is still manual |
| Codex chat proposal approval | Proposal v2, durable approval CAS, mutual peer-checked wire/client and exact one-field stdio MCP exist offline. Missing: trusted stored-proposal presentation, fixed listener/ACL service, broker-generation record, at-least-once control-to-executor handoff, atomic `ExecutionStore` chat consume/reservation/outbox admission, and normal-bracket PRE_KEY/PRE_SEND `userRole` fences |

Close the remaining items as narrow TESTNET-only, durable workflows with
observable failure tests. They may not become generic MCP execution tools,
widen signer actions, expose mainnet, or weaken the one-shot unknown-outcome
contract. The current `/dev/tty` HMAC is an administrative fallback. The
offline remote lane recognizes only exact `execute trade <proposal-id>` for an
immutable, short-lived, fully bound proposal and can durably record approval,
but is neither installed nor connected to execution. Bare/free-form chat
remains invalid. Until the live gates pass, the first harness order write
remains blocked.

## Credential provisioning

After the venue-credential-free gates pass:

1. Create or select a dedicated standard-mode Hyperliquid TESTNET account and
   minimum test collateral.
2. Generate and register a dedicated API wallet outside chat and the
   repository. Registration is itself an attended out-of-band `approveAgent`
   `/exchange` write; it is account provisioning, not the first harness order
   or qualification evidence.
3. Query fresh `userRole`/agent evidence for the API-wallet address and retain
   proof that it maps to the intended main account/subaccount and has not been
   pruned or replaced.
4. Generate independent signer, approval, recovery and grant secrets.
5. Install and verify the reviewed, root-owned role-restricted Keychain helper.
   Do not use the shared `/usr/bin/security` executable as the item ACL and do
   not provision through its ambiguous interactive CLI.
6. With a sacrificial value, positively test only the intended executor/control
   helper lookups and negatively test research plus desktop UID access. Reboot
   and repeat; only then provision the four explicit System Keychain items.
7. Render the final public executor config with the lowercase main/API wallet
   addresses, account ID and all previously reviewed values; retain its hash.

Do not put a secret in TOML, an environment variable, argv, a VM profile,
cloud-init, logs, a shared folder or an agent-readable path.

## One-time init and post-init ACL work

1. Preserve a fresh empty-directory, inode, owner, mode and pre-init ACL report.
2. Run credential-free `validate` against the final schema-v3 config.
3. Run `init` exactly once as executor UID 451.
4. Review, seal and run the repo's post-init ACL tool. It may add
   `delete` only to future-file inheritance; it must not modify the existing
   execution, staging or learning mains.
5. Prove durable mains remain executor-owned, mode 0600, single-link and
   non-replaceable by control/research. Prove cross-owner sidecar cleanup,
   snapshot cleanup and the exact owner matrix.
6. Run credential-free `status` and `dry-run`. Wrong-UID commands must fail
   before state, Keychain or network access.

The repo contains a rollback-safe post-init ACL artifact, but it is not yet in
a sealed applied deployment. Its single-use receipt and main-file invariants
must pass on the real quota paths.

Schema v12 deliberately refuses automatic migration when any schema-v11
qualification table is nonempty, including snapshot-only evidence. Preserve
and quarantine that database for review; use a separately reviewed migration
or a proved-empty new deployment, never an in-place rewrite or silent reset.

## Foreground no-write qualification

1. Start the Ubuntu router and activate the Mac full-tunnel peer.
2. Prove read-only `/info`, DNS and TLS work through the VM; record the known
   local-lab host-bypass limitation.
3. Ensure no executable command is queued.
4. Start the executor in the foreground, complete startup REST reconciliation,
   observe READY/no-work cycles, send SIGTERM and retain clean drain evidence.
5. Issue a short-lived infrastructure-only grant, preserve the control copy,
   install its exact root-owned research-readable copy, then start the learning
   MCP on `127.0.0.1:8765`. Stage one document and confirm every authority flag
   remains false.
6. Do not authorize a bracket merely to prove the worker can send. First close
   the qualification capability gaps above.

## First harness order write and full qualification

Before the GTC canary, retain clock synchronization and maximum-offset evidence
and implement/qualify the attended reduce-only close: a far order can still
fill during a market jump. The narrow canary needs minimum exposure, an owned
CLOID, an exact readback, a bounded cancel timeout and an unexpected-fill hard
halt/flatten path. Only after terminal cancellation or terminal-flat recovery
should a grant-backed bracket be staged and authorized, followed by the
three-leg IOC plus mandatory stop/target lifecycle.

Full qualification additionally requires WebSocket disconnect recovery,
response-loss fault injection, tunnel-loss unknown-outcome reconciliation,
long and short bracket lifecycles, partial-fill recovery, stop disappearance,
restart points and a final flat account with no unresolved attempt or reserved
risk.

Launchd remains last. Do not install it until foreground live qualification,
safe log rotation, quota/reboot tests, router boot ordering, clock checks and a
backup/restore drill pass.
