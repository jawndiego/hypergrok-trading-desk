# TESTNET commissioning and first-write gap register

Status: **TESTNET engine, schema-v12 qualification core/result coordinator and
schema-v13-v16 normal-entry/chat-admission/delivery boundary,
credential-free signer-envelope, pinned SDK 0.24.0 signer and independent
recovery verifier, route-bound one-shot sender, advisory WebSocket decoder and
local response-drop/crash harness, machine plans and guest/VM renderers
and role-bound full-lifecycle qualification orchestration implemented; the
separate TESTNET chat proposal/store/wire/stdio-MCP foundation is implemented;
source submission gates promoted; live qualification, remaining machine apply
and network qualification incomplete; first harness order write remains blocked**.

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
  renderer exist. Its guest check now exposes bounded non-secret hashes and
  WireGuard/HTTPS counters for a two-sample health collector. A typed
  five-second route-readiness gate exists and defaults unavailable; operator
  public-key provenance and a trusted live collector are still required.
- A separate TESTNET-only qualification core durably represents the retained
  account/agent snapshot, fixed GTC canary, bound cancel and full-residual
  attended close. Its credential-free envelope/injected recovery-verifier
  contract and offline one-shot/result/query/terminal/crash transitions exist.
  Its exact SDK 0.24.0 signer and independently reconstructed EIP-712 recovery
  verifier are golden-tested. Its exact TESTNET one-shot HTTP sender acquires
  authority only from the durable store and atomically records response or
  unknown transitions. Submission authority now requires exact persisted
  remote-VPN evidence and rechecks it after authority. The foreground worker
  composes place, paired queries, cancel and terminal
  reconciliation under one absolute read deadline.
- `trading-harness-qualification` is a separate non-MCP entry point. Control
  UID 452 may collect/verify an owner-only review artifact and perform fresh
  same-process `/dev/tty` approval-HMAC authorization as an administrative
  fallback. Its issued permit is durably registered and atomically consumed.
  Executor UID 451 may inspect, normalize and reconcile persisted
  qualification state. Public split
  prepare/sign commands are absent. `run` is promoted but fails before
  credentials whenever fixed installed remote-VPN evidence is unavailable.
- Credential-free final-path APFS/ACL/install and storage-guard artifacts exist
  under `deploy/macos/testnet`; none has been applied.
- A pinned Lima/VZ VM plan exists under `deploy/ubuntu-router/lima`. The signed snapshot/cloud-image inputs, offline host
  attestations and 116-package no-recommends closure are locked with a
  read-only replay verifier. Its schema-v3 root launcher enables only
  venue-credential-free runtime qualification, media/host-tool preparation,
  exact UID-454 Lima-home adoption, `validate --fill`, a dedicated VM-management
  SSH key whose private and public files are both mode `0600`, local-image
  installation and stopped-VM creation; the schema-v3 lock admits only the
  exact retained pre-fix management-key marker/controller recovery and one
  exact completed schema-v2 key-receipt continuation. Its local-image recovery
  additionally pins the predecessor sealed-media receipt/manifest and the sole
  unreceipted empty-home retirement left by the failed controller. Its final
  continuation verifies and adopts one exact already-created stopped instance
  under the observed mode-`0077` artifact modes without invoking create again.
  That base launcher keeps VM start, guest installation and every
  network/router-key phase disabled. The separate receipt-08-bound
  `lima-bootstrap` launcher now permits only one local-Terminal, physically
  air-gapped boot/verify/stop cycle; guest package and router/network activation
  remain disabled.
- A TESTNET-only proposal-v2 model binds the staging document, ticket,
  protected plan, grant, displayed economics, account identity, policy,
  account/market snapshots, broker session and expiry. A separate control
  SQLite adapter durably performs its single-use approval CAS. The bounded
  AF_UNIX handler and client mutually verify UID/GID before request bytes, and
  a separate stdio MCP exposes only `approve_testnet_trade(command_text)`.
  Typed control-only issuance and create-only/read-only presentation exist.
  Schema v13 validates a deterministic approved-proposal handoff and atomically
  consumes its explicit non-HMAC provenance with ticket, risk reservation,
  command, three legs and outbox. Schema v14 binds fresh PRE_KEY/PRE_SEND
  `userRole` evidence, exact addresses and signing interval through signed
  evidence, attempt, submission authority, transport outcome and send. Schema
  v15 persists an executor-config-derived chat scope; public admission accepts
  only a handoff ID and the store-owned clock while the fixed UID-451 reader
  internally loads a canonical, exact-ACL UID-452-owned config-hash-path
  artifact. Schema v16 persists and restart-validates the complete canonical
  ancestor/identity/ACL/byte evidence. A UID-452 artifact-first publisher,
  ID-only ready index, broker callback/startup active repair and cached
  UID-451 consumer now compose. The UID-453 exact seven-read collector,
  full evidence/quote projection, control grant/ticket preparation, UID-451
  preregistration receipt and broker-session-owned issuer also exist. All
  TESTNET chat source gates are enabled. No listener, identity, ACL, runtime or
  collector install exists, so fixed preflight still makes this path
  non-callable on the current machine.

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
   replay the immutable public-input lock, qualify the sealed runtime, seal the
   public media, install the inert host tools, adopt the exact UID-454 Lima
   home, retain `validate --fill`, create its dedicated management SSH key,
   install the local image and create the exact stopped VM. Then resolve
   socket_vmnet activation and first-boot APT blockers before starting it.
   Pass guest preflight before generating the VM and Mac WireGuard private keys
   on their owning machines, derive and
   attest the public keys, then render and qualify `local_nat_lab` using
   `docs/ubuntu_vm_router.md`. It does not change the public IP and does not
   prevent host bypass. Do not call it VPN-qualified. The separate remote
   `wg-egress` overlay and attended UID-451/UID-65 PF profile must be installed
   and leak-qualified before a functional TESTNET canary. UID 65 is the shared
   macOS resolver, so that PF profile restricts host-wide DNS while loaded.
   The application route gate now fails closed before entry preparation and
   again before submission authority with post-reader clock validation and the
   full two-second PRE_SEND headroom. Route-only preflight denial requeues only
   an active proven-unsent command; pre-preview maintenance normalizes claims
   and releases queued risk at the earliest ticket/leg expiry. The continuous
   collector, helpers and durable submission-authority binding exist, but no
   helper/artifact/PF/tunnel/process or live evidence is installed. Do not inject test
   evidence into a commissioned process.
   If Proton supplies the remote `wg-egress` peer, use only the attended
   guest-side importer in `docs/ubuntu_vm_router.md`: inspect a root-only staged
   profile, bind its exact profile hash and sanitized public-field hash to the
   reviewed overlay, and atomically install only the guest egress key. The
   profile/private key may not pass through chat, the repository, argv,
   environment or a host/guest shared directory. Import does not activate the
   tunnel or qualify the route.
   Receipt 07 is now complete at
   `1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601`.
   The separately rendered `lima-bootstrap` continuation recoverably replaced
   only that never-booted instance with a hardened stopped instance; receipt 08
   is `8ea55aa7a05534b91e40d42e70034162575f2dae3d568be06f6c8433ee1d39b6`.
   Its one enabled first-boot phase requires a local Terminal and continuously
   checked physical Mac air-gap, verifies the exact default-drop/lock/APT
   receipt over vsock, and stops/seals the VM before permitting host uplinks to
   return. UID-scoped PF is defense in depth, not the first-boot isolation
   boundary. Guest network reconnect remains unauthorized until a later
   stopped migration removes bootstrap sudo/provisioning.
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
    installing either the broker or its unregistered stdio MCP client. Install
    the separate handoff and ready-index paths only from an exact sealed plan,
    and define archival/GC before the 1,024-marker hard cap.

No `init`, venue/Keychain secret, grant issuance, launchd installation or
harness venue write belongs in this phase.

## Remaining promotion and live-evidence gaps

Machine commissioning alone cannot satisfy the published live checklist. The
following rows distinguish implemented-but-unpromoted contracts from remaining
code and attended-evidence gaps:

| Required qualification behavior | Current gap |
| --- | --- |
| Far non-marketable GTC canary, exact query and cancel | Schema-v12 typed envelope, pinned SDK signing/independent recovery, route-bound one-shot HTTP sender, response/crash-unknown persistence, paired queries, full foreground loop and terminal-flat release exist. A proven-unsent expired cancel retains reservation and permits exactly one fresh attended, read-proven-open same-CLOID successor. Source gates are promoted; installed credentials/VPN evidence and an attended live exercise remain absent |
| Retained pre-write account/metadata/order snapshot | Exact retained evidence/tamper checks, owner-only artifact export and distinct two-read `userRole` attestations immediately before key use and send are bound through the attempt and durable submission authority. They are implemented and adversarially tested offline but not live-qualified |
| Ordinary attended reduce-only close, including an unexpected GTC-canary fill | Full-residual envelope/result/query, pinned SDK signer/recovery, attended CLI authorization/reconciliation and terminal-flat source-reservation release are route-bound; live exercise remains absent; general bracket-parent close is intentionally unsupported |
| WebSocket disconnect/fill/recovery exercise | An injected, credential-free exact TESTNET client/decoder accepts only `orderUpdates` and `userEvents` (`channel: user`) and forces a REST request begun after the causal boundary whose receipt/server watermark covers the event after connect, every advisory event and every disconnect because the official feed has no gap-free sequence; timestamp-less events require strict server-time advance; no live connector, durable event integration or attended exercise exists |
| Forward request but drop the real response | A bounded loopback HTTP harness proves accept-then-drop, crash normalization, reservation retention and no resend; no live forwarding proxy or attended real-request exercise exists |
| Router health as an admission capability | The remote two-sample contract, hash-pinned root/UID-451 helpers, continuous single-flight collector and durable normal/qualification authority binding are implemented. It binds full PF rules/order, scoped resolver state, destination routes, complete guest config, TLS/read-only `/info`, exact exit IP, forced-physical denial and counter deltas. No provider/VM/WireGuard/PF/helper/artifact/process is installed and no live leak/reboot qualification exists |
| Executor free-space shutdown threshold | External fail-closed guard and launchd templates exist; root-owned config, real APFS `statvfs`, shutdown and restart behavior are not installed/qualified |
| Signed qualification artifact | No artifact builder/signing workflow exists; the deliverable is still manual |
| Codex chat proposal approval | Proposal v2, presentation, durable CAS, peer-checked bridge, one-field stdio MCP, schema-v13-v16 admission, UID-452 artifact-first publisher/ID-only ready index, startup repair and cached UID-451 consumer have enabled TESTNET source gates. The exact seven-read qualification artifact is recompiled by UID 452; an executor-owned receipt proves the exact registered grant/ticket/plan; the broker owns same-session issuance and expired-marker retirement. Missing: UID-453 and fixed path/ACL/runtime installation, collector/broker launch, retirement qualification and live end-to-end qualification |

Close the remaining items as narrow TESTNET-only, durable workflows with
observable failure tests. They may not become generic MCP execution tools,
widen signer actions, expose mainnet, or weaken the one-shot unknown-outcome
contract. The current `/dev/tty` HMAC is an administrative fallback. The
offline remote lane recognizes only exact `execute trade <proposal-id>` for an
immutable, short-lived, fully bound proposal and can durably record approval,
and a separately delivered handoff can be atomically admitted offline only
after the fixed UID-451 reader authenticates its config-bound UID-452 artifact.
The publisher and consumer source gates are enabled, but their paths/ACLs are
not installed. Bare/free-form chat remains
invalid. Until the live gates pass, the first harness order write remains blocked.

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
8. From the installed executor release and an empty environment, run
   `trading-harness-executor check-executor-credentials --config
   /etc/trading-desk/testnet-executor.toml` as UID 451 and
   `trading-harness-executor check-control-credentials --config
   /etc/trading-desk/testnet-executor.toml` as UID 452. Retain only their
   redacted JSON. The executor check must prove that the signer derives the
   configured API-wallet address and that recovery is available; the control
   check must prove approval and grant availability. Both must report no
   network access, no venue write and no credential value returned to the
   operator. Any failure blocks `init` and service startup; do not fall back to
   `/usr/bin/security`, environment variables or a plaintext key file.

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
