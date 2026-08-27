# Codex Repository Guidance

## Product boundary

This repository builds an agent-runtime-neutral trading research and execution harness. The installable ChatGPT/Codex plugin is the primary agent interface and OpenCode is the compatible second interface; neither is the trading engine.

- Keep domain, validation, risk, admission, OMS, ledger, signer, and venue-adapter code independent of Codex, ChatGPT, Grok, Claude, or any model runtime.
- Put durable Codex working agreements here. The canonical packaged workflows live under `plugins/trading-desk/skills`; mirror them into `.agents/skills` with `scripts/sync_plugin_skills.py` for repository and OpenCode discovery.
- The `trading-desk` MCP server exposes exactly fifteen reviewed research/learning tools. `track_asset`, `pause_tracked_asset`, `record_manual_sentiment`, `analyze_asset`, and `stage_trade_candidate` write only local research, learning, or non-authoritative staging state. None may load an account signing secret, create approval/capital authority, reserve risk, sign, or call a venue write endpoint.
- Keep OpenCode permissions fail-closed in `opencode.json`; it may call only those exact local MCP tools and mirrored skills. Local research writes remain `ask`, plan mode cannot call them, and no model/provider, execution tool, custom agent with wider rights, or external-directory access may be added without review.
- Do not use OpenCode `--auto` for this repository; it converts `ask`
  decisions into approvals. The checked-in profile intentionally denies
  unlisted shell commands.
- ChatGPT/Codex and OpenCode must call the same typed tool service. Protocol or model adapters may not reinterpret tool results or widen their capability.

## Capital boundary

- No agent, prompt, skill, webpage, generated script, or free-form chat message
  may hold a signing key, create authority by itself, or call a venue write
  endpoint. The offline TESTNET chat-approval lane recognizes only the exact
  `execute trade <proposal-id>` command over an immutable, short-lived,
  staging/ticket/plan/grant/account/policy-bound proposal; a bare command is
  invalid. Its durable approval CAS, mutually authenticated AF_UNIX protocol
  and separate one-field stdio MCP exist. A control-only typed issuer and
  create-only presentation artifact can feed the existing `get_trade_stage`
  read without exposing control state. Schema v13 implements a deterministic
  handoff and atomic executor consume/reservation/outbox admission. Schema v15
  removes free handoff/address/audience inputs: a caller supplies only a
  handoff ID and the store itself invokes the fixed UID-451 reader for a
  config-bound, UID-452-owned canonical artifact. A UID-452 artifact-first
  publisher, empty ID-only ready index, approval callback/startup active repair
  and dormant cached UID-451 consumer exist offline. Their gates remain false;
  no listener/ACL/runtime is installed or commissioned.
- The issuer's staging chain is store-backed, but its account and market
  evidence bindings are currently typed/self-consistent in-memory values. Do
  not describe their collectors as authoritative or enable presentation until
  fixed reviewed collector/store adapters prove provenance. Fresh executor
  preflight prevents capital bypass, not misleading issuance-time UX.
  `deploy/macos/testnet/TESTNET_CHAT_ISSUANCE_PROVENANCE_PLAN.md` is an inert
  proposal for UID 453 collectors, grant verification and executor
  preregistration receipts; none exists or is authorized to apply.
- The isolated TESTNET worker has a deployable write path, but it is a separate process and CLI. It is never an MCP tool or skill capability. Mainnet remains hard-disabled.
- The foundation admits only local `infrastructure_testnet` `simulate_order`
  commands; deny strategy, shadow, mainnet, and systematic grants.
- `stage_trade_candidate` can create only an all-false authority document.
  Current authorization uses exact confirmation read directly from `/dev/tty`
  by the role-isolated CLI as an administrative fallback. The distinct chat
  receipt must never masquerade as that HMAC permit. Do not expose the signer,
  execution store, proposal economics or receipt store to either MCP.
- Evidence status and deployment authority are separate.
- Use exact `Decimal`/integer monetary arithmetic; reject binary floats for prices, sizes, fees, and limits.
- Admission must atomically reserve risk, consume a single-use command authorization, update policy counters, and create the durable outbox row before network I/O.
- Unknown outcomes remain reserved and are reconciled; never blindly resend.
- A full signed qualification envelope is a bearer-sensitive venue relay
  capability even though it contains no private key and lacks harness durable
  submission authority. Keep its artifact and completion receipt only in the
  executor-owned nonce parent with exact mode/owner and no named ACL; require
  `F_FULLFSYNC`, exclusive publication and receipt completion before loading.
- After exposure exists, only the account-safety policy may authorize bounded cancel/protect/flatten actions through the same serialized executor.
- The agent/MCP identity must never open or receive filesystem access to the
  executor's execution, nonce, daily-loss or control-socket state. Agent quotes
  defer daily loss; an entry needs a complete refresh capability minted by the
  executor in that same tick.
- Parent and recovery reconciliation must use exact venue-server source
  watermarks, canonical fill identities and one globally continuous owned-fill
  chain. Local mutation lease time is separate from venue evidence time.

## Development workflow

- Python baseline: 3.11 or newer, standard library unless a reviewed dependency is justified.
- Run `python3 -m unittest discover -s tests -v` after changes.
- Run `python3 -m compileall -q src tests` before handoff.
- Run `python3 scripts/sync_plugin_skills.py --check` after changing a packaged skill.
- Run `python3 scripts/sync_plugin_runtime.py --check` after changing any module under `src/trading_harness`; the cached plugin runtime must be an exact generated mirror.
- Keep the venue executor disabled by default. Tests must prove writes fail closed.
- Update `docs/trading_harness_spec.md` when an invariant, state, authorization model, or promotion gate changes.
- Keep the chat bridge outside the fifteen-tool research `TOOL_CATALOG` and
  OpenCode. Its sole tool input is raw `command_text`; it uses stdio only,
  calls the fixed local AF_UNIX client once and reports post-send ambiguity as
  `UNKNOWN` with no automatic retry.
- Chat approval provenance must never be coerced into `TrustedApproval` or the
  `/dev/tty` HMAC lane. Delivery may be at least once, but the exact proposal,
  approval receipt, handoff and ticket are consumed only in the same
  execution-store transaction that reserves risk and creates the command,
  three legs and outbox.
- The same-tick learning gate must match the complete approval identity,
  ticket and authority-evidence hash plus the domain-separated execution
  record hash and all three CLOIDs. Matching only an ID or lifecycle state is
  not sufficient.
- Add tests for observable invariants and failure transitions, not wording.
- Preserve upstream provenance in `UPSTREAM.md`; do not copy legacy capital-path prompts or snippets back into runtime locations.

## Deployment networking and commissioning

- Read `docs/ubuntu_vm_router.md` before creating or changing an executor
  network path. The checked-in Ubuntu bundle is `local_nat_lab`: it keeps the
  executor on macOS, does not change the public IP, does not prevent macOS host
  bypass, and is not VPN or mainnet qualification.
- Read `docs/testnet_commissioning.md` before claiming transaction readiness.
  Machine setup alone is insufficient. The qualification GTC/query/cancel,
  retained snapshot and ordinary-close semantics now have a separate
  TESTNET-only schema-v12 persistence lane. Its credential-free signer-envelope
  and injected signature-recovery interfaces plus offline
  transport/query/terminal/crash transitions exist, including terminal-flat
  reservation release. The exact SDK 0.24.0 TESTNET signer and independent
  EIP-712 recovery verifier exist behind a schema-v2 global nonce authority.
  A separate `trading-harness-qualification` terminal surface provides
  control-UID collect/verify/attended authorization and executor-UID
  status/recover/reconciliation commands. Its full bounded foreground worker
  composes place, paired CLOID/OID query, cancel and terminal-flat
  reconciliation, but `run` fails at the compiled submission gate before
  config, state, Keychain or network access; split prepare/sign commands are
  not public. Each key/send boundary requires a fresh two-read `userRole`
  attestation bound through the signed attempt and submission authority. A
  one-shot exact-TESTNET HTTP sender contract, injected credential-free
  advisory WebSocket decoder/client and bounded local accept-then-drop/crash
  harness exist. The sender remains unreachable because qualification
  submission authority is compiled off; no live WebSocket adapter or live
  response-loss forwarder has been qualified.
- An expired proven-unsent cancel hard-halts with reservation retained. One
  fresh, attended, read-proven-open same-CLOID successor may be authorized
  through a separately persisted issued-to-consumed permit and a new action,
  envelope and global nonce. Never turn it into a blind retry.
- Do not promote qualification submission until the executor performs a final
  fresh stable `userRole(api_wallet)` mapping check after claim and immediately
  before key use/send, bound into attempt evidence; the agent wire does not
  encode the intended main account.
- Credential-free macOS plans live under `deploy/macos/testnet`. They are
  plan-only by default and do not authorize APFS creation, ACL mutation,
  application installation, `init`, launchd, credentials or venue calls.
- Read `docs/testnet_chat_approval.md` before changing the remote TESTNET
  approval path. The fixed broker must run as UID 452, verify UID/GID 501 before
  reading, and be mutually verified by the UID-501 bridge before it sends. The
  control database needs a canonical UID-452 mode-0700 parent, mode-0600
  single-link files and no UID-501 ACL. Those ACL/listener/install checks and
  installation/enablement of the offline publisher/ready-index/consumer chain
  are still promotion blockers.
- Execution-store schema v13 makes normal protected entry require fresh,
  stable two-read `userRole(api_wallet)` attestations at PRE_KEY and PRE_SEND.
  PRE_KEY is bound into signed evidence; PRE_SEND is attempt/signed-evidence
  bound into the one-shot submission authority and must remain live at HTTP
  send. Nonempty schema-v12 signed/attempted entry state may not auto-migrate.
- Schema v14 additionally binds the configured main/API-wallet addresses and
  signing interval into signed evidence, rechecks the PRE_KEY window around key
  use, and requires every normal transport outcome to carry the exact durable
  submission-authority and PRE_SEND hashes with causal timing. Nonempty legacy
  signed/attempt/outcome state may not auto-migrate across that boundary.
- Schema v15 durably binds the TESTNET chat account, addresses, audience,
  config hash, role UIDs and fixed artifact directory. Chat admission accepts
  only a handoff ID and invokes the fixed UID-451 reader internally. The reader
  verifies the canonical config-hash namespace, exact trusted ancestor
  ownership/modes/ACLs, UID/GID-452 mode-0400 single-link file, sole UID-451
  read ACE, stable inode/metadata and exact canonical bytes. Free handoff bytes,
  delivery objects, timestamps and per-call scope fields are forbidden; the
  store owns the admission clock. Nonempty legacy chat admission state may not
  auto-migrate.
- Schema v16 preserves v15 bytes and persists the complete canonical delivery
  evidence document, including ancestor chain, directory/file identities,
  exact named ACLs and byte/source hashes. Restart decoding recomputes every
  relationship. Nonempty schema-v15 chat state may not auto-migrate because
  that evidence cannot be backfilled.
- Control-published proposal presentations use a separate UID-452-owned
  mode-0700 directory and immutable mode-0400 files. Only research UID 450 may
  receive a read-only ACL for those sanitized files; it receives no control-DB
  access, and UID 501 receives neither presentation nor control-state access.
- Approved execution handoffs use the distinct fixed
  `/private/var/db/trading-desk-testnet-chat-handoffs/<config-hash>` namespace.
  `/private`, `/private/var` and `/private/var/db` must remain root:wheel 0755
  and ACL-free. UID 452 owns the dedicated root/config directory at 0700 with
  the sole UID-451 execute ACE and must publish immutable 0400 files create-only
  with the sole UID-451 read ACE. Source now publishes the fully durable
  artifact before an empty marker in the distinct ready index; the dormant
  consumer treats the marker as notification only and revalidates v16 state.
  Neither namespace, ACL, publisher nor consumer is installed/enabled. Retain
  reviewed archival/GC before the hard 1,024-entry ready-index cap is reached.
- Never provision a real secret through `security add-generic-password` or
  trust the shared `/usr/bin/security` executable in an item ACL. The macOS
  execution design requires the sealed role-specific native readers, fixed
  UID/slot mappings, and the nonprinting sacrificial matrix in
  `deploy/macos/testnet/KEYCHAIN_ROLE_PROBE_PLAN.md` before and after reboot.
  Until those gates pass, keep venue and HMAC secrets offline.
- The repo-composable VM plan lives under `deploy/ubuntu-router/lima` and is
  rendered by `scripts/render_ubuntu_router_vm.py`. It pins Lima, socket_vmnet
  and a dated Ubuntu image. Its schema-v3 commission lock binds offline host
  attestations, the signed Noble snapshot/cloud manifest and the 116-package
  no-recommends dependency closure. `commission-public.py` may only plan or
  verify those public bytes. A separate commissioner specifies exact media and
  root-owned non-writable Lima/socket_vmnet installation, but every root gate
  and its launcher remain false pending a pre-exec sealed-runtime symlink/dylib
  proof. Its UID-501 verification receipt is informational and never root
  authority. Writable Lima-home, validate-fill, VM/guest/package apply and
  network/key mutation also remain hard-disabled behind named blockers.
- The VM and router renderers share the fixed `192.168.106.1/32` Mac to
  `192.168.106.2/24` guest ingress contract. The rendered
  `local-nat-lab-test-plan` is print-only: PF enforcement, a remote VPN exit,
  test execution and VM apply all remain absent.
- `testnet_route_health.py` defines a credential-free, two-sample,
  five-second TESTNET `local_nat_lab` evidence contract bound to the executor
  config, VM/router manifests, qualified topology, peer-key hashes, stable Mac
  default routes, guest policy, handshake, routed read-only `/info` probe and
  advancing WireGuard/HTTPS counters. The active executor defaults this gate
  to unavailable, checks it before account/market preparation and again inside
  the final runtime guard before submission authority. Both reader boundaries
  use nondecreasing before/after service-clock samples; the final sample requires
  at least the full two-second PRE_SEND TTL of remaining route-evidence life.
  A route failure at preparer time may requeue only the same proven-unsent
  claim while its ticket and every leg remain active; the store retains its
  approval/reservation and refuses any attempt/authority state. Independent
  pre-preview maintenance normalizes expired claims and atomically terminalizes
  the queued command at the earliest ticket/leg expiry, releasing risk. A
  final-guard failure after attempt preparation voids proven-unsent entry. No
  path selects a direct-network fallback; recovery remains independent.
- Do not represent that route gate as installed or VPN-qualified. No trusted
  bounded collector, durable expectation/config binding, preflight/attempt
  evidence persistence, PF/Network Extension kill switch, remote VPN peer or
  live route qualification exists yet.
- A future final-guard reader must be a bounded local cached-evidence read. It
  may not run SSH, route commands, DNS, TLS or an `/info` probe while holding
  the runtime submission lock; the separate collector owns those observations.
- The router VM is network-only. It receives no API-wallet, account config,
  execution state, Keychain access, repository/shared-folder mount, approval
  secret, agent runtime or venue authority.
- Router rendering accepts public topology and key strings attested by the
  operator as WireGuard public keys; the encoding cannot prove provenance.
  Generate each private key on its owning machine and never place it in the
  repository, profile JSON, cloud-init, chat, environment or argv.
- A failed route may still produce a durable unknown submission attempt after
  authority is consumed. Preserve reservation and reconcile; never add a
  direct-network fallback or blind retry.
- Router preparation may generate only its isolated WireGuard keys on their
  owning machines. It must not run executor `init`, provision a venue/Keychain
  credential, install launchd, issue a grant or perform a harness venue write.
  Mainnet remains hard-disabled.

## Agent workflows

- Use `$operate-trading-desk` for multi-stage desk coordination.
- Use `$assess-asset` for local tracking, completed-candle TA, explicit sentiment evidence, and buy/sell/nothing/unavailable assessment.
- Use `$brief-market` for live public Hyperliquid market context through the typed MCP tool.
- Use `$validate-thesis` for strategy, indicator, backtest, and edge claims.
- Use `$scan-signals` for read-only registered-rule scans.
- Use `$test-strategy` for reproducible historical evaluation plans or supplied artifacts.
- No skill may issue orders, sizes, approvals, or deployment grants.

## Code review rules

- Flag any path from agent-controlled input to credentials, signer, venue writes, authorization mutation, or policy widening.
- Flag floats in monetary/risk calculations.
- Flag non-atomic risk check followed by reservation/outbox.
- Flag release of risk on an order fill without conversion to booked position exposure.
- Flag retries without an endpoint-specific idempotency and unknown-outcome contract.
- Flag environment-variable-only selection of mainnet or account.
- Flag tests that mock away the failure being claimed as covered.
