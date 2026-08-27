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

- No agent, prompt, skill, webpage, generated script, or chat message may hold a signing key, approve a trade, or call a venue write endpoint.
- The isolated TESTNET worker has a deployable write path, but it is a separate process and CLI. It is never an MCP tool or skill capability. Mainnet remains hard-disabled.
- The foundation admits only local `infrastructure_testnet` `simulate_order`
  commands; deny strategy, shadow, mainnet, and systematic grants.
- Approval in chat is invalid. `stage_trade_candidate` can create only an all-false authority document; attended authorization requires the exact ticket confirmation read directly from `/dev/tty` by `trading-harness-executor`.
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
  TESTNET-only schema-v11 persistence lane. Its credential-free signer-envelope
  and injected signature-recovery interfaces plus offline
  transport/query/terminal/crash transitions exist, including terminal-flat
  reservation release. The exact SDK 0.24.0 TESTNET signer and independent
  EIP-712 recovery verifier exist behind a schema-v2 global nonce authority.
  A separate `trading-harness-qualification` terminal surface provides
  control-UID collect/verify/attended authorization and executor-UID
  status/recover/reconciliation commands. Its `run` command fails at the
  compiled submission gate before config, state, Keychain or network access;
  split prepare/sign commands are not public. A one-shot exact-TESTNET HTTP
  sender contract, injected credential-free advisory WebSocket decoder/client
  and bounded local accept-then-drop/crash harness exist. The sender remains
  unreachable because qualification submission authority is compiled off; no
  complete live place/query/cancel worker, live WebSocket adapter or live
  response-loss forwarder has been promoted.
- Treat an expired proven-unsent cancel as a hard halt with reservation
  retained. No fresh same-CLOID cancel reauthorization exists yet; never add a
  blind retry or call the current one-phase `run` contract live-ready.
- Do not promote qualification submission until the executor performs a final
  fresh stable `userRole(api_wallet)` mapping check after claim and immediately
  before key use/send, bound into attempt evidence; the agent wire does not
  encode the intended main account.
- Credential-free macOS plans live under `deploy/macos/testnet`. They are
  plan-only by default and do not authorize APFS creation, ACL mutation,
  application installation, `init`, launchd, credentials or venue calls.
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
  verify those public bytes; host install, VM/package apply and network/key
  mutation remain absent and guest preflight must pass before keys exist.
- The VM and router renderers share the fixed `192.168.106.1/32` Mac to
  `192.168.106.2/24` guest ingress contract. The rendered
  `local-nat-lab-test-plan` is print-only: PF enforcement, a remote VPN exit,
  test execution and VM apply all remain absent.
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
