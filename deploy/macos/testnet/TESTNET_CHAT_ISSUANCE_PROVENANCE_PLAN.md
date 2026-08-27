# TESTNET chat issuance-provenance plan

Status: **inert plan only for deployment**. Enabled TESTNET source implements
the fixed evidence/projection stores, executor preregistration receipt and
same-process broker issuance composition. This document and its JSON companion
do not authorize creating an identity, installing a runtime, changing an ACL,
opening a network connection, provisioning a credential, issuing a proposal,
starting the broker, or touching a venue.

The live-composition adapter does not accept free account, market, grant or
registration objects. It reuses the exact seven-read TESTNET qualification
artifact, recompiles the account hash, publishes a sanitized quote projection,
and requires an executor-owned receipt before display. Promotion still
requires installing and qualifying those provenance-producing identities and
paths.

## Proposed collector identity

A future public-data collector is allocated UID/GID 453 and the account name
`trading-public-collector`. That identity does not exist, and this plan does
not create it. Existing research, executor, and control identities remain
exactly UID/GID 450, 451, and 452.

The collector has no login, home directory, shared group, credential, signer,
execution database, control-database write, or venue-write capability. Its
future network policy permits fixed TESTNET `POST` reads only to
`https://api.hyperliquid-testnet.xyz/info`, restricted to the reviewed
seven-read sequence: `userRole`, `userAbstraction`, `meta`,
`clearinghouseState`, `frontendOpenOrders`, `metaAndAssetCtxs`, and `l2Book`.
The exchange path is forbidden. Endpoints, environment, account, and arbitrary
request types are not runtime inputs.

## Account evidence shared by quote and issuer

The offline collector adapter creates an immutable full-source artifact containing
the canonical Hyperliquid account snapshot, venue snapshot hash, exact risk
limits and limits hash, symbol, local budget inputs, derived account-risk
snapshot, collector generation, source request evidence, and timestamps. The
artifact must make the derived account evidence hash independently
recomputable; retaining only `AccountRiskSnapshot` is insufficient because its
hash also depends on source values that object does not carry.

Full source artifacts are UID/GID-453-owned, mode 0400 files beneath a
UID/GID-453 mode-0700 namespace. Only control UID 452 receives search on the
directory and read on the file. A separate implemented sanitized quote projection binds
the exact full-source hash and may be read only by research UID 450. Both the
quote service and broker consume the same `account_snapshot_hash`; the staged
ticket records that hash, and the broker
reloads the full source and recomputes it before issuance. Neither side may
supply an account object directly.

Publication is create-exclusive, full-synchronized, ACL-verified and
no-replace. An exact existing artifact is idempotent; a crash-left partial
final poisons that name closed for operator review rather than being replaced.
Automatic overwrite or full-source deletion is prohibited. The collector
removes only fully verified quote projections after their five-second
observation lifetime, before enforcing the bounded quote index.

## Fresh issuance market evidence

The same collector creates full canonical `l2Book` evidence for the exact plan
instrument. Only control UID 452 may search and read it. The issuer reloads it
by hash, verifies collector provenance, rejects future timestamps, and requires
an age strictly below five seconds. It repeats entry crossability, visible
25-basis-point depth, and requested-size checks. A caller-provided mapping is
never a market-evidence source.

## Grant provenance without a broker secret

The existing infrastructure grant is HMAC-authenticated, so the broker cannot
turn portable bytes into a trusted grant without receiving a secret. The
implemented near-term path makes executor UID 451 register the already-trusted
grant and exact ticket/plan in the execution store, then publish an immutable
receipt binding that store identity and complete scope. Control UID 452
receives read only; it never receives the HMAC or key reader.

A future public-key grant format may replace this receipt path. The broker
would hold only the public verification material. No key material appears in
the machine-readable artifact.

## Executor preregistration before display

Before the proposal is shown, executor UID 451 durably registers the
exact ticket, protected plan, trusted infrastructure grant, account binding,
and policy scope. It then creates an immutable, sanitized receipt for control
UID 452. The receipt binds the execution-store identity hash and all ticket,
plan, grant, policy, account, registration-time, and expiry fields. It conveys
no execution authority and grants the broker no execution-database access.

The implemented control issuer loads and verifies this receipt before it creates either a
proposal or presentation. A caller cannot supply the receipt object.
The control-UID `prepare-chat-stage` command first authenticates the signed
grant through the configured grant slot and registers only the exact
grant/ticket/plan. UID 451 then publishes the receipt from those existing store
records; neither command creates approval, reservation or command state.

## Same-process active-session issuance

Issuance remains inside the process that owns the active UID-452 broker
listener generation. The issuer receives the exact live
`TestnetChatBrokerSession` object, never a caller-provided session hash or
decoded receipt. Issuance stops before that listener closes.

For one staging ID, the implemented issuer reloads the verified account
evidence, fresh market evidence, and executor preregistration/grant
receipt by canonical hash or ID. Only after every scope, economics, freshness,
expiry, and active-session check succeeds may it atomically store `PENDING` and
publish the sanitized proposal display.

## Store boundary and stop line

The issuance-evidence store exposes no free-payload write method.
Writes require an OS-authenticated collector or attended-verifier capability;
reads accept canonical IDs and hashes only. The broker cannot insert account,
market, grant, or preregistration values on behalf of a caller.

Promotion remains blocked on all of the following:

- creation and commissioning of UID/GID 453;
- a sealed info-only collector runtime and fixed outbound policy;
- exact collector, quote-projection, grant-receipt, and executor-receipt ACLs;
- creation of the fixed evidence, quote-projection and executor-receipt roots;
- composition of authenticated grant verification with executor registration;
- installation of the source-enabled fixed collector and registration commands;
- installation of the source-enabled broker and same-process issuer lifecycle; and
- live negative ACL, crash, freshness, replay, and reboot proofs.

Mainnet remains absent. No step in this plan authorizes an apply operation.
