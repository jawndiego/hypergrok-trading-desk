# TESTNET chat issuance-provenance plan

Status: **inert design only**. This document and its JSON companion do not
authorize creating an identity, installing a runtime, changing an ACL, opening
a network connection, provisioning a credential, issuing a proposal, starting
the broker, or touching a venue.

The current proposal issuer can revalidate internally consistent account,
market, and grant objects, but their constructor origin is not yet
authoritative. A persistence layer that accepted those same free objects would
only preserve a forgery. Promotion therefore requires provenance-producing
boundaries before a durable evidence store is implemented.

## Proposed collector identity

A future public-data collector is allocated UID/GID 453 and the account name
`trading-public-collector`. That identity does not exist, and this plan does
not create it. Existing research, executor, and control identities remain
exactly UID/GID 450, 451, and 452.

The collector has no login, home directory, shared group, credential, signer,
execution database, control-database write, or venue-write capability. Its
future network policy permits fixed TESTNET `POST` reads only to
`https://api.hyperliquid-testnet.xyz/info`, restricted to the reviewed
`clearinghouseState`, `meta`, and `l2Book` request families. The exchange path
is forbidden. Endpoints, environment, account, and arbitrary request types are
not runtime inputs.

## Account evidence shared by quote and issuer

The collector must create an immutable full-source account artifact containing
the canonical Hyperliquid account snapshot, venue snapshot hash, exact risk
limits and limits hash, symbol, local budget inputs, derived account-risk
snapshot, collector generation, source request evidence, and timestamps. The
artifact must make the derived account evidence hash independently
recomputable; retaining only `AccountRiskSnapshot` is insufficient because its
hash also depends on source values that object does not carry.

Full source artifacts are UID/GID-453-owned, mode 0400 files beneath a
UID/GID-453 mode-0700 namespace. Only control UID 452 receives search on the
directory and read on the file. A separate sanitized quote projection binds
the exact full-source hash and may be read by research UID 450 and control UID
452. Both the quote service and broker must consume the same
`account_evidence_hash`; the staged ticket records that hash, and the broker
reloads the full source and recomputes it before issuance. Neither side may
supply an account object directly.

Publication is hidden-inode, create-exclusive, full-synchronized,
ACL-verified, and no-replace. Final file and parent durability must be proven
again during crash recovery. Automatic overwrite or deletion is prohibited.

## Fresh issuance market evidence

The same collector creates full canonical `l2Book` evidence for the exact plan
instrument. Only control UID 452 may search and read it. The issuer reloads it
by hash, verifies collector provenance, rejects future timestamps, and requires
an age strictly below five seconds. It repeats entry crossability, visible
25-basis-point depth, and requested-size checks. A caller-provided mapping is
never a market-evidence source.

## Grant provenance without a broker secret

The existing infrastructure grant is HMAC-authenticated, so the broker cannot
turn its portable bytes into a trusted grant without receiving a secret. The
near-term design uses a separate attended, sealed verifier to create a
root-owned immutable receipt after authenticating the signed grant. The
receipt binds the signed artifact hash, complete trusted scope, config and
policy hashes, verifier code and generation, verification time, and grant
expiry. Control UID 452 receives read only; it never receives the HMAC or key
reader.

A future public-key grant format may replace the attended receipt. The broker
would hold only the public verification material. Neither option is enabled by
this plan, and no key material appears in the machine-readable artifact.

## Executor preregistration before display

Before the proposal is shown, executor UID 451 must have durably registered the
exact ticket, protected plan, trusted infrastructure grant, account binding,
and policy scope. It then creates an immutable, sanitized receipt for control
UID 452. The receipt binds the execution-store identity hash and all ticket,
plan, grant, policy, account, registration-time, and expiry fields. It conveys
no execution authority and grants the broker no execution-database access.

The control issuer must load and verify this receipt before it creates either a
proposal or presentation. A caller cannot supply the receipt object.

## Same-process active-session issuance

Issuance remains inside the process that owns the active UID-452 broker
listener generation. The issuer receives the exact live
`TestnetChatBrokerSession` object, never a caller-provided session hash or
decoded receipt. Issuance stops before that listener closes.

For one staging ID, the issuer reloads the verified account evidence, fresh
market evidence, preverified grant receipt, and executor preregistration
receipt by canonical hash or ID. Only after every scope, economics, freshness,
expiry, and active-session check succeeds may it atomically store `PENDING` and
publish the sanitized proposal display.

## Store boundary and stop line

The future issuance-evidence store must not expose a free-payload write method.
Writes require an OS-authenticated collector or attended-verifier capability;
reads accept canonical IDs and hashes only. The broker cannot insert account,
market, grant, or preregistration values on behalf of a caller.

Promotion remains blocked on all of the following:

- creation and commissioning of UID/GID 453;
- a sealed info-only collector runtime and fixed outbound policy;
- exact collector, quote-projection, grant-receipt, and executor-receipt ACLs;
- durable full-source account and market evidence stores;
- the attended grant-verification receipt pipeline or reviewed public-key
  replacement;
- the executor preregistration receipt pipeline;
- same-process active-session issuer composition; and
- live negative ACL, crash, freshness, replay, and reboot proofs.

Mainnet remains absent. No step in this plan authorizes an apply operation.
