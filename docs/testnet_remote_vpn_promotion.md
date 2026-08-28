# TESTNET remote-VPN promotion guard

Status: **the TESTNET source gates, route-bound normal/qualification senders,
fixed cache, collector, observation helpers and inert PF renderer exist. No PF
rule, tunnel, VM, key, helper, expectation, collector process or venue write is
installed or running on the machine; missing artifacts fail closed**.

This is the additional guard for the intended remote path:

```text
executor UID 451 + macOS resolver UID 65
  -> macOS PF anchor (executor HTTPS and host resolver DNS only on wg-exec)
  -> Mac wg-exec default IPv4/IPv6 route
  -> Ubuntu wg-exec
  -> nftables default-drop forward/output
  -> Ubuntu wg-egress
  -> reviewed remote peer
  -> exact expected public IPv4
  -> Hyperliquid TESTNET
```

It does not change the meaning of `local_nat_lab`. The schema-v2 remote
expectation must bind the exact `TestnetRouteHealthExpectation` hash,
executor-config hash, base router bundle, VM bundle and the distinct remote
Mac WireGuard configuration. The base expectation retains the local-lab Mac
fragment and public resolver; the remote expectation binds the provider-DNS
fragment independently. The base expectation hash commits to the complete
local contract, so neither remote value is required to equal its base value.
The local
schema continues to report `host_direct_bypass_prevented=false`,
`remote_vpn_exit_configured=false` and `vpn_qualified=false`.

## macOS PF artifact

`scripts/render_macos_testnet_pf.py` consumes only reviewed public values and
creates a new bundle containing:

- `com.jawndiego.trading-desk-testnet-executor`: an anchor scoped to executor
  UID 451 and the fixed macOS resolver UID 65;
- `pf-loader.conf`: the fixed anchor/load-anchor lines for later attended root
  integration;
- `pf-policy-plan`: a print-only plan that refuses any argument except
  `--plan`; and
- `bundle-manifest.json`: exact file hashes, the base-route expectation hash,
  remote-egress bundle hash and all live claims set false.

Render and replay-check without applying anything:

```sh
python3 scripts/render_macos_testnet_pf.py \
  --spec /absolute/reviewed/pf-spec.json \
  --output-dir /absolute/new/pf-review-bundle

python3 scripts/render_macos_testnet_pf.py \
  --check-bundle /absolute/new/pf-review-bundle \
  --expected-manifest-sha256 REVIEWED_DIGEST
```

The anchor allows UID 451 DNS plus TCP 443 only on the reviewed `utun`, and it
allows resolver UID 65 DNS only to the fixed tunnel resolver on that `utun`.
All other TCP/UDP IPv4 and IPv6 flows for either identity are blocked. Resolver
UID 65 is shared by macOS, so this is intentionally a host-wide DNS restriction
while the attended TESTNET profile is active; it must be disabled outside the
test window. UID 501, research/control, root and unrelated non-DNS traffic are
otherwise outside the anchor. Pre-policy PF states are not qualification
evidence.

The renderer cannot invoke `pfctl`, `sudo`, launchd, WireGuard, Keychain or a
network endpoint. Later installation must keep the executor stopped, install
root-owned/non-writable/no-ACL bytes, syntax-check the complete root ruleset,
load the anchor at the reviewed early position, clear pre-policy executor
states, and verify the active expanded anchor hash before starting UID 451.
Those are attended changes and are not authorized by this artifact.

## Remote evidence contract

`testnet_remote_vpn_health.py` defines a distinct
`testnet_remote_vpn_exit` expectation, two-sample evidence document and
promotion guard. Valid evidence binds and proves:

- both Mac default routes use the exact reviewed `utun` for `wg-exec`;
- PF is enabled; source policy, expanded anchor and complete root-rules/order
  hashes match; executor and resolver identities are tunnel-only; HTTPS and a
  forced-physical denial counter advance around the probe;
- the complete guest config plus both `wg-exec` and `wg-egress` configs match,
  and both peers have recent handshakes;
- guest input, forward and output policies are default-drop, physical-WAN
  output is limited to the reviewed outer peer, forwarding is only
  `wg-exec -> wg-egress`, and NAT is only on `wg-egress`;
- the routed DNS/TLS/fixed read-only TESTNET `/info` probe succeeds;
- the observed public IPv4 exactly equals the reviewed expected exit; and
- every WireGuard RX/TX direction, guest HTTPS, PF HTTPS and PF direct-block
  counter advances; resolver counters cannot regress.

Collection may span at most 15 seconds. Evidence expires no more than five
seconds after its second sample. Both the expectation and evidence decoders
reject additional/missing fields, mainnet/write authority, a true submission
gate, wrong exit IP, stale handshakes, topology drift and nonadvancing or
regressing counters.

`testnet_remote_vpn_health_artifacts.py` provides the only intended production
reader. It loads `expectation.json` and `evidence.json` from the fixed
root-owned, ACL-free, config-hash-bound namespace:

```text
/private/var/db/trading-desk-testnet-remote-vpn-health/<executor-config-hash>/
```

Directories must be root-owned mode `0755`; files must be root-owned mode
`0444`, single-link, bounded and ACL-free. Reads use directory-relative,
no-follow descriptors with pre/post metadata checks. A separate root collector
may atomically replace only `evidence.json` after complete validation. The
factory also loads the existing fixed root-owned local-route expectation and
rejects any base mismatch. The sender therefore receives a bounded cached
read, never caller-supplied evidence and never an SSH/route/DNS/TLS/HTTP probe
inside the submission lock.

`trading-harness-remote-vpn-health-collector --run` is the foreground refresh
surface; `--collect` performs one cycle. It is single-flight and invokes only:

Its preinstalled zero-length `root:wheel` mode-`0600` lock is
`/private/var/db/trading-desk-testnet-remote-vpn-health/collector.lock`, under
the same non-writable root-owned cache tree. `/private/var/run` is not trusted
for this lock because macOS grants write access there to GID `daemon`.

```text
/usr/local/libexec/trading-desk-testnet-remote-vpn-sample   (root)
/usr/local/libexec/trading-desk-testnet-remote-vpn-probe    (UID/GID 451)
```

The sample reads Mac routes, scoped DNS, full/anchor PF state and the fixed Lima
guest checker. Lima runs only as disabled `trading-router-operator` UID/GID
454, owner of the dedicated mode-0700 LIMA_HOME; its implicit groups must equal
the reviewed UIDs-450–452 Darwin local-account set `12,61,100,701`, with exact
group names, GeneratedUIDs and nesting bound by the v3 identity receipt. GID
701 is the host's everyone-nested public-folder group; any binding drift is a
hard stop. The router has no harness credential. The probe has no arguments: it resolves IPv4 through the
PF-confined system resolver, verifies each destination route uses the reviewed
`utun`, validates TLS/SNI, performs exact read-only TESTNET `POST /info`, reads
the fixed reviewed exit observer, and proves a forced-physical TCP 443 attempt
was denied. Helper output is streaming-capped. One cycle is bounded by wall and
monotonic clocks, publishes only with two seconds of remaining five-second TTL,
and never overwrites newer evidence.
`scripts/render_testnet_remote_vpn_profile.py` renders and replay-verifies the
exact five-file public media and prints its aggregate hash. Its `--mode base`
first prints the deterministic base expectation/hash needed to render the PF
bundle; `--mode render` then requires that exact PF/remote manifest binding and
`--mode verify` replays all sources. The plan/apply
installer `deploy/macos/testnet/05-install-remote-vpn-health.sh` requires that
expected hash and never loads PF or starts networking/services.

For Proton, the secret-bearing downloaded WireGuard profile is handled only
inside the Ubuntu guest by the attended fixed-path importer documented in
`docs/ubuntu_vm_router.md`. Its inspection exposes the five required public
fields plus fingerprints but not the private or derived local public key. The
remote-egress manifest binds those fields as
`wireguard_profile_public_binding_sha256`; key installation additionally
requires the exact full-profile SHA-256 observed during inspection. Successful
import atomically creates only the root-owned guest egress key and a redacted
receipt. It does not activate the tunnel or satisfy this promotion guard.
The remote overlay also rejects any public topology that differs from its
exact base-router manifest and emits the attended Mac fragment with Proton's
tunnel DNS; do not reuse the local-lab fragment's global resolver for the
remote profile.

## Promotion stop line

Both TESTNET source gates are true and the remote guard is composed, but fixed
root artifacts are absent and therefore deny every write. Before installing
and running them, retain live evidence for PF disable/reload, Mac tunnel loss,
VM loss, `wg-egress` loss,
remote-peer loss, DNS failure, wrong exit IP, sleep/wake, reboot and request-
accepted/response-lost behavior. Every loss must deny new sends without a
direct fallback; an already ambiguous venue outcome remains `UNKNOWN` and is
reconciled without retry. Normal and qualification submission authorities bind
the exact route mode, expectation hash, evidence hash and expiry; a loss after
authority becomes `UNKNOWN` without HTTP. Mainnet remains hard-disabled.
