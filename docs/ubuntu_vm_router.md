# Local Ubuntu VM router for TESTNET qualification

Status: **repository-rendered guest configuration plus a pinned Lima/VZ VM
bundle; immutable public-input replay and venue-credential-free preparation
through creation of one stopped VM are implemented but remain unapplied on a
new host. VM start, guest mutation, socket_vmnet activation, router/network
changes, live health collection and boot orchestration remain disabled and
unqualified; this is not VPN-qualified or a capital security boundary**.

This design keeps the signer/executor on macOS, where the reviewed System
Keychain and UID/ACL model exist, and puts only network routing in a dedicated
Ubuntu 24.04 ARM64 VM. The router receives a full-tunnel WireGuard peer from
the Mac and forwards accepted IPv4 traffic through its VM WAN interface.

```text
macOS executor and research traffic
        |
        | WireGuard wg-exec (0.0.0.0/0 and ::/0)
        v
Ubuntu router VM
  ingress NIC + wg-exec + separate WAN NIC
        |
        | nftables default-drop forwarding + IPv4 NAT
        v
hypervisor/shared or bridged WAN -> Internet -> Hyperliquid TESTNET HTTPS
```

`local_nat_lab` does not change the public IP and does not prevent host bypass.
The VM exits through the same Internet connection as the Mac, and macOS still
owns the physical interfaces. It provides a reproducible routing/failure lab,
not anonymity, a static exit IP, or protection against macOS root/hypervisor
compromise. A later remote WireGuard peer or physical router is required for a
stronger egress boundary.

Do not call the VM a host kill switch. Preventing bypass requires a separately
reviewed macOS PF/Network Extension policy across every physical, IPv6 and
`utun` path, or a physical router that the Mac cannot route around. That work
is intentionally not hidden inside the private-key-field-free VM renderer.

## Trust boundary

- The Ubuntu VM is a dedicated router. It is not an executor, signer, MCP
  server, research worker, approval plane, or database host.
- No API-wallet key, approval/recovery/grant secret, account config, execution
  state, repository mount, shared folder, clipboard integration, or agent
  runtime enters the VM.
- Its only secret is its own WireGuard private key, generated inside the VM
  from an attended console and stored root-only at
  `/etc/wireguard/trading-desk-router.key`.
- The Mac WireGuard private key is generated and retained by the official
  WireGuard app. Only the two public keys enter the router profile.
- The router cannot approve a trade or turn a failed network request into a
  retry. A lost response remains a durable unknown outcome and must reconcile
  before another send.
- Network controls do not replace signer policy, exact authorization, risk
  reservation, nonce durability, outbox persistence, protective orders, or
  recovery reconciliation. Mainnet remains hard-disabled.

## Repository bundle

The reviewed public inputs live in a copied profile based on
`deploy/ubuntu-router/router-spec.json.example`. The renderer accepts exactly
schema version 1 and mode `local_nat_lab`:

```sh
python3 scripts/render_ubuntu_router.py \
  --spec /absolute/reviewed/router-spec.json \
  --output-dir /absolute/new/router-bundle
python3 scripts/render_ubuntu_router.py \
  --check-bundle /absolute/new/router-bundle \
  --expected-manifest-sha256 REVIEWED_DIGEST_FROM_RENDER_OUTPUT
```

The output directory must not already exist. It contains:

| Output | Intended destination |
| --- | --- |
| `50-trading-desk-router.yaml` | `/etc/netplan/50-trading-desk-router.yaml` |
| `wg-exec.conf` | `/etc/wireguard/wg-exec.conf` |
| `nftables.conf` | `/etc/nftables.conf` on this dedicated VM only |
| `70-trading-desk-router.conf` | `/etc/sysctl.d/70-trading-desk-router.conf` |
| `trading-desk-router-check` | `/usr/local/libexec/trading-desk-router-check`; emits bounded non-secret topology/config hashes, handshake time and WireGuard/HTTPS counters for a future collector |
| `mac-wireguard.conf.fragment` | attended paste into an app-generated Mac tunnel |
| `local-nat-lab-test-plan` | plan-only attended test commands; never executes them |
| `bundle-manifest.json` | retained deployment evidence |

The manifest states explicitly that public egress does not change, host direct
bypass is not prevented, venue writes are not authorized, mainnet is not
authorized, the application route gate does not default ready, no trusted
health collector or durable route-evidence binding is configured, and no
`PrivateKey` field is emitted. WireGuard public and private
keys have the same encoded shape, so the renderer cannot prove provenance; the
operator must attest that both supplied strings were derived public keys.
Retain the printed manifest SHA-256 outside the writable bundle in the change
record; checking against a digest stored only inside the same directory is not
authentication.

The guest-config renderer does not create or define the VM. The separate
nonmutating Lima renderer below pins the host/image envelope. Rendering creates
no VM or live NIC; its bundle includes the distinct reviewed host-preparation
commissioner described below, while VM/guest/network work remains separately
disabled.

## Plan-only Lima VM bundle

`deploy/ubuntu-router/lima` adds a second deterministic renderer for the host
VM envelope. It pins Lima 2.2.0, socket_vmnet 1.2.2 and the dated Ubuntu 24.04
ARM64 release image from 2026-08-14. Stock Lima/VZ always supplies one default
user-mode NAT NIC; the plan adds exactly one socket_vmnet host-only ingress
NIC. Guest preflight fails if a third interface appears. The VZ-derived WAN
name/MAC is retained as public post-create evidence and VM recreation requires
requalification.

```sh
python3 scripts/render_ubuntu_router_vm.py \
  --spec /absolute/reviewed/vm-spec.json \
  --output-dir /absolute/new/router-vm-plan
python3 scripts/render_ubuntu_router_vm.py \
  --check-bundle /absolute/new/router-vm-plan \
  --expected-manifest-sha256 REVIEWED_DIGEST_FROM_RENDER_OUTPUT
limactl validate /absolute/new/router-vm-plan/lima.yaml
```

The renderer itself is nonmutating and its output contains no private key. The
separate bundled commissioner enables only venue-credential-free preparation;
VM start and network apply remain disabled. The VM plan disables host mounts,
containerd, Rosetta, host DNS/proxy propagation, SSH-agent forwarding and port
forwards. Package-lock schema v3 binds a separate commission lock containing:

- the four signed Noble `InRelease` files and exact `main/binary-arm64`
  `Packages.xz` hash/size pairs at snapshot `20260814T203500Z`;
- the signed dated cloud-image checksum, image and 663-package base manifest;
- the complete 116-package hard-dependency closure for the eight direct
  router packages with `--no-install-recommends`; and
- one added package (`wireguard-tools`) with no upgrade or removal, plus its
  exact repository path, size and SHA-256.

The bundle also retains offline SLSA provenance bundles and a pinned Sigstore
trusted root for Lima 2.2.0 and socket_vmnet 1.2.2. Their exact repositories,
tag refs, workflow identities, source commits, GitHub-hosted runner claim,
archive hashes and installed-binary hashes are locked. The UEC cloud-image key
is separately pinned to fingerprint
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`; it is not falsely attributed to
the Noble archive keyring, which contains the distinct archive key used for
the snapshot `InRelease` signatures.

`commission-public.py --verify-inputs` can replay all of those public inputs
without network access when given an exact mode-`0700` evidence directory and
operator-trusted absolute `gh` and `gpgv` executables. It verifies the full
image payload, signatures, signed index bindings, package closure, Debian
archive framing, safe host tar members and offline attestations. Success still
prints `apply_enabled=false`: the verifier has no install, VM, network or key
operation. `bootstrap-public.sh` likewise accepts only `--plan`.

```sh
python3 /absolute/router-vm-plan/commission-public.py --plan
python3 /absolute/router-vm-plan/commission-public.py \
  --verify-inputs \
  --evidence-dir /absolute/mode-0700/public-inputs \
  --gh /absolute/real/non-symlink/gh \
  --gpgv /absolute/real/non-symlink/gpgv
```

The plan prints the exact 16-file public evidence inventory. Verify mode rejects
missing/extra files, symlinks, unsafe ownership/modes, an unsafe verifier path,
signature/attestation disagreement, an index or payload hash mismatch,
dependency ambiguity and any package-transaction widening. `gh` uses only the
embedded offline bundles and trusted root; credential/token variables and
ambient config/cache locations are not passed to it.

## Venue-credential-free stopped-VM preparation

The rendered VM bundle includes `commission-apply.py`, its root-only
`commission-apply-launcher.sh`, dormant `commission-guest.py`, and the exact
schema-v3 `commission-apply-lock.json`. Running the Python commissioners with no
argument prints their plans. The lock separates UID 501 public-evidence replay
from the disabled `trading-router-operator` UID/GID 454 that exclusively owns
writable Lima state. The enabled host-only sequence is:

1. `operator-verify` replays the public verifier with the exact current
   `gh`/`gpgv` binaries, their complete Homebrew dylib closure and the pinned
   root-owned `llvm-otool`. Its durable receipt is informational only. A root
   phase never executes those UID-501/Homebrew paths and never treats that
   receipt as installation authority.
2. `qualify-runtime` verifies the installed root-owned Python tree, contained
   symlinks, pinned interpreter and Apple `llvm-otool`, and retained
   payload-only load scan before creating a fixed root-only receipt.
3. `apply-seal-media` independently matches every public evidence file to the
   root-sealed commission lock and copies only a fixed basename allowlist from
   the already root-sealed controller. It publishes root-owned mode-`0500`
   media with exclusive rename and exact `INSTALLING`/`READY` markers.
4. `apply-host-tools` extracts the exact attested archives into
   `/opt/trading-desk-router-tools/lima-2.2.0` and `/opt/socket_vmnet`, and
   installs the exact public plan at
   `/opt/trading-desk-router-tools/plans/lima.yaml`. Every
   installed path is root-owned and non-writable, the entire archive tree is
   byte-compared, and the three installed binaries retain their locked hashes
   and valid code signatures.

5. `apply-lima-home` verifies the exact commissioned UID/GID-454 identity and
   schema-v3 identity receipt. It can adopt only the exact pre-existing empty
   mode-`0700` home created by macOS commissioning, using a durable root marker,
   then installs only `_config/networks.yaml` and a dedicated empty HOME. The
   socket_vmnet group is the exact `trading-router-operator` primary group, not
   `admin` or `everyone`; no sudoers rule or daemon is installed by this phase.
6. `apply-validate-fill` drops to UID/GID 454 with an empty bounded environment,
   reads only the immutable root-owned plan through an inherited pipe, and
   retains the exact effective configuration digest. The plan fixes
   `user.comment: "Trading Desk Router Operator"`; Lima therefore cannot fill
   this field from the invoking host account's mutable GECOS value.
7. `apply-vm-management-key` uses the pinned Apple `ssh-keygen` as UID 454 to
   create only Lima's dedicated ED25519 management key. Both the private key and
   its public-key file remain mode `0600` inside `_config`, matching the sealed
   root launcher's mode-`0077` umask. They are fully synced before promotion;
   the private key never prints and is explicitly distinct from venue,
   Keychain and WireGuard credentials. The schema-v3 lock permits one narrowly
   scoped recovery from the exact retained pre-fix marker/controller and
   validate-fill receipt by one pinned replacement-commissioner script: only
   the already generated mode-`0600` pending or partially promoted pair can be
   completed, and arbitrary predecessor or replacement controllers remain
   rejected.
8. `apply-local-image` copies the exact signed-image payload from sealed media
   to a root-owned mode-`0444` local path after headroom checks, retires (without
   deleting) the obsolete empty `LIMA_HOME/home`, and validates the separate
   manifest-bound local-image plan.
9. `apply-create-vm` runs only `limactl create --tty=false
   --name=trading-desk-router -` as UID 454. It pins the deterministic raw-disk
   hash, stored plan, cloud config, Lima version and VZ identifier; verifies the
   management key inode did not change; and requires stable interfaces/default
   routes with no VM or socket_vmnet process before and after. It never starts
   the VM. The receipt explicitly records `ready_to_start=false`: the stock
   cloud config still has an unlocked-password/admin model, so start remains
   blocked until the separately reviewed offline pre-frozen image and locked
   guest-account bootstrap replace it.

The launcher proves its canonical root-owned/no-ACL controller chain and checks
the sealed runtime's owner, write bits, ACLs, symlink containment, interpreter
digest and direct Mach-O load closure before `exec`. Python requires `-I -B`,
revalidates the complete runtime-tree receipt, and every phase uses Darwin
`renameatx_np(RENAME_EXCL)` plus full file/directory durability barriers. Exact
interrupted state is resumable; non-adoptable media/tool state requires an
explicit transaction-receipted quarantine. Nothing is automatically deleted or
silently replaced. A host-tool retry permits only retained quarantine names
bound by the exact transaction and completed quarantine receipt; it never
adopts or removes them. The VM manifest still has global/VM apply false while its
narrow host-preparation authority is true.

A validate-only replacement controller may reuse existing exact phase 01–03
receipts without reinstalling media, tools or Lima state. It must reverify that
the new controller's `networks.yaml` hash equals the commissioned Lima-home
receipt, keep the previously installed plan immutable, and feed its own
manifest-bound plan to `limactl` through `/dev/fd/0`. The validate receipt binds
both the earlier commissioning manifest and the replacement validation
controller/plan hashes.

The stop line remains before VM start. socket_vmnet sudoers and daemon
activation are absent, and a first boot could race APT timers before the
complete 663-package baseline is frozen. VM start, guest
freeze/simulation/install and router activation therefore remain literal false
gates. No host route, PF rule, tunnel, router/WireGuard key, venue credential or
venue state is changed; only the explicitly named local VM-management SSH key
is created.

## VM network contract

Use an Ubuntu 24.04 ARM64 VM with two distinct NICs. The reviewed Lima plan
realizes these as one implicit usernet WAN plus one explicit host-only ingress:

1. An ingress/management NIC reachable from the Mac over a host-only or shared
   network. The Mac WireGuard endpoint and narrowly sourced SSH use this NIC.
2. A separate WAN NIC using hypervisor-shared NAT or a reviewed bridged
   adapter. Do not assume `en0`, `eth0`, or any other interface name; obtain
   the Linux names from `ip -br link` and place the reviewed values in the
   public router profile. The rendered netplan fixes the reviewed host-only
   endpoint address and keeps the WAN on IPv4 DHCP; the endpoint must not
   depend on an unrecorded DHCP lease after reboot.

For this sole checked-in mode, the host-only contract is fixed: the Mac source
is `192.168.106.1/32` and the guest endpoint is `192.168.106.2/24`. The router
renderer rejects any other pair so its output cannot silently disagree with
the VM plan. The implicit Lima user-mode NIC is the separate WAN; adding
`user-v2`, `vzNAT`, another socket_vmnet network or any third non-loopback NIC
invalidates qualification.

Do not bind-mount the repository or any `/var/db/trading-desk` path. Disable
shared folders, clipboard exchange and guest-agent file transfer after initial
provisioning. Retain the Ubuntu image version, hypervisor version, VM config
hash and rendered bundle hash as qualification evidence.

The checked-in nftables template is deliberately for a dedicated VM and starts
with `flush ruleset`. Its observable policy is:

- default-drop input and forwarding;
- WireGuard UDP and SSH accepted only on the reviewed ingress interface and
  only from the exact management `/32`;
- established replies accepted;
- IPv4 forwarded only from `wg-exec` to the reviewed WAN interface; accepted
  HTTPS carries an explicit packet counter for two-sample route evidence;
- forwarded clients may use only the reviewed DNS resolver on port 53,
  HTTPS/TCP 443 and NTP/UDP 123; DoT, QUIC and other ports remain blocked;
- NAT applied only to the WireGuard IPv4 subnet on that WAN;
- no ingress-to-WAN forwarding rule;
- IPv6 captured by the Mac full-tunnel route but not forwarded by the VM;
- router-originated output allowed for package maintenance and diagnostics.

That final output rule means this local profile is not a remote-exit kill
switch. A future VPN-qualified profile needs a different reviewed ruleset with
default-drop output, pinned peer IP/UDP, tunnel-only DNS/NTP and NAT only onto
the remote WireGuard interface. Do not convert modes with an environment
variable or a small live edit.

## Attended setup — host preparation only

Before any router or venue credential is created, confirm the Mac remains on a
currently supported security release and retain reboot/runtime/test evidence.
The current host was updated from macOS 15.3.1 to 26.6.2 build 25G83 on
2026-08-26; the pinned runtime and all three supported Python test suites were
requalified. Repeat after any later OS/runtime change. Apple publishes current
security releases at <https://support.apple.com/100100>.

Only the bounded venue-credential-free preparation sequence is authorized:
runtime qualification, public-media sealing, inert host-tool installation,
UID-454 Lima-home initialization, `validate --fill`, one explicit
VM-management SSH key, local-image installation and stopped-VM creation. VM
start, guest-package, network and router-key commands remain unauthorized. The legacy unpinned
`apt-get update`, unversioned package install and immediate `wg genkey`
sequence has been removed because it bypassed the reviewed locks.

Run each host phase only through a newly root-sealed rendered bundle and carry
forward the exact receipt hash printed by the preceding phase. After that
host-only stop line, another review must:

1. bind a local verified image into a newly rendered create configuration;
2. rerun the rendered `host-preflight.sh --check` and retain the exact
   `limactl validate --fill` digest before every create/start;
3. create the VM from that validated local-image config
   without mounts, forwarded agent, proxy/DNS inheritance or a third NIC;
4. start it only after a race-free first-boot APT freeze exists, run
   `guest-preflight.sh --pre-key`, and prove from a console-side
   `apt-get --simulate` that the local package proposes exactly
   `wireguard-tools` with no upgrade/removal before guest package mutation;
5. install the separately rendered guest router bundle, apply netplan from
   the console, and pass `guest-preflight.sh --post-netplan` with exactly
   `192.168.106.2/24`; and only then
6. generate the VM WireGuard private key in the VM and the Mac key in the
   official WireGuard app. Only derived public keys may enter the reviewed
   router spec. Private keys never enter chat, the repo, cloud-init, argv,
   environment, shared folders or evidence logs.

Firewall/service activation and the Mac full-tunnel peer remain blocked until
that apply artifact exists and passes review. When eventually authorized, the
firewall must be applied from the VM console, not the SSH session it restricts;
IPv6 must fail closed at the local router rather than leak over a native Mac
route.

## Venue-credential-free qualification

No venue credential, executor state or queued command is needed for these
checks. Retain command output and packet captures. The rendered
`local-nat-lab-test-plan --plan` prints the reviewed command inventory but does
not execute any test or mutate the host.

1. Run `sudo /usr/local/libexec/trading-desk-router-check` after the Mac peer
   has a recent handshake. It performs bounded local configuration checks for
   forwarding, service state, nftables policy/NAT, WAN route, exact peer and
   handshake age. Its success is not transaction or host-bypass readiness.
2. Confirm the Mac default IPv4 and IPv6 traffic enters the WireGuard tunnel.
3. Make a read-only TESTNET `/info` request and connect to the documented
   TESTNET WebSocket endpoint without sending an exchange action.
4. Confirm the observed public IP is still the home/office IP. A different IP
   would contradict `local_nat_lab` and requires review.
5. Confirm native IPv6, alternate DNS, DoT, QUIC/UDP 443 and unreviewed ports
   fail. For IPv6, record the `wg-exec` pre-routing IPv6 ingress counter before
   and after, keep kernel IPv6 forwarding at zero, and prove the WAN has neither
   an IPv6 default route nor a global IPv6 address. IPv6 is rejected before the
   forward hook and is not expected to increment its drop counter. For the
   IPv4 alternate-DNS, DoT, QUIC and unreviewed-port probes, record the explicit
   `wg-exec` forward drop counter before and after; a UDP client exit code alone
   is not evidence. The local profile deliberately permits TCP 443 to any
   destination and NTP/UDP 123; exact application URLs and TLS hostname checks
   remain separate.
6. Stop `wg-quick@wg-exec`, stop the VM, kill the hypervisor, renew DHCP,
   sleep/wake and reboot both sides. Record when macOS falls back to a physical
   route; this is expected evidence that host bypass remains unprevented.
7. Retain unit/fake-transport evidence for failure before and after durable
   attempt persistence. A real forward-request/drop-response exercise is not
   part of this no-write phase and remains an implementation gap before live
   qualification.

The application now has a narrowing-only route-health contract. It binds the
executor config, reviewed router/VM manifests, local-lab qualification,
peer-key hashes, exact endpoint/interfaces/peers/DNS and installed public
configuration. One evidence document contains two stable samples around the
fixed credential-free TESTNET `POST /info {"type":"meta"}` read. It requires a
recent handshake, unchanged Mac IPv4 and IPv6 `utun` defaults, exact guest
forwarding/nftables assertions, non-regressing WireGuard counters and an
increasing accepted-HTTPS counter. Collection may span at most 15 seconds and
expires within five seconds of its second sample.

This gate defaults to unavailable. A new entry is denied in the same-tick
runtime readiness decision, before account/market reads, and again inside the
final runtime submission guard before authority/send unless a trusted reader
returns exact active evidence. Each reader is bracketed by service-clock
samples; rollback or expiry during the read fails, and the final sample must
leave the full two-second PRE_SEND TTL before authority. Failure voids a
proven-unsent entry and never selects a direct route. Recovery remains
independent. The repository now has fixed local/remote root-owned caches, a
continuous fixed remote sample/probe collector, runnable hash-pinned helpers
and route-bound submission authority. No helper, schedule, PF/tunnel or
commissioned artifact is installed, so the collector path remains unavailable
by default.
A route-only preparation denial can release only the current claim and requeue
that same command while its ticket and all three legs remain active and no
attempt/authority exists. Before preview, credential-free maintenance
normalizes expired claims and atomically terminalizes queued work at the
earliest ticket/leg expiry, releasing its proven-unsent reservation. Thus a
permanent outage cannot strand the account's active-command slot.
`build_installed_testnet_route_health_gate()` is the production composition
hook. It loads only already-collected local evidence within a strict byte and
filesystem bound. It does not run SSH, route tools, DNS, TLS or the `/info`
probe while the final runtime submission lock is held; the separate collector
owns those observations and atomic evidence publication.

### Fixed route-health artifact and collector boundary

The local-mode expectation and short-lived cache have no configurable path:

```text
/private/var/db/trading-desk-testnet-route-health/<executor-config-hash>/expectation.json
/private/var/db/trading-desk-testnet-route-health/<executor-config-hash>/evidence.json
```

Both directory levels must be root:wheel mode `0755` and ACL-free. Both files
must be root:wheel mode `0444`, single-link, ACL-free regular files no larger
than 128 KiB. The reader opens through a verified directory descriptor with
`O_NOFOLLOW`, checks stable metadata around one bounded read, requires exact
canonical schemas, and re-verifies the config/manifest/topology bindings. The
root publisher writes a new file, fully syncs it, atomically replaces the cache,
fully syncs the parent, and reads the result back. The executor receives only
that cached document.

`trading-harness-route-health-collector --collect` uses the fixed executor
config and makes exactly three helper calls without retries: sample, read-only
probe, sample. The helpers must be root:wheel mode `0555`, single-link and
ACL-free at these fixed paths:

```text
/usr/local/libexec/trading-desk-testnet-route-sample
/usr/local/libexec/trading-desk-testnet-route-probe
```

Each helper receives no argument, stdin, credential environment or secret. The
sample helper has three seconds and must emit one canonical
`testnet_route_health_sample.v1` document combining current Mac default-route
and guest-check observations. The probe helper has six seconds and must emit
one canonical `testnet_route_health_probe_receipt.v1` for the fixed TESTNET
`POST /info {"type":"meta"}` request plus the retained negative-path
qualification/public-IP comparison. Output is bounded to 128 KiB. Clock
rollback, stale observations, changed topology, a non-advancing HTTPS/WireGuard
counter, wrong request hash, insufficient headroom before publication, or any
helper failure produces no publication and no retry. Headroom is checked again
after the atomic write; a cache that became too old during storage is left as
non-authoritative history and the executor gate rejects it.

Those two helper executables are contracts, not installed implementations.
The Mac-to-guest observation transport and retained local qualification receipt
must be selected and reviewed before they can be sealed. No expectation,
evidence file, helper, launchd job, ACL, network setting or credential is
installed by this repository change.

If the WireGuard route remains selected but blackholes after the final check,
one failed/unknown attempt is still possible. If macOS removes that route,
traffic may bypass the VM and succeed directly. There is no application-
configured fallback, but host fallback remains possible. A successful request
alone does not prove VM traversal. The gate is a fail-closed application signal,
not a host kill switch or VPN qualification.

## Current stop line and shortest attended sequence

Today the safe sequence stops after replaying the immutable public inputs,
qualifying the sealed runtime, sealing media, installing inert Lima/socket_vmnet
files, adopting the exact empty UID-454 `LIMA_HOME`, and retaining
`limactl validate --fill`; it then creates the dedicated management SSH key,
installs the exact local image, validates the local plan and creates one stopped
VM. These phases do not start a VM, install a sudoers rule, start socket_vmnet,
mutate guest packages, activate
nftables/WireGuard or change Mac routes.

The remaining blockers are intentional: socket_vmnet sudoers/daemon activation
is absent and there is no race-free first-boot APT freeze or console simulation
transcript. VM start, guest package mutation and every network/router-key phase
remain disabled.

After a later promotion, the shortest continued sequence is: bind the verified
local image and revalidate the exact configuration; create and start the exact
two-NIC VM; pass guest pre-key and post-netplan checks; generate each router-only
key on its owning machine; render and verify the router bundle; install it from
the VM console; activate the Mac tunnel; then execute and retain the rendered
local test plan. This qualifies the local failure/routing lab only.

## Remote TESTNET VPN egress overlay — renderable, not applied

The repository now has a separate `testnet_remote_vpn_exit` public-data overlay
under `deploy/ubuntu-router/remote-egress`, rendered by
`scripts/render_ubuntu_remote_egress.py`. It composes with one exact hashed
`local_nat_lab` bundle and does not mutate that mode in place. The overlay adds
`wg-egress`, replaces the guest firewall with default-drop output/forward
policies, permits the physical WAN only for DHCP and the fixed outer WireGuard
endpoint, forwards DNS/NTP/HTTPS only from `wg-exec` to `wg-egress`, and NATs
only onto `wg-egress`. It emits no direct-WAN fallback: loss of the remote peer
blackholes client traffic.

The operator must obtain five public values from a WireGuard-capable provider:
the provider-assigned tunnel IPv4 interface, fixed endpoint IPv4 and UDP port,
remote peer public key, tunnel DNS IPv4, and expected exit IPv4. A hostname or
rotating endpoint is deliberately unsupported. The spec also repeats the
reviewed VM interface names, Mac peer public key and local topology, and binds
the exact base-router manifest hash. Public-key encoding cannot establish that
a value was derived from a public rather than private key, so provenance is an
attended operator check.

With populated public values and an already rendered base bundle, render and
verify without credentials or network mutation:

```sh
python3 scripts/render_ubuntu_remote_egress.py \
  --render \
  --base-router-bundle /absolute/local-router-bundle \
  --spec /absolute/remote-egress-spec.json \
  --output /absolute/remote-egress-bundle

python3 scripts/render_ubuntu_remote_egress.py \
  --verify \
  --base-router-bundle /absolute/local-router-bundle \
  --bundle /absolute/remote-egress-bundle \
  --expected-manifest-sha256 REVIEWED_64_HEX_DIGEST
```

The output contains the public `wg-egress.conf`, complete replacement
`nftables.conf`, fixed policy-routing/sysctl values, systemd drop-ins that make
`wg-exec` require nftables plus `wg-egress`, a guest checker, a print-only
failure/leak test plan, and a derived Mac WireGuard fragment that replaces the
local-lab resolver with the provider tunnel DNS. The renderer requires the
remote spec's repeated interfaces, listen port, WireGuard network, Mac peer and
Mac public key to exactly match the hashed base-router topology; a merely
hash-valid but semantically different composition is rejected. Its fixed table
51821, fwmark 51821 and rule priorities
11000/11010 must be absent before installation. The rendered plan requires the
replacement firewall to be installed and validated from the VM console before
either tunnel is exposed. It does not install anything, create
`/etc/wireguard/trading-desk-egress.key`, start a service, contact the provider,
or change routes. A locally generated provider-compatible key may later be
created inside the guest. For Proton, the separately reviewed attended
importer below may instead extract the client key from Proton's downloaded
WireGuard profile directly into that fixed root-only file. In either case the
private key must never enter the spec, repository, environment, argv, chat or
a host/guest shared directory.

### Attended Proton profile import

`deploy/ubuntu-router/remote-egress/import-proton-wireguard.py` is a standalone
Ubuntu-guest importer for a Proton WireGuard configuration downloaded through
the operator's Proton account. It is not included in a rendered public bundle
and is not an authorization to create/start the VM or activate networking.
Before use, install a reviewed sealed copy at the fixed guest path
`/usr/local/libexec/trading-desk-import-proton-wireguard` as root:root mode
`0500`. The importer's mutating mode refuses any other program path, a
non-Ubuntu-24.04 ARM64 guest, a non-root or background session, any process
environment beyond the fixed locale/path allowlist, or Python without
isolated/no-bytecode flags. It also refuses active swap and disables process
and child core dumps before reading the profile.

The source profile is secret-bearing because it contains `PrivateKey`. It must
arrive through an attended operator-controlled secret transfer directly into
`/root/trading-desk-proton-import-v1`, never through chat, the repository, a
host/guest shared directory, an environment variable or argv. That directory
must be root:root mode `0700`; the selected direct-child `.conf` must be a real,
ACL/xattr-free, single-link root:root mode-`0400` file. Do not paste the profile
or its private key into a task or retain it in shell history.

The importer accepts exactly one `[Interface]` containing `PrivateKey`,
`Address` and `DNS`, followed by exactly one `[Peer]` containing `PublicKey`,
`AllowedIPs`, an IPv4 `Endpoint`, and an optional canonical
`PersistentKeepalive = 25`. Hooks, tables, preshared keys, hostnames, split
routes, extra peers and unknown fields fail closed. It accepts the
Proton IPv4 full-tunnel form and its optional IPv6 address/default route, but
installs only the base64 client private key required by the repository's
IPv4-only `wg-egress` policy. It invokes fixed `/usr/bin/wg pubkey` with the key
on a pipe, never in argv or the environment.

From the attended guest root console, first inspect the root-only source:

```sh
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B \
  /usr/local/libexec/trading-desk-import-proton-wireguard \
  inspect --source /root/trading-desk-proton-import-v1/PROFILE.conf
```

Inspection returns only the sanitized public profile, the full-profile and
public-binding SHA-256 fingerprints, derived-local-public-key and remote-key
fingerprints, and false authority/network claims. It never returns the private
key, source path or derived local public key. Copy only its `public_profile`
fields into the reviewed remote-egress spec, render and verify the public
bundle, and require its `wireguard_profile_public_binding_sha256` to equal the
inspection result. Then run the one-time import with both independently
retained fingerprints:

```sh
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B \
  /usr/local/libexec/trading-desk-import-proton-wireguard \
  install --source /root/trading-desk-proton-import-v1/PROFILE.conf \
  --expected-profile-sha256 REVIEWED_PROFILE_SHA256 \
  --expected-public-binding-sha256 REVIEWED_PUBLIC_BINDING_SHA256
```

The importer atomically creates only
`/etc/wireguard/trading-desk-egress.key` as root:root mode `0600` and a
redacted, root-only receipt at
`/var/lib/trading-desk-router-commission/state/04-proton-wireguard-import.json`.
It never overwrites a different key or receipt; an interrupted same-key import
is resumably adopted only after the retained pending inode, metadata, xattrs
and bytes are reverified and synced. A partial, different or unsafe pending
file is retained for attended review and is never automatically deleted. It
does not delete the source, install public config,
start WireGuard, change routes, contact Proton/Hyperliquid or authorize a venue
write. Retire the source separately through the operator's reviewed secret
retention procedure after the receipt is retained.

A separate render-only macOS PF anchor for executor UID 451 plus resolver UID
65, typed root-owned remote cache, fixed sample/probe helpers, continuous
collector, artifact installer and route-bound sender now exist. TESTNET source
gates are promoted, but missing root artifacts fail closed. Nothing has loaded
the PF anchor or started the helpers, so active host/DNS bypass prevention is
absent. Live provider handshake,
expected-exit-IP, DNS/IPv6/DoT/QUIC, tunnel-loss and reboot tests remain
attended commissioning steps. Until those pass, the rendered manifests
truthfully report `remote_vpn_exit_configured=false` and `vpn_qualified=false`.

## First TESTNET transaction boundary

The local router can carry read-only TESTNET traffic after its local checks. It
may carry attended functional transactions only after the separate
commissioning gaps close, and it never qualifies always-on egress isolation.
The default-unavailable route gate blocks normal entry until the fixed collector
and reviewed expectation are installed. Normal and qualification submission
authorities durably bind the exact remote evidence and recheck it after
authority; installed PF remains necessary to prevent macOS route fallback.
The first harness order write remains blocked by
`docs/testnet_commissioning.md`. The qualification-only GTC/cancel durable core
plus dormant signer/sender/result transitions and a role-bound terminal CLI
exist offline, but submission authority, a complete live lifecycle worker and
live integration remain absent. Do not substitute the armed three-leg bracket
as an easier first write.

After the local lab is stable and the provider values are reviewed, preserve
the Mac-to-VM `wg-exec` interface and commission the separately rendered
VM-to-remote `wg-egress` overlay. It can provide the reviewed exit IP without
moving the signer out of macOS, but only after the PF, collector and failure
tests above are active.

## References

- Ubuntu snapshot service:
  <https://ubuntu.com/server/docs/how-to/software/snapshot-service/>
- Ubuntu cloud-image checksum/signing-key verification:
  <https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/>
- GitHub offline artifact-attestation verification:
  <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline>
- Lima default user-mode network:
  <https://lima-vm.io/docs/config/network/user/>
- Lima VMNet/socket_vmnet networks:
  <https://lima-vm.io/docs/config/network/vmnet/>
- Ubuntu default-gateway WireGuard model:
  <https://ubuntu.com/server/docs/how-to/wireguard-vpn/vpn-as-the-default-gateway/>
- WireGuard key generation and persistent keepalive:
  <https://www.wireguard.com/quickstart/>
- Proton WireGuard configuration download:
  <https://protonvpn.com/support/wireguard-configurations>
- Proton manual WireGuard setup for Linux:
  <https://protonvpn.com/support/wireguard-linux>
- Hyperliquid TESTNET WebSocket endpoint:
  <https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/websocket>
