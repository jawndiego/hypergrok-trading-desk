# Local Ubuntu VM router for TESTNET qualification

Status: **repository-rendered guest configuration plus a pinned, plan-only
Lima/VZ VM bundle; signed package snapshot, VM apply and boot orchestration
remain unapplied/unqualified; not VPN-qualified or a capital security
boundary**.

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
| `trading-desk-router-check` | `/usr/local/libexec/trading-desk-router-check` |
| `mac-wireguard.conf.fragment` | attended paste into an app-generated Mac tunnel |
| `bundle-manifest.json` | retained deployment evidence |

The manifest states explicitly that public egress does not change, host direct
bypass is not prevented, venue writes are not authorized, mainnet is not
authorized, and no `PrivateKey` field is emitted. WireGuard public and private
keys have the same encoded shape, so the renderer cannot prove provenance; the
operator must attest that both supplied strings were derived public keys.
Retain the printed manifest SHA-256 outside the writable bundle in the change
record; checking against a digest stored only inside the same directory is not
authentication.

The guest-config renderer does not create or define the VM. The separate
plan-only Lima renderer below pins the host/image envelope, but neither tool
creates a VM, attaches a live NIC, bootstraps packages, installs files or
arranges boot ordering. Those remain explicit commissioning tasks.

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

The output is apply-disabled and contains no key. It disables host mounts,
containerd, Rosetta, host DNS/proxy propagation, SSH-agent forwarding and port
forwards. Its package lock remains
`awaiting_signed_apt_snapshot_and_vm_guest_preflight`: the candidate Ubuntu
snapshot and archive keyring must prove every exact package version before a
bootstrap/apply procedure may be added. `bootstrap-public.sh` therefore accepts
only `--plan`.

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
- IPv4 forwarded only from `wg-exec` to the reviewed WAN interface;
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

## Attended setup — currently blocked before apply

Before any router or venue credential is created, confirm the Mac remains on a
currently supported security release and retain reboot/runtime/test evidence.
The current host was updated from macOS 15.3.1 to 26.6.2 build 25G83 on
2026-08-26; the pinned runtime and all three supported Python test suites were
requalified. Repeat after any later OS/runtime change. Apple publishes current
security releases at <https://support.apple.com/100100>.

No VM/package/network/key command is authorized yet. The legacy unpinned
`apt-get update`, unversioned package install and immediate `wg genkey`
sequence has been removed because it bypassed the reviewed locks.

The next attended change must be a separately reviewed apply artifact that:

1. installs the exact hash- and signature-checked Lima and socket_vmnet
   binaries, creates a dedicated mode-`0700` `/var/db/trading-desk-lima`,
   installs only the rendered `networks.yaml`, and proves `default.yaml` and
   `override.yaml` are absent;
2. runs the rendered `host-preflight.sh --check` and retains the exact
   `limactl validate --fill` digest before every create/start;
3. proves the candidate signed Ubuntu snapshot, archive keyring hash and every
   locked package version, then changes the package lock from
   `review_pending_live_apt_policy` to `verified` through review;
4. creates the VM without mounts, forwarded agent, proxy/DNS inheritance or a
   third NIC, then runs `guest-preflight.sh --pre-key` from its console;
5. installs the separately rendered guest router bundle, applies netplan from
   the console, and passes `guest-preflight.sh --post-netplan` with exactly
   `192.168.106.2/24`; and only then
6. generates the VM WireGuard private key in the VM and the Mac key in the
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
checks. Retain command output and packet captures.

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
   fail. The local profile deliberately permits TCP 443 to any destination and
   NTP/UDP 123; exact application URLs and TLS hostname checks remain separate.
6. Stop `wg-quick@wg-exec`, stop the VM, kill the hypervisor, renew DHCP,
   sleep/wake and reboot both sides. Record when macOS falls back to a physical
   route; this is expected evidence that host bypass remains unprevented.
7. Retain unit/fake-transport evidence for failure before and after durable
   attempt persistence. A real forward-request/drop-response exercise is not
   part of this no-write phase and remains an implementation gap before live
   qualification.

The current application has no router-health admission field. If the WireGuard
route remains selected but blackholes, authority may be consumed before one
failed/unknown attempt. If macOS removes that route, traffic may bypass the VM
and succeed directly. There is no application-configured fallback, but host
fallback remains possible. A successful request alone does not prove VM
traversal. Do not describe router health as an entry gate until separately
reviewed application and host enforcement implement one.

## First TESTNET transaction boundary

The local router can carry read-only TESTNET traffic after its local checks. It
may carry attended functional transactions only after the separate
commissioning gaps close, and it never qualifies always-on egress isolation.
The first harness order write remains blocked by
`docs/testnet_commissioning.md`. The qualification-only GTC/cancel durable core
exists, but its signer, sender, result transitions and direct-terminal CLI do
not. Do not substitute the armed three-leg bracket as an easier first write.

After the local lab is stable, preserve the Mac-to-VM `wg-exec` interface and
add a separately reviewed VM-to-remote-gateway tunnel. That later design can
provide a static exit IP without moving the signer out of macOS.

## References

- Ubuntu default-gateway WireGuard model:
  <https://ubuntu.com/server/docs/how-to/wireguard-vpn/vpn-as-the-default-gateway/>
- WireGuard key generation and persistent keepalive:
  <https://www.wireguard.com/quickstart/>
- Hyperliquid TESTNET WebSocket endpoint:
  <https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/websocket>
