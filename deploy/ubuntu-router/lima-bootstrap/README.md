# Attended air-gap bootstrap continuation

This continuation consumes only the commissioned receipt-07 VM whose digest is
`1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601`.
Its currently enabled phase retains that never-booted instance and creates a
hardened replacement that remains stopped. It performs no VM start, guest
execution, active networking, credential access, router-key operation or venue
operation.

Render and replay-check as the desktop operator:

```sh
python3 scripts/render_ubuntu_router_bootstrap.py \
  --output-dir /absolute/new/review-directory

manifest_sha256=$(shasum -a 256 \
  /absolute/new/review-directory/bundle-manifest.json | awk '{print $1}')

python3 scripts/render_ubuntu_router_bootstrap.py \
  --check-bundle /absolute/new/review-directory \
  --expected-manifest-sha256 "$manifest_sha256" \
  --require-owner-uid 501
```

The root apply must use a separately root-sealed copy and carry that manifest
hash into `bootstrap-apply-launcher.sh apply-hardened-vm`. On success it prints
receipt 08 and leaves both the replacement and retained predecessor stopped.

Do not start the replacement manually. The next controller must continuously
prove that all Mac uplinks/default IPv4 and IPv6 routes are absent for the
whole first boot, stop the VM on every error, and authorize reconnect only
after `/usr/local/libexec/trading-desk-verify-first-boot` succeeds. The guest
nftables policy is not present before that air-gapped boot.
