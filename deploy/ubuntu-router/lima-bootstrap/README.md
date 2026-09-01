# Attended online post-start UNKNOWN recovery

This bundle has one attended phase: `recover-poststart-unknown-online`. It is
for the exact e33 first-boot attempt whose start log reached VZ `running`, whose
watchdog aborted on `full_route_topology_drift`, and whose incident disposition
is `UNKNOWN`. That disk is tainted and may never be retried or reused.

The controller pins the e33 markers, logs, watchdog result, incident, hardware
captures, retained sudoers, live VMNet residual, `LIMA_HOME/Library`, stopped VM
instance, receipt 08
`e5f8d3e43cb53fa0c72e0bfa88796147b310bdb50c21898b2f780362f910d84c`,
and quarantine ancestry
`2ae8f48d9363ebbc9605f604c4b6bbcd7ac54161b77a819731a0abe27525dbf5`.
It does not relax the route watchdog or infer the missing failed route row.

Run the sealed launcher online from a local attended Terminal:

```sh
sudo /absolute/sealed/bundle/bootstrap-apply-launcher.sh \
  recover-poststart-unknown-online \
  --expected-controller-manifest-sha256 <sealed-manifest-sha256>
```

Before mutation, a durable transaction binds the complete evidence frontier,
the tainted instance and changed disk descriptor, the stopped/no-process proof,
the host network snapshot, the original identity/birth lineage, an initially
empty verified process HOME, and the exact `LIMA_HOME/_config` inventory. The
SSH private key is bound only by metadata and is never opened or hashed.

The phase then quiesces the exact Apple UID-454 agent subset, compare-and-swaps
the Directory Service home from `LIMA_HOME` to the verified process HOME, runs
one exact-name stopped Lima status, quiesces UID 454 again, and retains all 15
tainted artifacts through crash-resumable source-or-destination moves. It
publishes receipt 14 only after `LIMA_HOME` contains exactly `_config`, every
tainted source is absent, every retained destination revalidates, the target
home is live, UID 454 and VM/watchdog processes are absent, and the network
authority remains absent. The initial whole-host network snapshot stays in the
audit record, but later online route, uplink, or inert-utun drift does not wedge
quarantine; only live VM interfaces, temporary sudoers, or router processes do.

Transaction, stopped-proof, and receipt pending files are validated and
promoted on rerun. A completed rerun only revalidates and prints the same
receipt. Ambiguous final-plus-pending state, out-of-order moves, drift, or an
unexpected process fails closed.

Success prints:

```text
poststart_unknown_recovery_receipt=/private/var/db/trading-desk-router-bootstrap-v1/receipts/14-poststart-unknown-recovery-e33dbb26c0b91014f0748dd121d78d66627dd11c1fe8db4af0931d2254865999.json
poststart_unknown_recovery_receipt_sha256=<sha256>
reserved_fresh_session_id=791f39c1e4dae90f50436de700211158688f557f70e91156c0a9dd95d3b7b7b8
fresh_recreate_authorized=false
disk_reuse_authorized=false
vm_status=Stopped
network_changes_performed=false
network_reconnect_authorized=false
venue_writes_authorized=false
mainnet_authorized=false
```

The fresh session is reserved only. This bundle cannot check an air gap,
create, start, retry, reconnect to, or delete a VM. It cannot authorize venue
writes or mainnet. A separately rendered phase-2 bundle must pin receipt 14
before it may recreate a fresh stopped VM; a later, separately reviewed bundle
must handle any air-gapped first boot.

The renderer is inert: it writes a review directory and replay-checks hashes,
owners, modes, ACLs, and the manifest. Rendering does not install the bundle or
execute recovery.
