# Attended TESTNET System Keychain provisioning plan

This is an operator plan, not an authorization to run it. Repository tests and
the default build command do not access a Keychain, read a credential, install
an executable or change a system path. Mainnet remains disabled.

The native candidate creates exactly these generic-password records in
`/Library/Keychains/System.keychain`:

| Purpose | Service | Account | Sole trusted reader |
| --- | --- | --- | --- |
| signer | `com.jawndiego.trading-desk.testnet-signer` | `hyperliquid-api-wallet` | executor reader |
| recovery | `com.jawndiego.trading-desk.testnet-recovery` | `recovery-hmac` | executor reader |
| approval | `com.jawndiego.trading-desk.testnet-approval` | `approval-hmac` | control reader |
| grant | `com.jawndiego.trading-desk.testnet-grant` | `grant-hmac` | control reader |
| executor probe | `com.jawndiego.trading-desk.testnet-probe-executor` | `sacrificial-probe-executor-v1` | executor reader |
| control probe | `com.jawndiego.trading-desk.testnet-probe-control` | `sacrificial-probe-control-v1` | control reader |

It accepts exactly one fixed slot name: `signer`, `recovery`, `approval`,
`grant`, `probe-executor` or `probe-control`. No argument controls a label,
account, reader or Keychain path. For `signer`, it reads the value twice from
`/dev/tty` with echo disabled, accepts
optional `0x` and hex letter case, and holds only the normalized nonzero
64-character lowercase form. Each HMAC invocation generates its one value with
`SecRandomCopyBytes`. No value is printed. The program cannot find, read, list,
update, replace, export or delete a Keychain item. A duplicate makes that
single create fail and leaves the existing item intact; successful slots are
therefore explicit, independently reviewable progress rather than a partial
four-item transaction. Security-framework user interaction is disabled before
the fixed Keychain open/create, so an unexpected GUI or unlock prompt fails
closed.

## Gated operator sequence

1. Finish every credential-free commissioning gate. Independently verify the
   TESTNET API wallet maps to the intended funded main account. Do not use a
   main-account private key.
2. Copy the builder and its exact C source from the reviewed commit into one
   absolute, canonical, root-owned, non-writable, ACL-free sealed source tree.
   Run only `build-keychain-provisioner.sh --build-release` with a new output
   below an equally sealed root-owned parent. Release mode verifies its own
   location and ancestor chain, the exact pinned source digest, direct
   root-owned Apple clang 21.0.0 (`clang-2100.1.1.101`), macOS 26.5 SDK,
   hardened signature and authoritative deterministic output digest. The
   `--build-development` mode is untrusted test output and is forbidden here.
   This reviewed source is
   `fc102c93fe21ce8d32236ad28d558b952521dcd4870d42fe0c1734fe7562d089`;
   its only eligible provisioner artifact is
   `3a834ab130bd89525ad386b186f8c86d5fd744d7aa5e9fc2a31572f125dfbcb3`.
3. Accept only the authoritative provisioner artifact SHA-256 printed by the
   sealed release builder; any other output is substitution, regardless of a
   reused ad-hoc identifier. Record the source commit, provisioner SHA-256,
   reader SHA-256 values and all three signing identifiers in an external
   manifest. Move the candidates to
   root-owned, non-writable sealed media. Re-verify hashes and signatures from
   that media.
4. Install the two reviewed role readers first. Before credential entry, prove
   their exact canonical paths, root owner, role group, mode `0510`, one link,
   absence of extended ACLs, expected SHA-256 values, valid hardened signatures
   and fixed signing identifiers. Prove UID 451 can execute only the executor
   reader, UID 452 only the control reader, and UIDs 450 and 501 neither.
5. From a directly attended root console, create exactly
   `/private/var/root/trading-desk-keychain-provisioning-v1` as root:wheel mode
   `0700`, with no extended ACL, then copy the sealed candidate to its exact
   compiled path `trading-keychain-provisioner-v1` as root:wheel mode `0500`,
   one link. Re-verify its external SHA-256 and hardened signing identifier.
   Do not leave another file in that directory.
6. Provision only `probe-executor` and `probe-control` first. Both are random,
   non-production records with separate labels; they never require deleting or
   replacing a production record. Follow the separately reviewed
   [nonprinting probe runner plan](KEYCHAIN_ROLE_PROBE_PLAN.md), accepting only
   runner artifact SHA-256
   `96b3c941dba152402728d825c19a9d586d852b718f4ff06a06bd37b4335658f9`.
   Require its complete intended-UID, root, research, desktop and cross-role
   matrix. Reboot and repeat the complete matrix, then remove its ephemeral
   executable path.
   Production provisioning remains blocked until both passes succeed. Harmless
   probe records may remain with their reader-only ACLs.
7. Confirm descriptors 0, 1 and 2 are the same foreground terminal. Through
   `/usr/bin/env -i`, invoke the exact absolute provisioner path once for each
   fixed slot, using only the respective literal `signer`, `recovery`,
   `approval` or `grant` argument. Enter only the dedicated TESTNET API-wallet
   private key at both hidden prompts for `signer`; HMAC slots must not prompt.
   Record a public pass/fail receipt after each invocation. Stop on any generic
   failure; do not overwrite or delete via an improvised command. The attempted
   create is atomic for that slot, and a duplicate is unchanged.
8. After each success, inspect only public metadata and ACL membership before
   moving to the next slot. The item must contain exactly its matching reader
   application in the trusted-application list; `/usr/bin/security`, the
   provisioner, shells, Python, Terminal and the other reader must not be
   trusted. Never reveal the password while inspecting.
9. Do not invoke a reader directly or attempt to adapt the probe runner to a
   production slot. Its no-argument binary is compiled for the two sacrificial
   labels only; the production-item proof is the exact ACL metadata plus the
   already-passed reader/UID matrix.
10. Immediately after the four production ACL checks,
   remove the provisioner from its canonical executable path and remove the now-empty
   provisioning directory. Alternatively, move the whole sealed directory to
   offline quarantine with no execute permission. Re-prove that the canonical
   path is absent. The installed role readers remain read-only; no long-lived
   credential-mutation executable may remain on the machine.
11. Retain only redacted hashes, ownership/signature/ACL results and pass/fail
    probe evidence. Never retain the signer, generated HMAC values, reader pipe
    bytes, Keychain password exports or terminal capture.

If any slot already exists, any ACL includes an extra trusted application, a
role can execute the wrong reader, terminal echo is not restored, or the
canonical provisioner remains installed, credential qualification fails closed.
