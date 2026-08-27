# Attended sacrificial Keychain role-probe plan

This plan qualifies only the two harmless TESTNET probe records. It does not
authorize production credential provisioning, service installation, `init`, a
venue call, or mainnet. The runner never reads a production slot and never
prints or persists a probe value.

## Fixed contract

The no-argument native runner is compiled for exactly:

- executor reader
  `/opt/trading-desk/libexec/trading-keychain-reader-executor-v1`, SHA-256
  `42e583ee40d48546a92bf40bf650fa576ec3d86455bf663cc3760b90d050df27`,
  slot `probe-executor`;
- control reader
  `/opt/trading-desk/libexec/trading-keychain-reader-control-v1`, SHA-256
  `da10752940f726258f4e2439b657db0c2f3fefcb3c30ef6a1eaa69df3da8e194`,
  slot `probe-control`.

It has no path, label, slot, UID, keychain, timeout, command, or retry input.
Each of ten cells forks exactly once. The child receives one exact
supplementary group, GID and UID; stdin is `/dev/null`, stdout is a bounded
pipe owned by the root parent, stderr is `/dev/null`, and the exec environment
is empty. A `/dev/fd` inventory rejects even inherited descriptors above a
lowered soft limit immediately before fork. The child then closes and re-proves
closed the exact pipe/null descriptors created after that inventory, before its
identity drop. The parent blocks signals across each live-child
window, then reaps the child and zeroes the buffer before restoring its prior
signal mask. The child starts with an empty signal mask. The parent accepts an
allowed read only after EOF, normal exit zero,
and exactly 64 nonzero lowercase hexadecimal bytes. It reads at most one extra byte,
rejects extra/truncated/zero/malformed output, overwrites the entire
locked buffer immediately after classification, and never retries. A denial
passes only with no stdout and the reader's fixed denial exit or kernel execute
denial. The three-second monotonic deadline is captured before pipe creation and fork; an
exec-surviving three-second `SIGALRM` watchdog also bounds an orphan if the
parent is stopped or uncatchably terminated. The parent kills and reaps on its
own timeout or capture failure.

The matrix admits only UID/GID 451 through the executor reader and UID/GID 452
through the control reader. It proves denials for root, research UID/GID 450,
desktop UID 501/GID 20, executor-to-control and control-to-executor. Output is
only these fixed redacted `PASS`/`FAIL` rows and an overall row.

## Build and seal

1. Review `keychain-role-probe-runner.c` and
   `build-keychain-role-probe-runner.sh` from one pinned commit. The reviewed
   source SHA-256 is
   `3b434f8ccaee6f1bc09ec0171cf4576ded8b96c6c83f4bfa9dbdcfe2a0e99af3`;
   the only eligible artifact SHA-256 is
   `356e6a01e178571c1ef1985c84a2ce1ca6028850e4ac13081e52f3edbda89076`.
2. Copy only that builder and source to an absolute canonical root-owned,
   non-writable, ACL-free sealed source tree. Through `/usr/bin/env -i`, run
   `--build-release` with a new output under an equally sealed root-owned
   parent. `--build-development`
   produces an explicitly untrusted test artifact and is forbidden for the
   attended probe.
3. Release mode pins and verifies direct root-owned Apple CLT clang 21.0.0
   (`clang-2100.1.1.101`), its exact digest and Apple code signature, the macOS
   26.5 SDK settings digest, source digest, static-analyzer result, two
   byte-identical independent builds, hardened ad-hoc identifier, forbidden
   symbol surface and final artifact digest. The build does not execute the
   candidate.
4. Move the eligible artifact through separately controlled sealed media.
   Re-verify its SHA-256, hardened signature, and identifier
   `com.jawndiego.trading-desk.keychain-role-probe-runner.v1` before and after
   copying it to the target.

## Attended probe

Prerequisites are the immutable installed readers, their exact role ownership
and execute modes, and only the two probe records created by the reviewed
provisioner. Do not create any signer, recovery, approval or grant record yet.

1. At a directly attended root console, create exactly
   `/private/var/root/trading-desk-keychain-role-probe-v1` as root:wheel mode
   `0700`, with no extended ACL. Copy only the eligible artifact into that
   directory as `trading-keychain-role-probe-runner-v1`, root:wheel mode
   `0500`, one link. No other directory entry is permitted.
2. Re-verify every ancestor, runner and reader ownership/mode/ACL invariant,
   both reader hashes and identifiers, and the runner hash and identifier.
   Confirm file descriptors 0, 1 and 2 are the same foreground terminal and
   no descriptor above 2 is open.
3. From that root console, use `/usr/bin/env -i` to invoke the exact runner
   path with no arguments. Do not use `sudo` as the runner invocation, a shell
   pipeline, redirection, `tee`, terminal recording or any wrapper that can
   capture child output. The runner itself contains the only permitted capture.
4. Require all ten expectation rows and `overall=PASS`. A missing row,
   `preflight=FAIL`, any cell `FAIL`, timeout, signal, prompt, Keychain UI,
   terminal output other than the fixed matrix, or nonzero runner status is a
   terminal qualification failure. Do not retry in the same session and do not
   provision production records.
5. Reboot. Re-verify the full sealed-path, reader, artifact and probe-record
   metadata, then run the one-shot matrix once more from a fresh attended root
   console. Both independently retained redacted receipts must pass.
6. After the post-reboot pass, remove the runner from its canonical executable
   path and remove the empty ephemeral probe directory, or move the whole
   directory to offline non-executable quarantine. Prove the canonical path is
   absent. Never leave a long-lived root probe launcher.

Retain only the source commit, public hashes/identifiers, public ownership and
ACL evidence, the redacted matrix, exit status and reboot boundary. Never
retain terminal capture, pipe bytes, Keychain password output, process memory,
or a core file. Production credential work remains a separate attended gate.
