#!/bin/sh
set -eu
umask 077

SOURCE=$(/usr/bin/dirname "$0")/keychain-role-probe-runner.c
NAME=trading-keychain-role-probe-runner-v1
IDENTIFIER=com.jawndiego.trading-desk.keychain-role-probe-runner.v1
CLANG=/Library/Developer/CommandLineTools/usr/bin/clang
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
SDK_SETTINGS=$SDK/SDKSettings.json
CODESIGN=/usr/bin/codesign
NM=/Library/Developer/CommandLineTools/usr/bin/llvm-nm
EXPECTED_CLANG_VERSION='Apple clang version 21.0.0 (clang-2100.1.1.101)'
EXPECTED_CLANG_SHA256=f30550eab15fdf5ab8c0dc54c52679711241e5d4b636b027e18c09fef531775d
EXPECTED_SDK_SETTINGS_SHA256=f8d005f09381389167f9e0aeaa169bc9e7dff162ef22ca2fd8e98df7ff1acafe
EXPECTED_SOURCE_SHA256=4bdaf5ebda40e62fc379d47c95f5477075e2a58f01e2b1f215f6f13c56c682ca
EXPECTED_ARTIFACT_SHA256=96b3c941dba152402728d825c19a9d586d852b718f4ff06a06bd37b4335658f9
OUTPUT=
CREATED_OUTPUT=0
COMMITTED=0

cleanup() {
  if [ "$CREATED_OUTPUT" = 1 ] && [ "$COMMITTED" = 0 ] && [ -n "$OUTPUT" ]; then
    CREATED_OUTPUT=0
    /bin/rm -f \
      "$OUTPUT/.build-a/.unsigned" "$OUTPUT/.build-b/.unsigned" \
      "$OUTPUT/.build-a/$NAME" "$OUTPUT/.build-b/$NAME" \
      "$OUTPUT/$NAME" "$OUTPUT/SHA256SUMS"
    /bin/rmdir "$OUTPUT/.build-a" "$OUTPUT/.build-b" 2>/dev/null || true
    /bin/rmdir "$OUTPUT" 2>/dev/null || \
      /bin/echo "ERROR: build output contains an unknown path and was preserved: $OUTPUT" >&2
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 1' HUP INT TERM

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no runner, reader, Keychain, credential, identity, service, or system path changed'
  /bin/echo 'Builds and statically analyzes one no-argument sacrificial role-probe runner; the candidate is never executed.'
  /bin/echo '--build-development creates explicitly untrusted user-owned test output.'
  /bin/echo '--build-release requires a canonical root-owned sealed builder/source tree and sealed output parent.'
  /bin/echo "expected_source_sha256=$EXPECTED_SOURCE_SHA256"
  /bin/echo "expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256"
  /bin/echo "direct_clt=$EXPECTED_CLANG_VERSION; clang_sha256=$EXPECTED_CLANG_SHA256; sdk=26.5"
  /bin/echo 'Release output is eligible only for a separately attended external seal/install/probe/removal procedure.'
}

digest() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

assert_no_acl() {
  entries=$(/bin/ls -led "$1" | /usr/bin/sed -n '/^[[:space:]]*[0-9][0-9]*:/p')
  [ -z "$entries" ] || die "named ACL rejected: $1"
}

assert_sealed_path_chain() {
  cursor=$1
  while :; do
    [ -d "$cursor" ] && [ ! -L "$cursor" ] || die "sealed directory unavailable: $cursor"
    [ "$(/usr/bin/stat -f %u "$cursor")" = 0 ] || die "sealed directory is not root-owned: $cursor"
    writable=$(/usr/bin/find "$cursor" -maxdepth 0 -perm +022 -print -quit)
    [ -z "$writable" ] || die "sealed directory is group/world writable: $cursor"
    assert_no_acl "$cursor"
    [ "$cursor" = / ] && break
    cursor=$(/usr/bin/dirname "$cursor")
  done
}

assert_root_owned_tool() {
  tool=$1
  [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] || die "build tool unavailable: $tool"
  [ "$(/usr/bin/stat -f %u "$tool")" = 0 ] || die "build tool is not root-owned: $tool"
  [ "$(/usr/bin/stat -f %l "$tool")" = 1 ] || die "hard-linked build tool rejected: $tool"
  writable=$(/usr/bin/find "$tool" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "writable build tool rejected: $tool"
}

assert_sealed_release_inputs() {
  output=$1
  case "$0" in /*) ;; *) die 'release builder path must be absolute' ;; esac
  [ ! -L "$0" ] && [ "$(/bin/realpath "$0")" = "$0" ] || \
    die 'release builder must be canonical and non-symlinked'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] && [ "$(/bin/realpath "$SOURCE")" = "$SOURCE" ] || \
    die 'release source must be canonical and non-symlinked'
  [ "$(digest "$SOURCE")" = "$EXPECTED_SOURCE_SHA256" ] || die 'release source digest mismatch'
  [ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || \
    die 'release build requires real and effective root'
  for sealed_file in "$0" "$SOURCE"; do
    [ "$(/usr/bin/stat -f %u "$sealed_file")" = 0 ] || die "sealed file is not root-owned: $sealed_file"
    [ "$(/usr/bin/stat -f %l "$sealed_file")" = 1 ] || die "sealed file link invariant: $sealed_file"
    writable=$(/usr/bin/find "$sealed_file" -maxdepth 0 -perm +022 -print -quit)
    [ -z "$writable" ] || die "sealed file is group/world writable: $sealed_file"
    assert_no_acl "$sealed_file"
  done
  assert_sealed_path_chain "$(/usr/bin/dirname "$0")"
  output_parent=$(/usr/bin/dirname "$output")
  [ "$(/bin/realpath "$output_parent")" = "$output_parent" ] || \
    die 'release output parent must be canonical'
  assert_sealed_path_chain "$output_parent"
}

assert_direct_toolchain() {
  assert_root_owned_tool "$CLANG"
  assert_root_owned_tool "$CODESIGN"
  assert_root_owned_tool "$NM"
  [ "$("$CLANG" --version | /usr/bin/sed -n '1p')" = "$EXPECTED_CLANG_VERSION" ] || \
    die 'compiler version differs from reviewed direct CLT'
  [ "$(digest "$CLANG")" = "$EXPECTED_CLANG_SHA256" ] || die 'direct CLT compiler digest mismatch'
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --verify --strict "$CLANG" || die 'direct CLT compiler signature invalid'
  [ -d "$SDK" ] && [ ! -L "$SDK" ] || die 'reviewed macOS 26.5 SDK unavailable'
  [ "$(/usr/bin/stat -f %u "$SDK")" = 0 ] || die 'SDK is not root-owned'
  [ "$(/usr/bin/plutil -extract Version raw -o - "$SDK_SETTINGS")" = 26.5 ] || \
    die 'SDK version differs from reviewed 26.5'
  [ "$(digest "$SDK_SETTINGS")" = "$EXPECTED_SDK_SETTINGS_SHA256" ] || \
    die 'SDK settings digest mismatch'
}

compile_one() {
  compile_target=$1
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    ZERO_AR_DATE=1 SOURCE_DATE_EPOCH=0 TMPDIR="$OUTPUT" \
    "$CLANG" -isysroot "$SDK" -std=c17 -Os -Wall -Wextra -Werror \
    -Wno-deprecated-declarations -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fPIE -Wl,-pie -Wl,-dead_strip "$SOURCE" \
    -framework Security -framework CoreFoundation -o "$compile_target"
}

sign_one() {
  sign_unsigned=$1
  sign_signed=$2
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --force --sign - --timestamp=none --options runtime \
    --identifier "$IDENTIFIER" "$sign_unsigned"
  /bin/mv "$sign_unsigned" "$sign_signed"
}

assert_static_surface() {
  artifact=$1
  symbols=$OUTPUT/.symbols
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$NM" -u "$artifact" > "$symbols"
  for required in _alarm _execve _fork _kill _mlock _pipe _poll _setgid _setgroups _setuid _waitpid; do
    /usr/bin/grep -Fqx "$required" "$symbols" || die "required native primitive absent: $required"
  done
  if /usr/bin/grep -Eq '_Sec(Keychain|Item)' "$symbols"; then
    die 'Keychain/item API symbol present in probe runner'
  fi
  if /usr/bin/grep -Eq '_(execl|execle|execlp|execv|execvp|popen|posix_spawn|system)$' "$symbols"; then
    die 'external subprocess-helper symbol present in probe runner'
  fi
  /bin/rm -f "$symbols"
}

build() {
  mode=$1
  build_output=$2
  OUTPUT=$build_output
  case "$build_output" in /*) ;; *) die 'output directory must be absolute' ;; esac
  [ "$(/usr/bin/uname -s)" = Darwin ] || die 'probe-runner build requires macOS'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || die 'probe-runner source unavailable'
  [ ! -e "$build_output" ] && [ ! -L "$build_output" ] || die 'output path already exists'
  assert_direct_toolchain
  [ "$mode" = development ] || assert_sealed_release_inputs "$build_output"

  /bin/mkdir -m 0700 "$build_output"
  CREATED_OUTPUT=1
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR="$build_output" \
    "$CLANG" --analyze -isysroot "$SDK" -std=c17 -Wall -Wextra -Werror \
    -Wno-deprecated-declarations -Xanalyzer -analyzer-output=text "$SOURCE"

  /bin/mkdir -m 0700 "$build_output/.build-a" "$build_output/.build-b"
  unsigned_a=$build_output/.build-a/.unsigned
  unsigned_b=$build_output/.build-b/.unsigned
  signed_a=$build_output/.build-a/$NAME
  signed_b=$build_output/.build-b/$NAME
  final=$build_output/$NAME
  compile_one "$unsigned_a"
  compile_one "$unsigned_b"
  sign_one "$unsigned_a" "$signed_a"
  sign_one "$unsigned_b" "$signed_b"
  /usr/bin/cmp -s "$signed_a" "$signed_b" || die 'independent builds are not byte-for-byte deterministic'
  /bin/mv "$signed_a" "$final"
  /bin/rm -f "$signed_b"
  /bin/rmdir "$build_output/.build-a" "$build_output/.build-b"
  /bin/chmod 0500 "$final"
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --verify --strict --verbose=2 "$final"
  details=$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" -d --verbose=4 "$final" 2>&1)
  /bin/echo "$details" | /usr/bin/grep -Fqx "Identifier=$IDENTIFIER" || \
    die 'probe-runner signing identifier mismatch'
  /bin/echo "$details" | /usr/bin/grep -F 'flags=0x10002(adhoc,runtime)' >/dev/null || \
    die 'probe-runner hardened-runtime signature missing'
  assert_static_surface "$final"

  actual_artifact=$(digest "$final")
  if [ "$mode" = release ]; then
    [ "$(digest "$SOURCE")" = "$EXPECTED_SOURCE_SHA256" ] || die 'release source changed during build'
    [ "$actual_artifact" = "$EXPECTED_ARTIFACT_SHA256" ] || \
      die 'release artifact digest differs from authoritative pin'
  fi
  (cd "$build_output" && /usr/bin/shasum -a 256 "$NAME") > "$build_output/SHA256SUMS"
  /bin/chmod 0400 "$build_output/SHA256SUMS"
  COMMITTED=1
  /bin/echo "BUILD_COMPLETE mode=$mode output=$build_output"
  if [ "$mode" = release ]; then
    /bin/echo "RELEASE_CANDIDATE sha256=$EXPECTED_ARTIFACT_SHA256"
  else
    /bin/echo "UNTRUSTED_DEVELOPMENT_ARTIFACT sha256=$actual_artifact never install or execute this output"
  fi
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die 'plan takes no arguments'
    plan
    ;;
  --build-development)
    [ "$#" -eq 2 ] || die '--build-development requires one absolute new output directory'
    build development "$2"
    ;;
  --build-release)
    [ "$#" -eq 2 ] || die '--build-release requires one absolute new output directory'
    build release "$2"
    ;;
  *) die 'unknown mode; run without arguments for the plan' ;;
esac
