#!/bin/sh
set -eu
umask 077

SOURCE=$(/usr/bin/dirname "$0")/keychain-provisioner.c
NAME=trading-keychain-provisioner-v1
IDENTIFIER=com.jawndiego.trading-desk.keychain-provisioner.v1
CLANG=/Library/Developer/CommandLineTools/usr/bin/clang
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
CODESIGN=/usr/bin/codesign
EXPECTED_SOURCE_SHA256=7c874a6ac231ab72012337550b17359ed75d875cf500e91c21c0758986b51d26
EXPECTED_ARTIFACT_SHA256=8ecaad4c2fb3f2e9d84b4e535177fa41a9a84310e4495588575082de40cd28de
EXPECTED_CLANG_VERSION='Apple clang version 21.0.0 (clang-2100.1.1.101)'
OUTPUT=
CREATED_OUTPUT=0
COMMITTED=0

cleanup() {
  if [ "$CREATED_OUTPUT" = 1 ] && [ "$COMMITTED" = 0 ] && [ -n "$OUTPUT" ]; then
    CREATED_OUTPUT=0
    /bin/rm -f "$OUTPUT/.$NAME.unsigned" "$OUTPUT/$NAME" "$OUTPUT/SHA256SUMS"
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
  /bin/echo 'PLAN_ONLY no executable, Keychain, credential, reader, service, or system path changed'
  /bin/echo 'Release mode accepts only an absolute canonical root-owned sealed script/source tree and a new output under a sealed root-owned parent.'
  /bin/echo "expected_source_sha256=$EXPECTED_SOURCE_SHA256"
  /bin/echo "expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256"
  /bin/echo "toolchain=$EXPECTED_CLANG_VERSION; sdk=26.5; artifact hash is authoritative"
  /bin/echo 'The candidate can run only as real/effective root from its exact sealed ephemeral canonical path.'
  /bin/echo 'It accepts one of six fixed TESTNET production/probe slot names and one fixed System Keychain; it has no read/update/delete/export/list operation.'
  /bin/echo '--build-development is explicitly untrusted and exists only for user-owned compile/unit tests.'
  /bin/echo 'Building never executes the candidate; only --build-release can produce an artifact eligible for sealing.'
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

assert_sealed_release_inputs() {
  output=$1
  case "$0" in /*) ;; *) die 'release builder path must be absolute' ;; esac
  [ ! -L "$0" ] && [ "$(/bin/realpath "$0")" = "$0" ] || die 'release builder must be canonical and non-symlinked'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] && [ "$(/bin/realpath "$SOURCE")" = "$SOURCE" ] || die 'release source must be canonical and non-symlinked'
  [ "$(digest "$SOURCE")" = "$EXPECTED_SOURCE_SHA256" ] || die 'release source digest mismatch'
  [ "$(/usr/bin/id -u)" = 0 ] || die 'release build requires real root'
  [ -f "$0" ] && [ "$(/usr/bin/stat -f %u "$0")" = 0 ] && [ "$(/usr/bin/stat -f %l "$0")" = 1 ] || die 'release builder ownership/link invariant'
  [ "$(/usr/bin/stat -f %u "$SOURCE")" = 0 ] && [ "$(/usr/bin/stat -f %l "$SOURCE")" = 1 ] || die 'release source ownership/link invariant'
  for sealed_file in "$0" "$SOURCE"; do
    writable=$(/usr/bin/find "$sealed_file" -maxdepth 0 -perm +022 -print -quit)
    [ -z "$writable" ] || die "sealed file is group/world writable: $sealed_file"
    assert_no_acl "$sealed_file"
  done
  assert_sealed_path_chain "$(/usr/bin/dirname "$0")"
  output_parent=$(/usr/bin/dirname "$output")
  [ "$(/bin/realpath "$output_parent")" = "$output_parent" ] || die 'release output parent must be canonical'
  assert_sealed_path_chain "$output_parent"
}

assert_root_owned_tool() {
  tool=$1
  [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] || die "build tool unavailable: $tool"
  [ "$(/usr/bin/stat -f %u "$tool")" = 0 ] || die "build tool is not root-owned: $tool"
  [ "$(/usr/bin/stat -f %l "$tool")" = 1 ] || die "hard-linked build tool rejected: $tool"
  writable=$(/usr/bin/find "$tool" -maxdepth 0 -perm +022 -print -quit)
  [ -z "$writable" ] || die "writable build tool rejected: $tool"
}

build() {
  mode=$1
  output=$2
  OUTPUT=$output
  case "$output" in /*) ;; *) die 'output directory must be absolute' ;; esac
  [ "$(/usr/bin/uname -s)" = Darwin ] || die 'provisioner build requires macOS'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || die 'provisioner source is unavailable'
  [ ! -e "$output" ] && [ ! -L "$output" ] || die 'output path already exists'
  assert_root_owned_tool "$CLANG"
  assert_root_owned_tool "$CODESIGN"
  [ "$("$CLANG" --version | /usr/bin/sed -n '1p')" = "$EXPECTED_CLANG_VERSION" ] || die 'compiler version differs from reviewed toolchain'
  [ -d "$SDK" ] && [ ! -L "$SDK" ] || die 'reviewed macOS 26.5 SDK unavailable'
  [ "$(/usr/bin/stat -f %u "$SDK")" = 0 ] || die 'SDK is not root-owned'
  [ "$(/usr/bin/plutil -extract Version raw -o - "$SDK/SDKSettings.json")" = 26.5 ] || \
    die 'SDK version differs from reviewed 26.5'
  [ "$mode" = development ] || assert_sealed_release_inputs "$output"

  /bin/mkdir -m 0700 "$output"
  CREATED_OUTPUT=1
  temporary=$output/.$NAME.unsigned
  final=$output/$NAME
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR="$output" \
    "$CLANG" -isysroot "$SDK" -std=c17 -Os -Wall -Wextra -Werror \
    -Wno-deprecated-declarations -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fPIE -Wl,-pie -Wl,-dead_strip "$SOURCE" \
    -framework Security -framework CoreFoundation -o "$temporary"
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --force --sign - --timestamp=none --options runtime \
    --identifier "$IDENTIFIER" "$temporary"
  /bin/mv "$temporary" "$final"
  /bin/chmod 0500 "$final"
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --verify --strict --verbose=2 "$final"
  if [ "$mode" = release ]; then
    [ "$(digest "$final")" = "$EXPECTED_ARTIFACT_SHA256" ] || die 'release artifact digest differs from authoritative pin'
  fi
  (cd "$output" && /usr/bin/shasum -a 256 "$NAME") > "$output/SHA256SUMS"
  /bin/chmod 0400 "$output/SHA256SUMS"
  COMMITTED=1
  /bin/echo "BUILD_COMPLETE mode=$mode output=$output"
  if [ "$mode" = release ]; then
    /bin/echo "RELEASE_CANDIDATE sha256=$EXPECTED_ARTIFACT_SHA256"
  else
    /bin/echo 'UNTRUSTED_DEVELOPMENT_ARTIFACT never provision with this output'
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
