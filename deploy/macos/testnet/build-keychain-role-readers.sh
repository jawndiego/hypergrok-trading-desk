#!/bin/sh
set -eu
umask 077

SOURCE=$(/usr/bin/dirname "$0")/keychain-role-reader.c
EXECUTOR_NAME=trading-keychain-reader-executor-v1
CONTROL_NAME=trading-keychain-reader-control-v1
CLANG=/Library/Developer/CommandLineTools/usr/bin/clang
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
SDK_SETTINGS=$SDK/SDKSettings.json
CODESIGN=/usr/bin/codesign
NM=/Library/Developer/CommandLineTools/usr/bin/llvm-nm
OTOOL=/Library/Developer/CommandLineTools/usr/bin/llvm-otool
EXPECTED_CLANG_VERSION='Apple clang version 21.0.0 (clang-2100.1.1.101)'
EXPECTED_CLANG_SHA256=f30550eab15fdf5ab8c0dc54c52679711241e5d4b636b027e18c09fef531775d
EXPECTED_SDK_SETTINGS_SHA256=f8d005f09381389167f9e0aeaa169bc9e7dff162ef22ca2fd8e98df7ff1acafe
EXPECTED_SOURCE_SHA256=4727f666c4c107fedda46a20ec536e479a72714d49adaebff25ec5d3d60494d5
EXPECTED_EXECUTOR_ARTIFACT_SHA256=8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7
EXPECTED_CONTROL_ARTIFACT_SHA256=2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9
CREATED_OUTPUT=0
COMMITTED=0
OUTPUT=

cleanup() {
  if [ "$CREATED_OUTPUT" = 1 ] && [ "$COMMITTED" = 0 ] && [ -n "$OUTPUT" ]; then
    CREATED_OUTPUT=0
    /bin/rm -f \
      "$OUTPUT/.build-a/.$EXECUTOR_NAME.unsigned" \
      "$OUTPUT/.build-a/$EXECUTOR_NAME" \
      "$OUTPUT/.build-a/.$CONTROL_NAME.unsigned" \
      "$OUTPUT/.build-a/$CONTROL_NAME" \
      "$OUTPUT/.build-b/.$EXECUTOR_NAME.unsigned" \
      "$OUTPUT/.build-b/$EXECUTOR_NAME" \
      "$OUTPUT/.build-b/.$CONTROL_NAME.unsigned" \
      "$OUTPUT/.build-b/$CONTROL_NAME" \
      "$OUTPUT/$EXECUTOR_NAME" "$OUTPUT/$CONTROL_NAME" \
      "$OUTPUT/.symbols-executor" "$OUTPUT/.symbols-control" \
      "$OUTPUT/.loads-executor" "$OUTPUT/.loads-control" \
      "$OUTPUT/.commands-executor" "$OUTPUT/.commands-control" \
      "$OUTPUT/.header-executor" "$OUTPUT/.header-control" \
      "$OUTPUT/SHA256SUMS"
    /bin/rmdir "$OUTPUT/.build-a" "$OUTPUT/.build-b" 2>/dev/null || true
    /bin/rmdir "$OUTPUT" 2>/dev/null || \
      /bin/echo "ERROR: build output contains an unknown path and was preserved: $OUTPUT" >&2
    OUTPUT=
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 1' HUP INT TERM

die() {
  /bin/echo "ERROR: $*" >&2
  exit 1
}

plan() {
  /bin/echo 'PLAN_ONLY no helper, Keychain, credential, service, or system path changed'
  /bin/echo 'Builds and statically analyzes two role-compiled, ad-hoc signed hardened Mach-O helpers; no candidate is executed.'
  /bin/echo '--build-development creates explicitly untrusted user-owned test output.'
  /bin/echo '--build-release requires a canonical root-owned sealed builder/source tree and sealed output parent.'
  /bin/echo "expected_source_sha256=$EXPECTED_SOURCE_SHA256"
  /bin/echo "expected_executor_artifact_sha256=$EXPECTED_EXECUTOR_ARTIFACT_SHA256"
  /bin/echo "expected_control_artifact_sha256=$EXPECTED_CONTROL_ARTIFACT_SHA256"
  /bin/echo "direct_clt=$EXPECTED_CLANG_VERSION; clang_sha256=$EXPECTED_CLANG_SHA256; sdk=26.5"
  /bin/echo 'Executor helper admits UID/GID 451 signer+recovery+probe-executor; control admits UID/GID 452 approval+grant+probe-control.'
  /bin/echo 'The build never provisions, reads, lists, updates, deletes, or executes against a Keychain item.'
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
  assert_root_owned_tool "$OTOOL"
  [ "$("$CLANG" --version | /usr/bin/sed -n '1p')" = "$EXPECTED_CLANG_VERSION" ] || \
    die 'compiler version differs from reviewed direct CLT'
  [ "$(digest "$CLANG")" = "$EXPECTED_CLANG_SHA256" ] || die 'direct CLT compiler digest mismatch'
  for signed_tool in "$CLANG" "$NM" "$OTOOL"; do
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$CODESIGN" --verify --strict "$signed_tool" || die "direct CLT tool signature invalid: $signed_tool"
  done
  [ -d "$SDK" ] && [ ! -L "$SDK" ] || die 'reviewed macOS 26.5 SDK unavailable'
  [ "$(/usr/bin/stat -f %u "$SDK")" = 0 ] || die 'SDK is not root-owned'
  [ -f "$SDK_SETTINGS" ] && [ ! -L "$SDK_SETTINGS" ] || die 'SDK settings unavailable'
  [ "$(/usr/bin/plutil -extract Version raw -o - "$SDK_SETTINGS")" = 26.5 ] || \
    die 'SDK version differs from reviewed 26.5'
  [ "$(digest "$SDK_SETTINGS")" = "$EXPECTED_SDK_SETTINGS_SHA256" ] || \
    die 'SDK settings digest mismatch'
}

compile_one() {
  macro=$1
  target=$2
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR="$OUTPUT" \
    "$CLANG" -isysroot "$SDK" -std=c17 -Os -Wall -Wextra -Werror \
    -Wno-deprecated-declarations \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wl,-pie -Wl,-dead_strip \
    -D"$macro"=1 "$SOURCE" -framework Security -framework CoreFoundation \
    -o "$target"
}

sign_one() {
  identifier=$1
  unsigned=$2
  signed=$3
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" --force --sign - --timestamp=none --options runtime \
    --identifier "$identifier" "$unsigned"
  /bin/mv "$unsigned" "$signed"
}

assert_static_surface() {
  role=$1
  artifact=$2
  expected_identifier=$3
  symbols=$OUTPUT/.symbols-$role
  loads=$OUTPUT/.loads-$role
  commands=$OUTPUT/.commands-$role
  header=$OUTPUT/.header-$role

  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$NM" -u "$artifact" > "$symbols"
  for required in \
    _SecKeychainFindGenericPassword _SecKeychainItemFreeContent \
    _SecKeychainOpen _SecKeychainSetUserInteractionAllowed \
    _getegid _geteuid _getgid _getgroups _getuid _write; do
    /usr/bin/grep -Fqx "$required" "$symbols" || die "required reader primitive absent: $required"
  done
  unexpected_security=$(/usr/bin/awk '
    /^_Sec/ &&
    $0 != "_SecKeychainFindGenericPassword" &&
    $0 != "_SecKeychainItemFreeContent" &&
    $0 != "_SecKeychainOpen" &&
    $0 != "_SecKeychainSetUserInteractionAllowed" {print; exit}
  ' "$symbols")
  [ -z "$unexpected_security" ] || die "unexpected Security API symbol in reader: $unexpected_security"
  if /usr/bin/grep -Eq \
    '_(connect|dlopen|dlsym|execl|execle|execlp|execv|execve|execvp|fork|fopen|open|popen|posix_spawn|posix_spawnp|send|sendmsg|sendto|socket|system)$' \
    "$symbols"; then
    die 'forbidden file, dynamic-loading, network, or subprocess symbol present in reader'
  fi

  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$OTOOL" -hv "$artifact" > "$header"
  /usr/bin/grep -Eq \
    '^MH_MAGIC_64[[:space:]]+ARM64[[:space:]]+ALL.*EXECUTE.*NOUNDEFS.*PIE' \
    "$header" || die 'reader is not a thin arm64 PIE executable'

  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$OTOOL" -L "$artifact" > "$loads"
  unexpected_load=$(/usr/bin/awk '
    NR > 1 && NF {
      path = $1
      if (path !~ "^/System/Library/" && path !~ "^/usr/lib/") {print path; exit}
    }
  ' "$loads")
  [ -z "$unexpected_load" ] || die "non-system reader load path: $unexpected_load"
  [ "$(/usr/bin/awk 'NR > 1 && NF {count += 1} END {print count + 0}' "$loads")" = 3 ] || \
    die 'reader dynamic library inventory differs'
  for required_load in \
    /System/Library/Frameworks/Security.framework/Versions/A/Security \
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation \
    /usr/lib/libSystem.B.dylib; do
    /usr/bin/awk -v expected="$required_load" 'NR > 1 && $1 == expected {found = 1} END {exit !found}' "$loads" || \
      die "required system load path absent: $required_load"
  done

  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$OTOOL" -l "$artifact" > "$commands"
  if /usr/bin/grep -Eq \
    'cmd LC_(DYLD_ENVIRONMENT|LAZY_LOAD_DYLIB|LOAD_UPWARD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|RPATH)' \
    "$commands"; then
    die 'forbidden reader load command present'
  fi

  details=$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    "$CODESIGN" -d --verbose=4 "$artifact" 2>&1)
  /bin/echo "$details" | /usr/bin/grep -Fqx "Identifier=$expected_identifier" || \
    die 'reader signing identifier mismatch'
  /bin/echo "$details" | /usr/bin/grep -F 'flags=0x10002(adhoc,runtime)' >/dev/null || \
    die 'reader hardened-runtime signature missing'

  /bin/rm -f "$symbols" "$loads" "$commands" "$header"
}

build() {
  mode=$1
  output=$2
  OUTPUT=$output
  case "$output" in /*) ;; *) die 'output directory must be absolute' ;; esac
  [ "$(/usr/bin/uname -s)" = Darwin ] || die 'helper build requires macOS'
  [ "$(/usr/bin/uname -m)" = arm64 ] || die 'helper build requires an arm64 host'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || die 'helper source is unavailable'
  [ ! -e "$output" ] && [ ! -L "$output" ] || die 'output path already exists'
  assert_direct_toolchain
  [ "$mode" = development ] || assert_sealed_release_inputs "$output"

  /bin/mkdir -m 0700 "$output"
  CREATED_OUTPUT=1
  /bin/mkdir -m 0700 "$output/.build-a" "$output/.build-b"
  for macro in TRADING_HELPER_EXECUTOR TRADING_HELPER_CONTROL; do
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR="$output" \
      "$CLANG" --analyze -isysroot "$SDK" -std=c17 -Wall -Wextra -Werror \
      -Wno-deprecated-declarations -Xanalyzer -analyzer-output=text \
      -D"$macro"=1 "$SOURCE"
  done

  for role in executor control; do
    case "$role" in
      executor)
        macro=TRADING_HELPER_EXECUTOR
        name=$EXECUTOR_NAME
        identifier=com.jawndiego.trading-desk.keychain-reader.executor.v1
        expected_artifact=$EXPECTED_EXECUTOR_ARTIFACT_SHA256
        ;;
      control)
        macro=TRADING_HELPER_CONTROL
        name=$CONTROL_NAME
        identifier=com.jawndiego.trading-desk.keychain-reader.control.v1
        expected_artifact=$EXPECTED_CONTROL_ARTIFACT_SHA256
        ;;
    esac
    unsigned_a=$output/.build-a/.$name.unsigned
    unsigned_b=$output/.build-b/.$name.unsigned
    signed_a=$output/.build-a/$name
    signed_b=$output/.build-b/$name
    final=$output/$name
    compile_one "$macro" "$unsigned_a"
    compile_one "$macro" "$unsigned_b"
    sign_one "$identifier" "$unsigned_a" "$signed_a"
    sign_one "$identifier" "$unsigned_b" "$signed_b"
    /usr/bin/cmp -s "$signed_a" "$signed_b" || \
      die "independent $role reader builds are not byte-for-byte deterministic"
    /bin/mv "$signed_a" "$final"
    /bin/rm -f "$signed_b"
    /bin/chmod 0500 "$final"
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$CODESIGN" --verify --strict --verbose=2 "$final"
    assert_static_surface "$role" "$final" "$identifier"
    actual_artifact=$(digest "$final")
    if [ "$mode" = release ]; then
      [ "$actual_artifact" = "$expected_artifact" ] || \
        die "$role release artifact digest differs from authoritative pin"
    fi
  done
  /bin/rmdir "$output/.build-a" "$output/.build-b"

  if [ "$mode" = release ]; then
    [ "$(digest "$SOURCE")" = "$EXPECTED_SOURCE_SHA256" ] || die 'release source changed during build'
  fi
  (
    cd "$output"
    /usr/bin/shasum -a 256 "$EXECUTOR_NAME" "$CONTROL_NAME"
  ) > "$output/SHA256SUMS"
  /bin/chmod 0400 "$output/SHA256SUMS"
  COMMITTED=1
  /bin/echo "BUILD_COMPLETE mode=$mode output=$output"
  if [ "$mode" = release ]; then
    /bin/echo "RELEASE_CANDIDATES executor_sha256=$EXPECTED_EXECUTOR_ARTIFACT_SHA256 control_sha256=$EXPECTED_CONTROL_ARTIFACT_SHA256"
  else
    /bin/echo 'UNTRUSTED_DEVELOPMENT_ARTIFACTS never install or grant Keychain access to this output'
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
