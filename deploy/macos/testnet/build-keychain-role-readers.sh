#!/bin/sh
set -eu
umask 077

SOURCE=$(/usr/bin/dirname "$0")/keychain-role-reader.c
EXECUTOR_NAME=trading-keychain-reader-executor-v1
CONTROL_NAME=trading-keychain-reader-control-v1
CLANG=/Library/Developer/CommandLineTools/usr/bin/clang
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
CODESIGN=/usr/bin/codesign
CREATED_OUTPUT=0
COMMITTED=0
OUTPUT=

cleanup() {
  if [ "$CREATED_OUTPUT" = 1 ] && [ "$COMMITTED" = 0 ] && [ -n "$OUTPUT" ]; then
    /bin/rm -f \
      "$OUTPUT/.$EXECUTOR_NAME.unsigned" "$OUTPUT/$EXECUTOR_NAME" \
      "$OUTPUT/.$CONTROL_NAME.unsigned" "$OUTPUT/$CONTROL_NAME" \
      "$OUTPUT/SHA256SUMS"
    /bin/rmdir "$OUTPUT" 2>/dev/null || \
      /bin/echo "ERROR: build output contains an unknown path and was preserved: $OUTPUT" >&2
    CREATED_OUTPUT=0
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
  /bin/echo 'Builds two role-compiled, ad-hoc signed hardened Mach-O helpers into one new absolute output directory.'
  /bin/echo 'Executor helper admits only UID/GID 451 signer+recovery; control admits only UID/GID 452 approval+grant.'
  /bin/echo 'The build never provisions, reads, lists, updates, or deletes a Keychain item.'
}

build() {
  output=$1
  OUTPUT=$output
  case "$output" in /*) ;; *) die 'output directory must be absolute' ;; esac
  [ "$(/usr/bin/uname -s)" = Darwin ] || die 'helper build requires macOS'
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || die 'helper source is unavailable'
  [ ! -e "$output" ] && [ ! -L "$output" ] || die 'output path already exists'
  for tool in "$CLANG" "$CODESIGN"; do
    [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] || die "build tool unavailable: $tool"
    [ "$(/usr/bin/stat -f %u "$tool")" = 0 ] || die "build tool is not root-owned: $tool"
    [ "$(/usr/bin/stat -f %l "$tool")" = 1 ] || die "hard-linked build tool rejected: $tool"
    writable=$(/usr/bin/find "$tool" -maxdepth 0 -perm +022 -print -quit)
    [ -z "$writable" ] || die "writable build tool rejected: $tool"
  done
  [ -d "$SDK" ] && [ ! -L "$SDK" ] || die 'reviewed macOS 26.5 SDK unavailable'
  [ "$(/usr/bin/stat -f %u "$SDK")" = 0 ] || die 'SDK is not root-owned'
  [ "$(/usr/bin/plutil -extract Version raw -o - "$SDK/SDKSettings.json")" = 26.5 ] || die 'SDK version differs from reviewed 26.5'
  /bin/mkdir -m 0700 "$output"
  CREATED_OUTPUT=1

  for role in executor control; do
    case "$role" in
      executor)
        macro=TRADING_HELPER_EXECUTOR
        name=$EXECUTOR_NAME
        identifier=com.jawndiego.trading-desk.keychain-reader.executor.v1
        ;;
      control)
        macro=TRADING_HELPER_CONTROL
        name=$CONTROL_NAME
        identifier=com.jawndiego.trading-desk.keychain-reader.control.v1
        ;;
    esac
    temporary=$output/.$name.unsigned
    final=$output/$name
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR="$output" \
      "$CLANG" -isysroot "$SDK" -std=c17 -Os -Wall -Wextra -Werror \
      -Wno-deprecated-declarations \
      -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wl,-pie -Wl,-dead_strip \
      -D"$macro"=1 "$SOURCE" -framework Security -framework CoreFoundation \
      -o "$temporary"
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$CODESIGN" --force --sign - --timestamp=none --options runtime \
      --identifier "$identifier" "$temporary"
    /bin/mv "$temporary" "$final"
    /bin/chmod 0500 "$final"
    /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$CODESIGN" --verify --strict --verbose=2 "$final"
  done
  (
    cd "$output"
    /usr/bin/shasum -a 256 "$EXECUTOR_NAME" "$CONTROL_NAME"
  ) > "$output/SHA256SUMS"
  /bin/chmod 0400 "$output/SHA256SUMS"
  COMMITTED=1
  /bin/echo "BUILD_COMPLETE output=$output"
  /bin/echo 'Artifacts are development candidates only until externally sealed, hash-pinned, and installed root-owned mode 0510.'
}

case "${1-plan}" in
  plan)
    [ "$#" -le 1 ] || die 'plan takes no arguments'
    plan
    ;;
  --build)
    [ "$#" -eq 2 ] || die '--build requires one absolute new output directory'
    build "$2"
    ;;
  *) die 'unknown mode; run without arguments for the plan' ;;
esac
