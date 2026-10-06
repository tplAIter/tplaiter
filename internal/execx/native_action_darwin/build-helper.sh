#!/bin/sh
set -eu
# Candidate only; never installation or signing.
clang=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
sdk=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
"$clang" -target arm64-apple-macos26.0 -isysroot "$sdk" --ld-path=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld -Os -Wall -Wextra -Werror "$(dirname "$0")/bootstrap.c" -o "$(dirname "$0")/helper-arm64.bin"
