#!/bin/sh

arch=x86_64

gum_tests=$(dirname "$0")
cd "$gum_tests/../../build/tmp-macos-$arch/frida-gum" || exit 1
. ../../frida-env-macos-x86_64.rc
ninja || exit 1
tests/gum-tests "$@"
