#!/bin/sh

arch=arm64

remote_host=iphone
remote_prefix=/usr/local/opt/frida-tests-$arch

gum_tests=$(dirname "$0")
cd "$gum_tests/../../build/tmp_thin-ios-$arch/frida-gum" || exit 1
. ../../frida_thin-meson-env-macos-x86_64.rc
ninja || exit 1
cd tests
ssh "$remote_host" "mkdir -p '$remote_prefix'"
rsync -rLz gum-tests data "$remote_host:$remote_prefix/" || exit 1
ssh "$remote_host" "$remote_prefix/gum-tests" "$@"
