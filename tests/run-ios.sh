#!/bin/sh

arch=arm64

remote_host=iphone
remote_prefix=/var/root/frida-tests-$arch

gum_tests=$(dirname "$0")
cd "$gum_tests/../../build/tmp-ios-$arch/frida-gum" || exit 1
. ../../frida-meson-env-macos-x86_64.rc
ninja || exit 1
cd tests
rsync -rLz gum-tests data "$remote_host:$remote_prefix/" || exit 1
ssh "$remote_host" "$remote_prefix/gum-tests" "$@"
