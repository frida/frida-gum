#!/bin/sh

arch=arm

remote_prefix=/data/local/tmp/frida-tests-$arch

gum_tests=$(dirname "$0")
. $gum_tests/android_devices.rc 
. $gum_tests/configure_os.rc 
cd "$gum_tests/../../build/tmp-android-$arch/frida-gum" || exit 1
. ../../frida-meson-env-$os-x86_64.rc
ninja || exit 1
cd tests
adb -s $device shell "mkdir $remote_prefix"
adb -s $device push gum-tests data $remote_prefix || exit 1
adb -s $device shell "$remote_prefix/gum-tests $@"
