#!/bin/sh

set -x

src=$(dirname $0)
os=$1
arch=$2

if [ -z "$os" -o -z "$arch" ]; then
  echo "usage: $0 <os> <arch>"
  exit 1
fi

if [ -z "$VALAC" ]; then
  echo "This script must be run from within a Frida build environment." > /dev/stderr
  exit 1
fi

tmp1="$(mktemp /tmp/build-targetfunctions.XXXXXX)"
tmp2="$(mktemp /tmp/build-targetfunctions.XXXXXX)"

if [ "$os" = "macos" -o "$os" = "ios" ]; then
  shlib_suffix=dylib
  extra_ldflags="-Wl,-undefined,error -Wl,-dead_strip"
  strip_command=strip
  strip_options=-Sx

  cat >"$tmp1" << EOF
_gum_test_target_function
_gum_test_target_nop_function_a
_gum_test_target_nop_function_b
_gum_test_target_nop_function_c
EOF
  targetfuncs_ldflags="-Wl,-exported_symbols_list,$tmp1"

  cat >"$tmp2" << EOF
_gum_test_special_function
EOF
  specialfuncs_ldflags="-Wl,-exported_symbols_list,$tmp2"
else
  shlib_suffix=so
  extra_ldflags="-Wl,--gc-sections -Wl,-no-undefined"
  strip_command=$STRIP
  strip_options=--strip-all

  cat >"$tmp1" << EOF
GUM_TEST_TARGETFUNCTIONS_1.0 {
  global:
    gum_test_target_function;
    gum_test_target_nop_function_a;
    gum_test_target_nop_function_b;
    gum_test_target_nop_function_c;

  local:
    *;
};
EOF
  targetfuncs_ldflags="-Wl,--version-script=$tmp1 -Wl,-soname,targetfunctions-$os-$arch.$shlib_suffix"

  cat >"$tmp2" << EOF
GUM_TEST_SPECIALFUNCTIONS_1.0 {
  global:
    gum_test_special_function;

  local:
    *;
};
EOF
  specialfuncs_ldflags="-Wl,--version-script=$tmp2 -Wl,-soname,specialfunctions-$os-$arch.$shlib_suffix"
fi

common_cflags="$CFLAGS -Wall -pipe -gdwarf-2 -g3 -I../../gum $($PKG_CONFIG --cflags glib-2.0)"
common_ldflags="$LDFLAGS -shared $extra_ldflags $($PKG_CONFIG --libs glib-2.0)"

$CC $common_cflags -O0 -c targetfunctions.c || exit 1
$CC \
      targetfunctions.o \
      -o $src/../data/targetfunctions-$os-$arch.$shlib_suffix \
      $common_ldflags \
      $targetfuncs_ldflags || exit 1

rm targetfunctions.o
$strip_command $strip_options $src/../data/targetfunctions-$os-$arch.$shlib_suffix || exit 1

$CC $common_cflags -O2 -c specialfunctions.c || exit 1
$CC \
      specialfunctions.o \
      -o $src/../data/specialfunctions-$os-$arch.$shlib_suffix \
      $common_ldflags \
      $specialfuncs_ldflags || exit 1
rm specialfunctions.o
$strip_command $strip_options $src/../data/specialfunctions-$os-$arch.$shlib_suffix || exit 1

rm "$tmp1" "$tmp2"
