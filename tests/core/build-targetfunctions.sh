#!/bin/sh

src=$(dirname $0)
arch=$1

if [ -z "$arch" ]; then
  echo "usage: $0 <arch>"
  exit 1
fi

if [ -z "$FRIDA_ROOT" ] ; then
  echo "Must set FRIDA_ROOT env var first"
  exit 1
fi

if [ -z "$CONFIG_SITE" ]; then
  echo "This script must be run from within a Frida build environment." > /dev/stderr
  exit 1
fi

tmp1="$(mktemp /tmp/build-targetfunctions.XXXXXX)"
tmp2="$(mktemp /tmp/build-targetfunctions.XXXXXX)"

if [ "$(uname -s)" = "Darwin" ]; then
  shlib_suffix=dylib
  extra_ldflags="-Wl,-undefined,error -Wl,-dead_strip"
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
  targetfuncs_ldflags="-Wl,--version-script=$tmp1 -Wl,-soname,targetfunctions-$arch.$shlib_suffix"

  cat >"$tmp2" << EOF
GUM_TEST_SPECIALFUNCTIONS_1.0 {
  global:
    gum_test_special_function;

  local:
    *;
};
EOF
  specialfuncs_ldflags="-Wl,--version-script=$tmp2 -Wl,-soname,specialfunctions-$arch.$shlib_suffix"
fi

common_cflags="$CFLAGS -Wall -pipe -gdwarf-2 -g3 -I../../gum $($PKG_CONFIG --cflags glib-2.0)"
common_ldflags="$LDFLAGS -shared $extra_ldflags $($PKG_CONFIG --libs glib-2.0)"

$CC $common_cflags -O0 -c targetfunctions.c || exit 1
$CC \
      $common_ldflags \
      $targetfuncs_ldflags \
      -o $src/../data/targetfunctions-$arch.$shlib_suffix \
      targetfunctions.o \
      "$glib_library" || exit 1
rm targetfunctions.o
strip $strip_options $src/../data/targetfunctions-$arch.$shlib_suffix || exit 1

$CC $common_cflags -O2 -c specialfunctions.c || exit 1
$CC \
      $common_ldflags \
      $specialfuncs_ldflags \
      -o $src/../data/specialfunctions-$arch.$shlib_suffix \
      specialfunctions.o \
      "$glib_library" || exit 1
rm specialfunctions.o
strip $strip_options $src/../data/specialfunctions-$arch.$shlib_suffix || exit 1

rm "$tmp1" "$tmp2"
