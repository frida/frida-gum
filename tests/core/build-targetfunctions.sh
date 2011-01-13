#!/bin/sh

arch=$1

if [ -z "$arch" ]; then
  echo "usage: $0 <arch>"
  exit 1
fi

tmp1="$(mktemp /tmp/build-targetfunctions.XXXXXX)"
tmp2="$(mktemp /tmp/build-targetfunctions.XXXXXX)"

if [ "$(uname -s)" = "Darwin" ]; then
  shlib_suffix=dylib
  glib_prefix=$FRIDA_SDKROOT
  glib_library="$glib_prefix/lib/libglib-2.0.a"
  extra_ldflags="-Wl,-undefined,error -Wl,-framework,CoreFoundation -Wl,-framework,CoreServices -liconv"
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
  glib_prefix=/usr
  glib_library="$FRIDA_PREFIX/lib/libglib-2.0.a"
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

common_cflags="-fdata-sections -ffunction-sections -fPIC -std=gnu99 -DHAVE_CONFIG_H -I. -I../.. -include config.h -I ../../gum -I ../../libs -I ../../tests -I ../../gum/arch-x86 -I ../../ext/udis86 -pthread -I$glib_prefix/include/glib-2.0 -I$glib_prefix/lib/glib-2.0/include -Wall -pipe -gdwarf-2 -g3"
common_ldflags="-shared $extra_ldflags"

gcc $common_cflags -O0 -c targetfunctions.c || exit 1
gcc \
      $common_ldflags \
      $targetfuncs_ldflags \
      -o targetfunctions-$arch.$shlib_suffix \
      targetfunctions.o \
      "$glib_library" || exit 1
rm targetfunctions.o
strip $strip_options targetfunctions-$arch.$shlib_suffix || exit 1

gcc $common_cflags -O2 -c specialfunctions.c || exit 1
gcc \
      $common_ldflags \
      $specialfuncs_ldflags \
      -o specialfunctions-$arch.$shlib_suffix \
      specialfunctions.o \
      "$glib_library" || exit 1
rm specialfunctions.o
strip $strip_options specialfunctions-$arch.$shlib_suffix || exit 1

rm "$tmp1" "$tmp2"
