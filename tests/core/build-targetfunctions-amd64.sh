common_cflags="-fdata-sections -ffunction-sections -fPIC -std=gnu99 -DHAVE_CONFIG_H -I. -I../.. -include config.h -I ../../gum -I ../../libs -I ../../tests -I ../../gum/arch-x86 -I ../../ext/udis86 -pthread -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -Wall -pipe -gdwarf-2 -g3"
common_ldflags="-shared -Wl,-no-undefined -shared -Wl,--gc-sections"
glib_library="$FRIDA_PREFIX/lib/libglib-2.0.a"

gcc $common_cflags -O0 -c targetfunctions.c
verscript="$(mktemp)"
cat >"$verscript" << EOF
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
gcc \
      $common_ldflags \
      -Wl,--version-script="$verscript" \
      -Wl,-soname,targetfunctions-amd64.so \
      -o targetfunctions-amd64.so \
      targetfunctions.o \
      "$glib_library"
rm targetfunctions.o "$verscript"
strip --strip-all targetfunctions-amd64.so

gcc $common_cflags -O2 -c specialfunctions.c
verscript="$(mktemp)"
cat >"$verscript" << EOF
GUM_TEST_SPECIALFUNCTIONS_1.0 {
  global:
    gum_test_special_function;

  local:
    *;
};
EOF
gcc \
      $common_ldflags \
      -Wl,--version-script="$verscript" \
      -Wl,-soname,specialfunctions-amd64.so \
      -o specialfunctions-amd64.so \
      specialfunctions.o \
      "$glib_library"
rm specialfunctions.o "$verscript"
strip --strip-all specialfunctions-amd64.so
