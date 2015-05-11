AC_INIT([frida-gum], [1.0.0])
AC_CONFIG_SRCDIR([gum/gum.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_OBJC
AM_PROG_AS
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

AC_TYPE_UNSIGNED_LONG_LONG_INT
AC_TYPE_LONG_DOUBLE
AC_TYPE_LONG_LONG_INT

AC_CHECK_HEADERS([elf.h sys/elf.h])

HAVE_I386=no
HAVE_ARM=no
HAVE_ARM64=no
case $host_cpu in
  i?86|x86*)
    HAVE_I386=yes
  ;;
  arm|armv7)
    HAVE_ARM=yes
  ;;
  aarch64)
    HAVE_ARM64=yes
  ;;
esac
if [[ "$HAVE_I386" = "yes" ]]; then
  AC_DEFINE(HAVE_I386, 1, [Define to 1 if target is x86 based.])
fi
if [[ "$HAVE_ARM" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM, 1, [Define to 1 if target is ARM based.])
fi
if [[ "$HAVE_ARM64" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM64, 1, [Define to 1 if target is AArch64 based.])
fi
AM_CONDITIONAL(ARCH_I386, test "$HAVE_I386" = "yes")
AM_CONDITIONAL(ARCH_ARM, test "$HAVE_ARM" = "yes")
AM_CONDITIONAL(ARCH_ARM64, test "$HAVE_ARM64" = "yes")

case $host_os in
  linux*)   HAVE_LINUX=yes  ;;
  darwin*)  HAVE_DARWIN=yes ;;
  nto-qnx*) HAVE_QNX=yes    ;;
  *)                        ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
  AC_DEFINE(_GNU_SOURCE, 1, [Enable GNU extensions (required by Linux backend).])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
if [[ "x$HAVE_QNX" = "xyes" ]]; then
  AC_DEFINE(HAVE_QNX, 1, [Define to 1 if OS is QNX based.])
  AC_DEFINE(_QNX_SOURCE, 1, [Enable QNX extensions.])
fi
AM_CONDITIONAL(OS_LINUX, test "x$HAVE_LINUX" = "xyes")
AM_CONDITIONAL(OS_DARWIN, test "x$HAVE_DARWIN" = "xyes")
AM_CONDITIONAL(OS_QNX, test "x$HAVE_QNX" = "xyes")

case $host_os in
  darwin*)
    case $host_cpu in
      arm|aarch64)
        HAVE_MAC=no
        HAVE_IOS=yes
        ;;
      *)
        HAVE_MAC=yes
        HAVE_IOS=no
        ;;
    esac
    ;;
  *-android*)
    HAVE_ANDROID=yes
    ;;
  *)
    ;;
esac
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  AC_DEFINE(HAVE_MAC, 1, [Define to 1 if OS is Mac.])
fi
AM_CONDITIONAL(OS_MAC, test "x$HAVE_MAC" = "xyes")
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  AC_DEFINE(HAVE_ANDROID, 1, [Define to 1 if OS is Android based.])
fi
AM_CONDITIONAL(OS_ANDROID, test "x$HAVE_ANDROID" = "xyes")

if [[ "x$HAVE_IOS" = "xyes" ]]; then
  AC_DEFINE(HAVE_IOS, 1, [Define to 1 if OS is iOS.])
fi
AM_CONDITIONAL(OS_IOS, test "x$HAVE_IOS" = "xyes")

AC_CHECK_MEMBER([struct mallinfo.arena],
    [AC_DEFINE(HAVE_LIBC_MALLINFO, 1, [Define to 1 if libc has mallinfo struct.])])

GLIB_VERSION=2.46.0
CAPSTONE_VERSION=4.0
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION,
    gio-2.0 >= $GLIB_VERSION, capstone >= $CAPSTONE_VERSION"
PKG_CHECK_MODULES(GUM, [$pkg_modules])

PKG_CHECK_MODULES(LIBUNWIND, [libunwind], [HAVE_LIBUNWIND=yes], [HAVE_LIBUNWIND=no])
if [[ "x$HAVE_LIBUNWIND" = "xyes" ]]; then
  AC_DEFINE(HAVE_LIBUNWIND, 1, [Define to 1 if libunwind is available.])
  GUM_LDFLAGS="$GUM_LDFLAGS $LIBUNWIND_LDFLAGS"
  GUM_LIBS="$GUM_LIBS $LIBUNWIND_LIBS"
  LIBUNWIND_REQUIRES=libunwind
fi
AC_SUBST(LIBUNWIND_REQUIRES)
AM_CONDITIONAL(HAVE_LIBUNWIND, [test "x$HAVE_LIBUNWIND" = "xyes"])

if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_CHECK_HEADER([bfd.h], AC_CHECK_LIB([bfd], [bfd_openr], HAVE_BFD=yes, HAVE_BFD=no, [-ldl -lz]), HAVE_BFD=no)
  test "$HAVE_BFD" = "yes" && BFD_LIBS="-lbfd -ldl -lz"
else
  AC_CHECK_HEADER(bfd.h, HAVE_BFD=yes, HAVE_BFD=no)
  test "$HAVE_BFD" = "yes" && BFD_LIBS="-lbfd -lz"
fi
test "$HAVE_BFD" = "yes" && GUM_LIBS="$GUM_LIBS $BFD_LIBS"
AC_SUBST(BFD_LIBS)
AM_CONDITIONAL(HAVE_BFD, test "$HAVE_BFD" = "yes")

if [[ "x$HAVE_LINUX" = "xyes" -o "x$HAVE_QNX" = "xyes" ]]; then
  if [[ "x$HAVE_LIBUNWIND" != "xyes" ]]; then
    AC_MSG_ERROR([libunwind is required.])
  fi
  if [[ "x$HAVE_BFD" != "xyes" ]]; then
    AC_MSG_ERROR([libbfd and zlib required.])
  fi
fi

AC_SUBST(GUM_CFLAGS)
AC_SUBST(GUM_LDFLAGS)
AC_SUBST(GUM_LIBS)

LIBFFI_REQUIRES="libffi >= 3.1.1"
PKG_CHECK_MODULES(V8, [v8], [HAVE_GUMJS=yes], [HAVE_GUMJS=no])
if [[ "x$HAVE_GUMJS" = "xyes" ]]; then
  AC_DEFINE(HAVE_GUMJS, 1, [Define to 1 if GumJS is available.])
  PKG_CHECK_MODULES(LIBFFI, [$LIBFFI_REQUIRES])
  GUMJS_CFLAGS="$GUM_CFLAGS $LIBFFI_CFLAGS $V8_CFLAGS"
  GUMJS_LDFLAGS="$GUM_LDFLAGS $LIBFFI_LDFLAGS $V8_LDFLAGS"
  GUMJS_LIBS="$GUM_LIBS $LIBFFI_LIBS $V8_LIBS"
fi
AM_CONDITIONAL(ENABLE_GUMJS, [test "x$HAVE_GUMJS" = "xyes"])
AC_SUBST(GUMJS_CFLAGS)
AC_SUBST(GUMJS_LDFLAGS)
AC_SUBST(GUMJS_LIBS)
AC_SUBST(LIBFFI_REQUIRES)

GUM_TEST_LIBS=""
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  GUM_TEST_LIBS="$GUM_TEST_LIBS -Wl,-framework -Wl,AppKit"
fi
if [[ "x$HAVE_IOS" = "xyes" ]]; then
  GUM_TEST_LIBS="$GUM_TEST_LIBS -Wl,-framework -Wl,Foundation"
fi
AC_SUBST(GUM_TEST_LIBS)

AC_CONFIG_FILES([
  frida-gum-1.0.pc
  frida-gumjs-1.0.pc
  frida-gumpp-1.0.pc
  Makefile
  libs/Makefile
  libs/gum/Makefile
  libs/gum/heap/Makefile
  libs/gum/prof/Makefile
  gum/Makefile
  bindings/Makefile
  bindings/gumjs/Makefile
  bindings/gumpp/Makefile
  tests/Makefile
  tests/core/Makefile
  tests/heap/Makefile
  tests/prof/Makefile
  tests/gumjs/Makefile
  tests/gumpp/Makefile
  vapi/Makefile
])
AC_OUTPUT
