AC_INIT([libgum], [1.0.0])
AC_CONFIG_SRCDIR([gum/gum.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_OBJC
AM_PROG_AS
AM_PROG_AR
LT_INIT
AC_PROG_INSTALL

HAVE_I386=no
HAVE_ARM=no
case $target_cpu in
  i?86|x86*)
    HAVE_I386=yes
  ;;
  arm)
    HAVE_ARM=yes
  ;;
esac
if [[ "$HAVE_I386" = "yes" ]]; then
  AC_DEFINE(HAVE_I386, 1, [Define to 1 if target is x86 based.])
fi
if [[ "$HAVE_ARM" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM, 1, [Define to 1 if target is ARM based.])
fi
AM_CONDITIONAL(ARCH_I386, test "$HAVE_I386" = "yes")
AM_CONDITIONAL(ARCH_ARM, test "$HAVE_ARM" = "yes")

case $host_os in
  linux*)  HAVE_LINUX=yes  ;;
  darwin*) HAVE_DARWIN=yes ;;
  *)			   ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
  AC_DEFINE(_GNU_SOURCE, 1, [Enable GNU extensions (required by Linux backend).])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_LINUX, test "x$HAVE_LINUX" = "xyes")
AM_CONDITIONAL(OS_DARWIN, test "x$HAVE_DARWIN" = "xyes")

case $host_os in
  darwin*)
    case $host_cpu in
      arm)
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

AC_TRY_LINK(
    [ #include <execinfo.h> ],
    [ backtrace (NULL, 0); ],
    HAVE_GLIBC=yes,
    HAVE_GLIBC=no)
if [[ "x$HAVE_GLIBC" = "xyes" ]]; then
  AC_DEFINE(HAVE_GLIBC, 1, [Define to 1 if libc is glibc.])
fi
AM_CONDITIONAL(HAVE_GLIBC, test "$HAVE_GLIBC" = "yes")

AC_CHECK_MEMBER([struct mallinfo.arena],
    [AC_DEFINE(HAVE_LIBC_MALLINFO, 1, [Define to 1 if libc has mallinfo struct.])])

GLIB_VERSION=2.24.1
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION,
    gio-2.0 >= $GLIB_VERSION, libffi >= 3.0.12"
PKG_CHECK_MODULES(GUM, [$pkg_modules])

PKG_CHECK_MODULES(V8, [v8], [HAVE_V8=yes], [HAVE_V8=no])
if [[ "x$HAVE_V8" = "xyes" ]]; then
  AC_DEFINE(HAVE_V8, 1, [Define to 1 if v8 is available.])
fi
AM_CONDITIONAL(HAVE_V8, [test "x$HAVE_V8" = "xyes"])

GUM_CFLAGS="$GUM_CFLAGS $V8_CFLAGS"
GUM_LDFLAGS="$GUM_LDFLAGS $V8_LDFLAGS"
GUM_LIBS="$GUM_LIBS $V8_LIBS"

if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_CHECK_HEADER([bfd.h], AC_CHECK_LIB([bfd], [bfd_openr], HAVE_BFD=yes, HAVE_BFD=no), HAVE_BFD=no)
  test "$HAVE_BFD" = "yes" && GUM_LIBS="$GUM_LIBS -lbfd"
else
  AC_CHECK_HEADER(bfd.h, HAVE_BFD=yes, HAVE_BFD=no)
fi
AM_CONDITIONAL(HAVE_BFD, test "$HAVE_BFD" = "yes")

AC_ARG_ENABLE(objc, [AC_HELP_STRING([--enable-objc], [enable Obj-C dependent code [default=no]])],, [enable_objc=no])
if [[ "x$enable_objc" = "xyes" ]]; then
  AC_DEFINE(HAVE_OBJC, 1, [Define to 1 if Obj-C dependent code is available.])
fi
AM_CONDITIONAL(ENABLE_OBJC, [test "x$enable_objc" = "xyes"])

GUM_EXTRA_LIBS="-lstdc++"
if [[ "x$enable_objc" = "xyes" ]]; then
  GUM_EXTRA_LIBS="$GUM_EXTRA_LIBS -Wl,-framework,Foundation -F/System/Library/PrivateFrameworks -Wl,-framework,Symbolication"
fi
AC_SUBST(GUM_EXTRA_LIBS)

GUM_LDFLAGS="$GUM_LDFLAGS $GUM_EXTRA_LIBS"

AC_SUBST(GUM_CFLAGS)
AC_SUBST(GUM_LDFLAGS)
AC_SUBST(GUM_LIBS)

if [[ "x$HAVE_BFD" = "xyes" ]] || [[ "x$enable_objc" = "xyes" ]]; then
  enable_symbol_backend=yes
  AC_DEFINE(HAVE_SYMBOL_BACKEND, 1, [Define to 1 if a symbol backend is available.])
else
  enable_symbol_backend=no
fi

if [[ "x$enable_symbol_backend" = "xyes" ]]; then
  AC_DEFINE(HAVE_LIBS, 1, [Define to 1 if helper libs are available.])
fi
AM_CONDITIONAL(ENABLE_LIBS, [test "x$enable_symbol_backend" = "xyes" ])

AC_ARG_ENABLE(bindings, [AC_HELP_STRING([--enable-bindings], [build bindings [default=auto]])],, [enable_bindings=auto])
if [[ "x$enable_bindings" = "xauto" ]]; then
  if [[ "x$enable_symbol_backend" = "xyes" ]]; then
    enable_bindings=yes
  else
    enable_bindings=no
  fi
fi
if [[ "x$enable_bindings" = "xyes" ]]; then
  AC_DEFINE(HAVE_BINDINGS, 1, [Define to 1 if bindings are available.])
fi
AM_CONDITIONAL(ENABLE_BINDINGS, [test "x$enable_bindings" != "xno" -a "x$enable_symbol_backend" = "xyes" ])

AC_CONFIG_FILES([
	gum-1.0.pc
	gumpp-1.0.pc
	Makefile
	ext/Makefile
	ext/udis86/Makefile
	ext/udis86/libudis86/Makefile
	libs/Makefile
	libs/gum/Makefile
	libs/gum/heap/Makefile
	libs/gum/prof/Makefile
	gum/Makefile
	bindings/Makefile
	bindings/gumpp/Makefile
	tests/Makefile
	tests/core/Makefile
	tests/heap/Makefile
	tests/prof/Makefile
	tests/gumpp/Makefile
	vapi/Makefile
])
AC_OUTPUT
