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
AC_PROG_LIBTOOL
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
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_LINUX, test "x$HAVE_LINUX" = "xyes")
AM_CONDITIONAL(OS_DARWIN, test "x$HAVE_DARWIN" = "xyes")

case $host_os in
  darwin10\.*|darwin11\.*) HAVE_OSX=yes     ;;
  *-android*)              HAVE_ANDROID=yes ;;
  *)				;;
esac
if [[ "x$HAVE_OSX" = "xyes" ]]; then
  AC_DEFINE(HAVE_OSX, 1, [Define to 1 if OS is Mac OS X.])
fi
AM_CONDITIONAL(OS_OSX, test "x$HAVE_OSX" = "xyes")
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  AC_DEFINE(HAVE_ANDROID, 1, [Define to 1 if OS is Android based.])
fi
AM_CONDITIONAL(OS_ANDROID, test "x$HAVE_ANDROID" = "xyes")

if [[ "x$HAVE_DARWIN" = "xyes" ]] && [[ "x$HAVE_OSX" != "xyes" ]]; then
  HAVE_IOS=yes
  AC_DEFINE(HAVE_IOS, 1, [Define to 1 if OS is iOS.])
else
  HAVE_IOS=no
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
    gio-2.0 >= $GLIB_VERSION, v8"
PKG_CHECK_MODULES(GUM, [$pkg_modules])

if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_CHECK_HEADER([bfd.h], AC_CHECK_LIB([bfd], [bfd_openr]), AC_ERROR([*** Header file bfd.h not found; please install the binutils headers  ***]))
  HAVE_BFD=yes

  GUM_LIBS="$GUM_LIBS -lbfd"
else
  AC_CHECK_HEADER(bfd.h, HAVE_BFD=yes, HAVE_BFD=no)
fi
AM_CONDITIONAL(HAVE_BFD, test "$HAVE_BFD" = "yes")

GUM_EXTRA_LIBS="-lstdc++"
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  GUM_EXTRA_LIBS="$GUM_EXTRA_LIBS -Wl,-framework,Foundation -F/System/Library/PrivateFrameworks -Wl,-framework,Symbolication"
fi
AC_SUBST(GUM_EXTRA_LIBS)

GUM_LDFLAGS="$GUM_LDFLAGS $GUM_EXTRA_LIBS"

AC_SUBST(GUM_CFLAGS)
AC_SUBST(GUM_LDFLAGS)
AC_SUBST(GUM_LIBS)

if [[ "x$HAVE_BFD" = "xyes" -o "x$HAVE_DARWIN" = "xyes" ]] && [[ "x$HAVE_IOS" = "xno" ]]; then
  AC_DEFINE(HAVE_SYMBOL_BACKEND, 1, [Define to 1 if a symbol backend is available.])
fi

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
