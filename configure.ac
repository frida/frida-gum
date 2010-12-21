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
AC_PROG_LIBTOOL
AC_PROG_INSTALL

GLIB_VERSION=2.24.1
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION,
    gio-2.0 >= $GLIB_VERSION"
PKG_CHECK_MODULES(GUM, [$pkg_modules])
AC_SUBST(GUM_CFLAGS)
AC_SUBST(GUM_LIBS)

AC_CHECK_HEADER(bfd.h, HAVE_BFD=yes, HAVE_BFD=no)
if [[ "$HAVE_BFD" = "yes" ]]; then
  AC_DEFINE(HAVE_SYMBOL_BACKEND, 1, [Define to 1 if symbol backend is available.])
fi
AM_CONDITIONAL(HAVE_BFD, test "$HAVE_BFD" = "yes")

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

case $target_os in
  linux*)  HAVE_LINUX=yes  ;;
  darwin*) HAVE_DARWIN=yes ;;
  *)                       ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_LINUX, test "x$HAVE_LINUX" = "xyes")
AM_CONDITIONAL(OS_DARWIN, test "x$HAVE_DARWIN" = "xyes")

case $target_os in
  darwin10\.*) HAVE_OSX=yes ;;
  *)                      ;;
esac
if [[ "x$HAVE_OSX" = "xyes" ]]; then
  AC_DEFINE(HAVE_OSX, 1, [Define to 1 if OS is Mac OS X.])
fi
AM_CONDITIONAL(OS_OSX, test "x$HAVE_OSX" = "xyes")

if [[ "x$HAVE_DARWIN" = "xyes" ]] && [[ "x$HAVE_OSX" != "xyes" ]]; then
  HAVE_IOS=yes
  AC_DEFINE(HAVE_IOS, 1, [Define to 1 if OS is iOS.])
fi
AM_CONDITIONAL(OS_IOS, test "x$HAVE_IOS" = "xyes")

AC_CONFIG_FILES([
	gum-1.0.pc
	Makefile
	ext/Makefile
	ext/udis86/Makefile
	ext/udis86/libudis86/Makefile
        libs/Makefile
        libs/gum/Makefile
        libs/gum/heap/Makefile
        libs/gum/prof/Makefile
	gum/Makefile
	tests/Makefile
	tests/core/Makefile
	tests/heap/Makefile
	vapi/Makefile
])
AC_OUTPUT
