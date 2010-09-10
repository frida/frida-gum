AC_INIT([libgum], [1.0.0])
AC_CONFIG_SRCDIR([gum/gum.c])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules is available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

GLIB_VERSION=2.25.13
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION"
PKG_CHECK_MODULES(GUM, [$pkg_modules])
AC_SUBST(GUM_CFLAGS)
AC_SUBST(GUM_LIBS)

AC_CHECK_HEADER(bfd.h, HAVE_BFD=yes, HAVE_BFD=no)
if [[ "$HAVE_BFD" = "yes" ]]; then
  AC_DEFINE(HAVE_SYMBOL_BACKEND, 1, [Define to 1 if symbol backend is available.])
fi

HAVE_I386=no
HAVE_ARM=no
case $target_cpu in
  i?86)
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
  darwin) HAVE_DARWIN=yes ;;
  *)      HAVE_DARWIN=no  ;;
esac
if [[ "$HAVE_DARWIN" = "yes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_DARWIN, test "$HAVE_DARWIN" = "yes")

AC_CONFIG_FILES([
	gum-1.0.pc
	Makefile
	gum/Makefile
	tests/Makefile
	tests/core/Makefile
	vapi/Makefile
])
AC_OUTPUT
