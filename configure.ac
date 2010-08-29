AC_INIT([libgum], [0.1])
AC_CONFIG_SRCDIR([gum/gum.c])
AC_CONFIG_HEADERS([config.h])

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

AC_CONFIG_FILES([
	Makefile
	gum/Makefile
	tests/Makefile
	tests/core/Makefile
])
AC_OUTPUT
