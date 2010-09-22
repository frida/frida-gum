SUBDIRS = core

noinst_PROGRAMS = gum-tests
noinst_LTLIBRARIES = libgum-tests.la

gum_tests_SOURCES = \
	$(NULL)
gum_tests_LDADD = \
	$(builddir)/libgum-tests.la \
	$(top_builddir)/gum/libgum-1.0.la

libgum_tests_la_SOURCES = \
	gumtest.c \
	testutil.c \
	testutil.h
libgum_tests_la_LIBADD = \
	$(builddir)/core/libgum-tests-core.la \
	$(top_builddir)/gum/libgum-1.0.la \
	$(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/libs \
	$(GUM_CFLAGS)

all-local: gum-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/gum-tests.xcent" "$<"
