SUBDIRS = core

noinst_PROGRAMS = gum-tests

gum_tests_SOURCES = \
	gumtest.c \
	testutil.c \
	testutil.h
gum_tests_LDADD = \
	$(builddir)/core/libgum-tests-core.la \
	$(top_builddir)/gum/libgum-1.0.la \
	$(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/libs \
	$(GUM_CFLAGS)

all-local: gum-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/gum-tests.xcent" "$<"
