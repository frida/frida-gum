noinst_PROGRAMS = gum-tests

gum_tests_SOURCES = \
	gumtest.c
gum_tests_LDADD = \
	$(top_builddir)/gum/libgum.la \
	$(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir) \
	$(GUM_CFLAGS)

all-local: gum-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/gum-tests.xcent" "$<"
