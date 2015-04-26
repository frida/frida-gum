SUBDIRS = \
	core \
	heap \
	prof \
	gumpp

if ENABLE_GUMJS
SUBDIRS += \
	gumjs
endif

if OS_ANDROID
else
if OS_IOS
else
TESTS = gum-tests
endif
endif

noinst_PROGRAMS = gum-tests
noinst_LTLIBRARIES = libgum-tests.la

extra_testsuites =
extra_ldflags =
extra_libs =

if ENABLE_GUMJS
extra_testsuites += \
	$(builddir)/gumjs/libgum-tests-gumjs.la
extra_ldflags += \
	$(GUMJS_LDFLAGS)
extra_libs += \
	$(top_builddir)/bindings/gumjs/libfrida-gumjs.la \
	$(GUMJS_LIBS)
endif

gum_tests_SOURCES = \
	dummy.cpp
gum_tests_LDFLAGS = \
	$(GUM_LDFLAGS) \
	$(extra_ldflags)
gum_tests_LDADD = \
	$(builddir)/libgum-tests.la \
	$(top_builddir)/bindings/gumpp/libfrida-gumpp-static-1.0.la \
	$(extra_libs) \
	$(top_builddir)/gum/libfrida-gum-1.0.la \
	$(GUM_TEST_LIBS) \
	$(GUM_LIBS)
if OS_MAC
gum_tests_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/gum-tests.plist"
endif

libgum_tests_la_SOURCES = \
	gumtest.c \
	testutil.c \
	testutil.h \
	stubs/dummyclasses.c \
	stubs/dummyclasses.h \
	stubs/fakebacktracer.c \
	stubs/fakebacktracer.h \
	stubs/fakeeventsink.c \
	stubs/fakeeventsink.h \
	lowlevel-helpers.c \
	lowlevel-helpers.h
libgum_tests_la_LIBADD = \
	$(builddir)/core/libgum-tests-core.la \
	$(builddir)/heap/libgum-tests-heap.la \
	$(builddir)/prof/libgum-tests-prof.la \
	$(builddir)/gumpp/libgum-tests-gumpp.la \
	$(extra_testsuites)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/gum/arch-x86 \
	-I $(top_srcdir)/libs \
	$(GUM_CFLAGS)

if OS_MAC
all-local: gum-tests
	( \
		if [ -f "$(builddir)/.libs/gum-tests" ]; then \
			codesign -s "$$MAC_CERTID" -i "re.frida.GumTests" "$(builddir)/.libs/gum-tests" || true; \
		else \
			codesign -s "$$MAC_CERTID" -i "re.frida.GumTests" "$(builddir)/gum-tests" || true; \
		fi; \
		if [ ! -d "$(builddir)/data" ]; then \
			cp -a "$(srcdir)/data" "$(builddir)/data"; \
		fi \
	)
else
if OS_IOS
all-local: gum-tests
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/gum-tests.xcent" "$<" || true
else
all-local: gum-tests
	( \
		if [ ! -d "$(builddir)/data" ]; then \
			cp -a "$(srcdir)/data" "$(builddir)/data"; \
		fi \
	)
endif
endif
