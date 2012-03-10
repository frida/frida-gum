SUBDIRS = \
	core \
	heap \
	prof

if OS_ANDROID
else
if OS_IOS
else
SUBDIRS += gumpp
TESTS = gum-tests
endif
endif

noinst_PROGRAMS = gum-tests
noinst_LTLIBRARIES = libgum-tests.la

arch_sources = $(NULL)
binding_ldadd = $(NULL)
binding_libadd = $(NULL)

if ARCH_I386
arch_sources += \
	lowlevel-helpers.c \
	lowlevel-helpers.h
endif

if OS_ANDROID
else
if OS_IOS
else
binding_ldadd += $(top_builddir)/bindings/gumpp/libgumpp-1.0.la
binding_libadd += $(builddir)/gumpp/libgum-tests-gumpp.la
endif
endif

gum_tests_SOURCES = \
	$(NULL)
gum_tests_LDFLAGS = \
	$(GUM_LDFLAGS)
gum_tests_LDADD = \
	$(builddir)/libgum-tests.la \
	$(top_builddir)/gum/libgum-1.0.la \
	$(binding_ldadd) \
	$(GUM_LIBS) \
	-lstdc++

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
	$(arch_sources)
libgum_tests_la_LIBADD = \
	$(builddir)/core/libgum-tests-core.la \
	$(builddir)/heap/libgum-tests-heap.la \
	$(builddir)/prof/libgum-tests-prof.la \
	$(binding_libadd)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/gum/arch-x86 \
	-I $(top_srcdir)/libs \
	$(GUM_CFLAGS)

if OS_IOS
all-local: gum-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/gum-tests.xcent" "$<"
endif
