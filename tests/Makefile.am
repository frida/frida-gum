SUBDIRS = \
	core \
	heap \
	prof

noinst_PROGRAMS = gum-tests
noinst_LTLIBRARIES = libgum-tests.la

arch_sources = $(NULL)
backend_libs = $(NULL)

if ARCH_I386
arch_sources += \
	lowlevel-helpers.c \
	lowlevel-helpers.h
endif

if HAVE_BFD
backend_libs += \
	-lbfd
endif

gum_tests_SOURCES = \
	$(NULL)
gum_tests_LDADD = \
	$(builddir)/libgum-tests.la \
	$(top_builddir)/gum/libgum-1.0.la \
	$(backend_libs) \
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
	$(top_builddir)/gum/libgum-1.0.la \
	$(GUM_LIBS)

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
