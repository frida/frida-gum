noinst_LTLIBRARIES = libgum-tests-gumjs.la

os_sources = $(NULL)

if OS_DARWIN
os_sources += \
	script-darwin.m
else
libgum_tests_gumjs_la_LIBTOOLFLAGS = \
	--tag=CC
endif

if OS_IOS
os_sources += \
	kscript.c
endif

libgum_tests_gumjs_la_SOURCES = \
	script.c \
	$(os_sources)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/bindings/gumjs \
	-I $(top_srcdir) \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(GUM_CFLAGS)
