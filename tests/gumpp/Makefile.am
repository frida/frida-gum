sources = $(NULL)

if OS_ANDROID
else
if OS_IOS
else
sources += \
	backtracer.cxx
endif
endif

noinst_LTLIBRARIES = libgum-tests-gumpp.la

libgum_tests_gumpp_la_SOURCES = $(sources)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/bindings/gumpp \
	-I $(top_srcdir)/tests
