noinst_LTLIBRARIES = libgum-tests-core.la

libgum_tests_core_la_SOURCES = \
	interceptor.c \
	symbolutil.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(GUM_CFLAGS)
