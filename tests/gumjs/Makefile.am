noinst_LTLIBRARIES = libgum-tests-gumjs.la

libgum_tests_gumjs_la_SOURCES = \
	script.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/bindings/gumjs \
	-I $(top_srcdir) \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(GUM_CFLAGS)
