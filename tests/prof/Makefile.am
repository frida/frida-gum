noinst_LTLIBRARIES = \
	libgum-tests-prof.la

libgum_tests_prof_la_SOURCES = \
	fakesampler.c \
	fakesampler.h \
	profiler.c \
	sampler.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/libs/gum/prof \
	-I $(top_srcdir)/tests \
	$(GUM_CFLAGS)
