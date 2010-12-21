noinst_LTLIBRARIES = \
	libgum-tests-heap.la

libgum_tests_heap_la_SOURCES = \
	allocationtracker.c \
	allocatorprobe.c \
	allocatorprobex.cxx \
	boundschecker.c \
	cobjecttracker.c \
	instancetracker.c \
	pagepool.c \
	sanitychecker.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/libs/gum/heap \
	-I $(top_srcdir)/tests \
	-I $(top_srcdir)/tests/stubs \
	$(GUM_CFLAGS)
