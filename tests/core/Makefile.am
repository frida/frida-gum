noinst_LTLIBRARIES = libgum-tests-core.la libgum-targetfunctions.la

libgum_tests_core_la_SOURCES = \
	arch-arm/armwriter.c \
	arch-arm/armrelocator.c \
	arch-arm/thumbwriter.c \
	arch-arm/thumbrelocator.c \
	symbolutil.c \
	interceptor.c \
	script.c

libgum_targetfunctions_la_SOURCES = \
	targetfunctions.c
libgum_targetfunctions_la_LDFLAGS = \
	-rpath /nowhere

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/gum/arch-arm \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(GUM_CFLAGS)
