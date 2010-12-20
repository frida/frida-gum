noinst_LTLIBRARIES = libgum-prof-1.0.la

gumincludedir = $(includedir)/gum-1.0/gum/prof
guminclude_HEADERS = \
	gumbusycyclesampler.h \
	gumcallcountsampler.h \
	gumcyclesampler.h \
	gummalloccountsampler.h \
	gumprofiler.h \
	gumprofilereport.h \
	gumsampler.h \
	gumwallclocksampler.h

libgum_prof_1_0_la_SOURCES = \
	gumcallcountsampler.c \
	gummalloccountsampler.c \
	gumprofiler.c \
	gumprofilereport.c \
	gumsampler.c \
	gumwallclocksampler.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	$(GUM_CFLAGS)
