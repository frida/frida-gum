noinst_LTLIBRARIES = libfrida-gum-prof-1.0.la

arch_sources = $(NULL)
arch_includes = $(NULL)

if ARCH_I386
if OS_QNX
else
arch_sources += \
	gumcyclesampler-x86.c
arch_includes += \
	-I $(top_srcdir)/gum/arch-x86
endif
endif

os_sources = $(NULL)

if OS_DARWIN
os_sources += \
	gumbusycyclesampler-darwin.c
endif

if OS_QNX
os_sources += \
	gumcyclesampler-qnx.c
endif

fridaincludedir = $(includedir)/frida-1.0/gum/prof
fridainclude_HEADERS = \
	gumbusycyclesampler.h \
	gumcallcountsampler.h \
	gumcyclesampler.h \
	gummalloccountsampler.h \
	gumprofiler.h \
	gumprofilereport.h \
	gumsampler.h \
	gumwallclocksampler.h

libfrida_gum_prof_1_0_la_SOURCES = \
	$(arch_sources) \
	$(os_sources) \
	gumcallcountsampler.c \
	gummalloccountsampler.c \
	gumprofiler.c \
	gumprofilereport.c \
	gumsampler.c \
	gumwallclocksampler.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	$(arch_includes) \
	$(GUM_CFLAGS)
