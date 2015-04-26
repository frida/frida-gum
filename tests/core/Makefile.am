noinst_LTLIBRARIES = libgum-tests-core.la

arch_sources = $(NULL)
arch_includes = $(NULL)
os_sources = $(NULL)
script_sources = $(NULL)

if ARCH_I386
arch_sources += \
	arch-x86/stalker-x86.c
endif

if OS_MAC
arch_sources += \
	arch-x86/stalker-x86-mac.m
else
libgum_tests_core_la_LIBTOOLFLAGS = \
	--tag=CC
endif

libgum_tests_core_la_SOURCES = \
	memory.c \
	process.c \
	symbolutil.c \
	backtracer.c \
	interceptor.c \
	arch-x86/codewriter.c \
	arch-x86/relocator.c \
	arch-arm/armwriter.c \
	arch-arm/armrelocator.c \
	arch-arm/thumbwriter.c \
	arch-arm/thumbrelocator.c \
	arch-arm64/arm64writer.c \
	arch-arm64/arm64relocator.c \
	$(arch_sources) \
	$(os_sources) \
	$(script_sources)

EXTRA_DIST = \
	targetfunctions.c \
	specialfunctions.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/gum/arch-x86 \
	-I $(top_srcdir)/gum/arch-arm \
	-I $(top_srcdir)/gum/arch-arm64 \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	-I $(top_srcdir)/tests/stubs \
	$(arch_includes) \
	$(GUM_CFLAGS)
