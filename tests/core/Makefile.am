noinst_LTLIBRARIES = \
	libgum-tests-core.la \
	libgum-targetfunctions.la

arch_sources = $(NULL)
arch_includes = $(NULL)

if ARCH_I386
arch_sources += \
	arch-x86/codewriter.c \
	arch-x86/functionparser.c \
	arch-x86/relocator.c
arch_includes += \
	-I $(top_srcdir)/gum/arch-x86 \
	-I $(top_srcdir)/ext/udis86
endif

if ARCH_ARM
arch_sources += \
	arch-arm/armwriter.c \
	arch-arm/armrelocator.c \
	arch-arm/thumbwriter.c \
	arch-arm/thumbrelocator.c
arch_includes += \
	-I $(top_srcdir)/gum/arch-arm
endif

libgum_tests_core_la_SOURCES = \
	$(arch_sources) \
	memory.c \
	symbolutil.c \
	interceptor.c \
	script.c

libgum_targetfunctions_la_SOURCES = targetfunctions.c
libgum_targetfunctions_la_LDFLAGS = -rpath /nowhere
libgum_targetfunctions_la_LIBADD = $(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(arch_includes) \
	$(GUM_CFLAGS)
