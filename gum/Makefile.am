lib_LTLIBRARIES = libgum-1.0.la
noinst_LTLIBRARIES = libgum.la

gumincludedir = $(includedir)/gum-1.0/gum
guminclude_HEADERS = \
	gum.h \
	gumarray.h \
	gumbacktracer.h \
	gumclosure.h \
	gumcodeallocator.h \
	gumdefs.h \
	gumevent.h \
	gumeventsink.h \
	gumfunction.h \
	gumhash.h \
	guminterceptor.h \
	guminvocationcontext.h \
	guminvocationlistener.h \
	gumlist.h \
	gummemory.h \
	gummemoryaccessmonitor.h \
	gumreturnaddress.h \
	gumspinlock.h \
	gumstalker.h \
	gumsymbolutil.h \
	gumsysinternals.h \
	gumtracer.h

libgum_1_0_la_SOURCES = $(NULL)
libgum_1_0_la_LDFLAGS = \
	-export-symbols-regex "^gum_.*" \
	$(GUM_LDFLAGS)
libgum_1_0_la_LIBADD = \
	libgum.la \
	$(GUM_LIBS)
libgum_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

arch_sources = $(NULL)
arch_includes = $(NULL)
arch_libs = $(NULL)
backend_sources = $(NULL)
script_sources = $(NULL)

if ARCH_I386
archincludedir = $(includedir)/gum-1.0/gum/arch-x86
archinclude_HEADERS = \
	arch-x86/gumx86backtracer.h \
	arch-x86/gumx86writer.h \
	arch-x86/gumx86relocator.h \
	arch-x86/gumx86reader.h \
	arch-x86/gumx86functionparser.h
arch_sources += \
	arch-x86/gumx86backtracer.c \
	arch-x86/gumx86writer.c \
	arch-x86/gumx86relocator.c \
	arch-x86/gumx86reader.c \
	arch-x86/gumx86functionparser.c \
	arch-x86/gumudis86.h \
	arch-x86/gumudis86.c
arch_includes += \
	-I $(srcdir)/arch-x86 \
	-I $(top_srcdir)/ext/udis86
arch_libs += \
	$(top_builddir)/ext/udis86/libudis86/libudis86.la
backend_sources += \
	backend-x86/gumclosure-x86.c \
	backend-x86/guminterceptor-x86.c \
	backend-x86/gumspinlock-x86.c
endif

if ARCH_ARM
archincludedir = $(includedir)/gum-1.0/gum/arch-arm
archinclude_HEADERS = \
	arch-arm/gumarm.h \
	arch-arm/gumarmwriter.h \
	arch-arm/gumarmrelocator.h \
	arch-arm/gumthumbwriter.h \
	arch-arm/gumthumbrelocator.h
arch_sources += \
	arch-arm/gumarmwriter.c \
	arch-arm/gumarmrelocator.c \
	arch-arm/gumthumbwriter.c \
	arch-arm/gumthumbrelocator.c
arch_includes += \
	-I $(srcdir)/arch-arm
backend_sources += \
	backend-arm/gumclosure-arm.c \
	backend-arm/guminterceptor-arm.c \
	backend-arm/gumspinlock-arm.c
endif

if OS_LINUX
backend_sources += \
	backend-linux/gumsymbolutil-linux.c
endif

if OS_DARWIN
backend_sources += \
	backend-darwin/gummemory-darwin.c \
	backend-darwin/gumnsbacktracer.m \
	backend-darwin/gumsymbolutil-darwin.m
guminclude_HEADERS += backend-darwin/gumnsbacktracer.h
else
backend_sources += \
	backend-unix/gummemory-unix.c
endif

if HAVE_GLIBC
backend_sources += \
	backend-glibc/gumgnubacktracer.c
endif

if HAVE_BFD
backend_sources += \
	backend-bfd/gumsymbolutil-bfd.c
endif

if OS_ANDROID
else
backend_sources += backend-gcc/gumgccbacktracer.c
guminclude_HEADERS += backend-gcc/gumgccbacktracer.h
endif

if HAVE_V8
script_sources += gumscript.cpp
guminclude_HEADERS += gumscript.h
endif

container_sources = \
	gumarray.c \
	gumhash.c \
	gumlist.c

libgum_la_SOURCES = \
	gum.c \
	gumbacktracer.c \
	gumcodeallocator.c \
	guminterceptor.c \
	guminvocationcontext.c \
	guminvocationlistener.c \
	gummemory.c \
	gumreturnaddress.c \
	gumtls.h \
	$(arch_sources) \
	$(container_sources) \
	$(script_sources) \
	$(backend_sources)
libgum_la_LIBADD = \
	$(top_builddir)/libs/gum/heap/libgum-heap-1.0.la \
	$(top_builddir)/libs/gum/prof/libgum-prof-1.0.la \
	$(arch_libs)
libgum_la_LIBTOOLFLAGS = --tag=disable-shared

AM_CPPFLAGS = \
	-include config.h \
	$(arch_includes) \
	$(GUM_CFLAGS)
