lib_LTLIBRARIES = libgum-1.0.la

gumincludedir = $(includedir)/gum-1.0/gum
guminclude_HEADERS = \
	gum.h \
	gumarray.h \
	gumbacktracer.h \
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
	gumreturnaddress.h \
	gumscript.h \
	gumspinlock.h \
	gumstalker.h \
	gumsymbolutil.h \
	gumsysinternals.h \
	gumtracer.h

arch_sources = $(NULL)
arch_libs = $(NULL)
backend_sources = $(NULL)
backend_libs = $(NULL)

if ARCH_I386
arch_sources += \
	arch-x86/gumx86writer.h \
	arch-x86/gumx86writer.c \
	arch-x86/gumx86relocator.h \
	arch-x86/gumx86relocator.c \
	arch-x86/gumx86reader.h \
	arch-x86/gumx86reader.c \
	arch-x86/gumx86functionparser.h \
	arch-x86/gumx86functionparser.c \
	arch-x86/gumudis86.h \
	arch-x86/gumudis86.c
arch_libs += \
	$(top_builddir)/ext/udis86/libudis86/libudis86.la
backend_sources += \
	backend-x86/guminterceptor-x86.c \
	backend-x86/gumscriptcompiler-x86.c \
	backend-x86/gumspinlock-x86.c
endif

if ARCH_ARM
arch_sources += \
	arch-arm/gumarm.h \
	arch-arm/gumarmwriter.c \
	arch-arm/gumarmwriter.h \
	arch-arm/gumarmrelocator.c \
	arch-arm/gumarmrelocator.h \
	arch-arm/gumthumbwriter.c \
	arch-arm/gumthumbwriter.h \
	arch-arm/gumthumbrelocator.c \
	arch-arm/gumthumbrelocator.h
backend_sources += \
	backend-arm/guminterceptor-arm.c \
	backend-arm/gumscriptcompiler-arm.c \
	backend-arm/gumspinlock-arm.c
endif

if OS_LINUX
backend_sources += \
	backend-linux/gumsymbolutil-linux.c
endif

if OS_DARWIN
backend_sources += \
	backend-darwin/gummemory-darwin.c \
	backend-darwin/gumsymbolutil-darwin.c
else
backend_sources += \
	backend-unix/gummemory-unix.c
endif

if HAVE_BFD
backend_sources += \
	backend-bfd/gumsymbolutil-bfd.c
backend_libs += \
	-lbfd
endif

container_sources = \
	gumarray.c \
	gumhash.c \
	gumlist.c

libgum_1_0_la_SOURCES = \
	gum.c \
	gumcodeallocator.c \
	guminterceptor.c \
	guminvocationcontext.c \
	guminvocationlistener.c \
	gumscript.c \
	gumscript-priv.h \
	gumscriptcompiler.h \
	gumtls.h \
	$(arch_sources) \
	$(container_sources) \
	$(backend_sources)
libgum_1_0_la_LIBADD = \
	$(arch_libs) \
	$(backend_libs) \
	$(GUM_LIBS)
libgum_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

AM_CPPFLAGS = \
	-include config.h \
	-I $(srcdir)/arch-arm \
	-I $(srcdir)/arch-x86 \
	$(GUM_CFLAGS)
