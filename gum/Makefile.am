BUILT_SOURCES = $(NULL)

lib_LTLIBRARIES = libfrida-gum-1.0.la
noinst_LTLIBRARIES = libfrida-gum.la

fridaincludedir = $(includedir)/frida-1.0/gum
fridainclude_HEADERS = \
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
	gummemoryaccessmonitor.h \
	gummemorymap.h \
	gumprocess.h \
	gumreturnaddress.h \
	gumspinlock.h \
	gumstalker.h \
	gumsymbolutil.h \
	gumsysinternals.h

x86includedir = $(includedir)/frida-1.0/gum/arch-x86
x86include_HEADERS = \
	arch-x86/gumx86writer.h \
	arch-x86/gumx86relocator.h \
	arch-x86/gumx86reader.h

armincludedir = $(includedir)/frida-1.0/gum/arch-arm
arminclude_HEADERS = \
	arch-arm/gumarm.h \
	arch-arm/gumarmwriter.h \
	arch-arm/gumarmrelocator.h \
	arch-arm/gumthumbwriter.h \
	arch-arm/gumthumbrelocator.h

arm64includedir = $(includedir)/frida-1.0/gum/arch-arm64
arm64include_HEADERS = \
	arch-arm64/gumarm64.h \
	arch-arm64/gumarm64writer.h \
	arch-arm64/gumarm64relocator.h

libfrida_gum_1_0_la_SOURCES = $(NULL)
libfrida_gum_1_0_la_LDFLAGS = \
	-export-symbols-regex "^gum_.*" \
	$(GUM_LDFLAGS)
libfrida_gum_1_0_la_LIBADD = \
	libfrida-gum.la \
	$(GUM_LIBS)
libfrida_gum_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

arch_sources = $(NULL)
arch_includes = $(NULL)
arch_libs = $(NULL)
backend_sources = $(NULL)

if ARCH_I386
archincludedir = $(includedir)/frida-1.0/gum/arch-x86
archinclude_HEADERS = \
	arch-x86/gumx86backtracer.h
arch_sources += \
	arch-x86/gumx86backtracer.c
arch_includes += \
	-I $(srcdir)/arch-x86
backend_sources += \
	backend-x86/guminterceptor-x86.c \
	backend-x86/gumspinlock-x86.c \
	backend-x86/gumstalker-x86.c \
	backend-x86/gumstalker-x86-glue.S
endif

if ARCH_ARM
archincludedir = $(includedir)/frida-1.0/gum/arch-arm
archinclude_HEADERS = \
	arch-arm/gumarmbacktracer.h \
	arch-arm/gumarmreader.h
arch_sources += \
	arch-arm/gumarmbacktracer.c \
	arch-arm/gumarmreader.c
arch_includes += \
	-I $(srcdir)/arch-arm
backend_sources += \
	backend-arm/guminterceptor-arm.c \
	backend-arm/gumspinlock-arm.c \
	backend-arm/gumstalker-arm.c
endif

if ARCH_ARM64
archincludedir = $(includedir)/frida-1.0/gum/arch-arm64
archinclude_HEADERS = \
	arch-arm64/gumarm64backtracer.h
arch_sources += \
	arch-arm64/gumarm64backtracer.c
backend_sources += \
	backend-arm64/guminterceptor-arm64.c \
	backend-arm64/gumspinlock-arm64.c \
	backend-arm64/gumstalker-arm64.c
endif

if OS_LINUX
backend_sources += \
	backend-linux/gummemory-linux.c \
	backend-linux/gumprocess-linux.c
fridainclude_HEADERS += \
	backend-linux/gumlinux.h
endif

if OS_DARWIN
backend_sources += \
	backend-darwin/gumdarwinbacktracer.c \
	backend-darwin/gumsymbolutil-darwin.c \
	backend-darwin/gummemory-darwin.c \
	backend-darwin/gumprocess-darwin.c
fridainclude_HEADERS += \
	backend-darwin/gumdarwin.h \
	backend-darwin/gumdarwinbacktracer.h
else
backend_sources += \
	backend-posix/gummemory-posix.c
endif

if OS_QNX
backend_sources += \
	backend-qnx/gumprocess-qnx.c \
	backend-qnx/gummemory-qnx.c
fridainclude_HEADERS += \
	backend-qnx/gumqnx.h
endif

if HAVE_LIBUNWIND
backend_sources += \
	backend-libunwind/gumunwbacktracer.c
fridainclude_HEADERS += \
	backend-libunwind/gumunwbacktracer.h
endif

if HAVE_BFD
backend_sources += \
	backend-bfd/gumsymbolutil-bfd.c
endif

container_sources = \
	gumarray.c \
	gumhash.c \
	gumlist.c

libfrida_gum_la_SOURCES = \
	gum.c \
	gum-init.h \
	gumbacktracer.c \
	gumcodeallocator.c \
	gumeventsink.c \
	guminterceptor.c \
	guminvocationcontext.c \
	guminvocationlistener.c \
	gummemory.c \
	gummemorymap.c \
	gummetalhash.c \
	gummetalhash.h \
	gumprintf.c \
	gumprintf.h \
	gumprocess.c \
	gumreturnaddress.c \
	gumtls.h \
	arch-x86/gumx86writer.c \
	arch-x86/gumx86relocator.c \
	arch-x86/gumx86reader.c \
	arch-arm/gumarmwriter.c \
	arch-arm/gumarmrelocator.c \
	arch-arm/gumthumbwriter.c \
	arch-arm/gumthumbrelocator.c \
	arch-arm64/gumarm64writer.c \
	arch-arm64/gumarm64relocator.c \
	$(arch_sources) \
	$(container_sources) \
	$(backend_sources)
libfrida_gum_la_LIBADD = \
	$(top_builddir)/libs/gum/heap/libfrida-gum-heap-1.0.la \
	$(top_builddir)/libs/gum/prof/libfrida-gum-prof-1.0.la \
	$(arch_libs)
libfrida_gum_la_LIBTOOLFLAGS = \
	--tag=disable-shared

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(srcdir)/arch-arm64 \
	$(arch_includes) \
	$(GUM_CFLAGS)
