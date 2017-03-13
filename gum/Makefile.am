BUILT_SOURCES = $(NULL)

lib_LTLIBRARIES = libfrida-gum-1.0.la
noinst_LTLIBRARIES = libfrida-gum.la

fridaincludedir = $(includedir)/frida-1.0/gum
fridainclude_HEADERS = \
	gum.h \
	gumapiresolver.h \
	gumbacktracer.h \
	gumcloak.h \
	gumcodeallocator.h \
	gumcodesegment.h \
	gumdefs.h \
	gumevent.h \
	gumeventsink.h \
	gumexceptor.h \
	gumfunction.h \
	guminterceptor.h \
	guminvocationcontext.h \
	guminvocationlistener.h \
	gumkernel.h \
	gummemory.h \
	gummemoryaccessmonitor.h \
	gummemorymap.h \
	gummoduleapiresolver.h \
	gummodulemap.h \
	gumprocess.h \
	gumreturnaddress.h \
	gumspinlock.h \
	gumstalker.h \
	gumsymbolutil.h \
	gumsysinternals.h \
	gumtls.h

x86includedir = $(includedir)/frida-1.0/gum/arch-x86
x86include_HEADERS = \
	arch-x86/gumx86writer.h \
	arch-x86/gumx86relocator.h \
	arch-x86/gumx86reader.h

armincludedir = $(includedir)/frida-1.0/gum/arch-arm
arminclude_HEADERS = \
	arch-arm/gumarmwriter.h \
	arch-arm/gumarmrelocator.h \
	arch-arm/gumthumbwriter.h \
	arch-arm/gumthumbrelocator.h \
	arch-arm/gumarmreg.h

arm64includedir = $(includedir)/frida-1.0/gum/arch-arm64
arm64include_HEADERS = \
	arch-arm64/gumarm64writer.h \
	arch-arm64/gumarm64relocator.h

mipsincludedir = $(includedir)/frida-1.0/gum/arch-mips
mipsinclude_HEADERS = \
	arch-mips/gummipswriter.h \
	arch-mips/gummipsrelocator.h

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
	arch-arm/gumarmreader.h \
	arch-arm/gumthumbreader.h
arch_sources += \
	arch-arm/gumarmbacktracer.c \
	arch-arm/gumarmreader.c \
	arch-arm/gumthumbreader.c
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
	arch-arm64/gumarm64backtracer.h \
	arch-arm64/gumarm64reader.h
arch_sources += \
	arch-arm64/gumarm64backtracer.c \
	arch-arm64/gumarm64reader.c
backend_sources += \
	backend-arm64/guminterceptor-arm64.c \
	backend-arm64/gumspinlock-arm64.c \
	backend-arm64/gumstalker-arm64.c \
	backend-arm64/gumstalker-arm64-glue.S
endif

if ARCH_MIPS
archincludedir = $(includedir)/frida-1.0/gum/arch-mips
archinclude_HEADERS = \
	arch-mips/gummipsbacktracer.h \
	arch-mips/gummipsreader.h
arch_sources += \
	arch-mips/gummipsbacktracer.c \
	arch-mips/gummipsreader.c
arch_includes += \
	-I $(srcdir)/arch-mips
backend_sources += \
	backend-mips/guminterceptor-mips.c \
	backend-mips/gumspinlock-mips.c \
	backend-mips/gumstalker-mips.c
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
	backend-darwin/gumobjcapiresolver.c \
	backend-darwin/gumobjcapiresolver.h \
	backend-darwin/gumdarwinbacktracer.c \
	backend-darwin/gumsymbolutil-darwin.c \
	backend-darwin/gumkernel-darwin.c \
	backend-darwin/gumtls-darwin.c \
	backend-darwin/gummemory-darwin.c \
	backend-darwin/gumprocess-darwin.c \
	backend-darwin/gumcodesegment-darwin.c \
	backend-darwin/gumexceptor-darwin.c \
	backend-darwin/gumdarwinmapper.c \
	backend-darwin/gumdarwinmodule.c \
	backend-darwin/gumdarwinmoduleresolver.c
fridainclude_HEADERS += \
	backend-darwin/gumdarwin.h \
	backend-darwin/gumdarwinbacktracer.h \
	backend-darwin/gumdarwinmapper.h \
	backend-darwin/gumdarwinmodule.h \
	backend-darwin/gumdarwinmoduleresolver.h
else
if OS_QNX
backend_sources += \
	backend-qnx/gumprocess-qnx.c \
	backend-qnx/gummemory-qnx.c \
	backend-posix/gummemory-posix.c \
	backend-qnx/gumtls-qnx.c
fridainclude_HEADERS += \
	backend-qnx/gumqnx.h
else
backend_sources += \
	backend-posix/gumtls-posix.c \
	backend-posix/gummemory-posix.c
endif
backend_sources += \
	backend-posix/gumexceptor-posix.c
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

libfrida_gum_la_SOURCES = \
	gum.c \
	gum-init.h \
	gumapiresolver.c \
	gumbacktracer.c \
	gumcloak.c \
	gumcloak-priv.h \
	gumcodeallocator.c \
	gumcodesegment.c \
	gumexceptor.c \
	gumexceptorbackend.h \
	gumeventsink.c \
	guminterceptor.c \
	guminvocationcontext.c \
	guminvocationlistener.c \
	gumkernel.c \
	gumleb.c \
	gumleb.h \
	gumlibc.c \
	gumlibc.h \
	gummemory.c \
	gummemorymap.c \
	gummetalarray.c \
	gummetalarray.h \
	gummetalhash.c \
	gummetalhash.h \
	gummoduleapiresolver.c \
	gummodulemap.c \
	gumprintf.c \
	gumprintf.h \
	gumprocess.c \
	gumprocess-priv.h \
	gumreturnaddress.c \
	arch-x86/gumx86writer.c \
	arch-x86/gumx86relocator.c \
	arch-x86/gumx86reader.c \
	arch-arm/gumarmwriter.c \
	arch-arm/gumarmrelocator.c \
	arch-arm/gumthumbwriter.c \
	arch-arm/gumthumbrelocator.c \
	arch-arm/gumarmreg.c \
	arch-arm64/gumarm64writer.c \
	arch-arm64/gumarm64relocator.c \
	arch-mips/gummipswriter.c \
	arch-mips/gummipsrelocator.c \
	$(arch_sources) \
	$(backend_sources)
libfrida_gum_la_LIBADD = \
	$(top_builddir)/libs/gum/heap/libfrida-gum-heap-1.0.la \
	$(top_builddir)/libs/gum/prof/libfrida-gum-prof-1.0.la \
	$(arch_libs)
libfrida_gum_la_LIBTOOLFLAGS = \
	--tag=disable-shared

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir) \
	-I $(srcdir)/arch-arm64 \
	$(arch_includes) \
	$(GUM_CFLAGS)
