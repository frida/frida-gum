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

arch_sources = \
	arch-arm/gumthumbwriter.c \
	arch-arm/gumthumbwriter.h \
	arch-arm/gumthumbrelocator.c \
	arch-arm/gumthumbrelocator.h

container_sources = \
	gumarray.c \
	gumhash.c \
	gumlist.c

backend_sources =

if ARCH_I386
backend_sources += \
	backend-x86/guminterceptor-x86.c \
	backend-x86/gumscriptcompiler-x86.c
endif

if ARCH_ARM
backend_sources += \
	backend-arm/guminterceptor-arm.c \
	backend-arm/gumscriptcompiler-arm.c \
	backend-arm/gumspinlock-arm.c
endif

if OS_DARWIN
backend_sources += \
	backend-darwin/gummemory-darwin.c \
	backend-darwin/gumsymbolutil-darwin.c
endif

unix_sources = dlmalloc.c

libgum_1_0_la_SOURCES = \
	gum.c \
	gumcodeallocator.c \
	guminterceptor.c \
	guminvocationcontext.c \
	guminvocationlistener.c \
	gumscript.c \
	gumscript-priv.h \
	gumscriptcompiler.h \
	$(arch_sources) \
	$(container_sources) \
	$(backend_sources) \
	$(unix_sources)
libgum_1_0_la_LIBADD = \
	$(GUM_LIBS)
libgum_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

AM_CPPFLAGS = \
	-include config.h \
	-I $(srcdir)/arch-arm \
	$(GUM_CFLAGS)
