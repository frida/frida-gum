lib_LTLIBRARIES = libgum-1.0.la

gumincludedir = $(includedir)/gum-1.0/gum
guminclude_HEADERS = \
	gum.h \
	gumarray.h \
	gumbacktracer.h \
	gumcodeallocator.h \
	gumdefs.h \
	gumeventsink.h \
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

backend_sources =

if OS_DARWIN
backend_sources += backend-darwin/gumsymbolutil-darwin.c
endif

unix_sources = \
	backend-unix/dlmalloc.c \
	backend-unix/gummemory-unix.c

libgum_1_0_la_SOURCES = \
	gum.c \
	$(backend_sources) \
	$(unix_sources)
libgum_1_0_la_LIBADD = \
	$(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	$(GUM_CFLAGS)
