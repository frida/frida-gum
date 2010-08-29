lib_LTLIBRARIES = libgum.la

backend_sources =

if OS_DARWIN
backend_sources += backend-darwin/gumsymbolutil-darwin.c
endif

libgum_la_SOURCES = \
	gum.c \
	$(backend_sources)
libgum_la_LIBADD = \
	$(GUM_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	$(GUM_CFLAGS)
