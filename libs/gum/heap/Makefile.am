noinst_LTLIBRARIES = libfrida-gum-heap-1.0.la

fridaincludedir = $(includedir)/frida-1.0/gum/heap
fridainclude_HEADERS = \
	gumallocationblock.h \
	gumallocationgroup.h \
	gumallocationtracker.h \
	gumallocatorprobe.h \
	gumboundschecker.h \
	gumcobject.h \
	gumcobjecttracker.h \
	gumheapapi.h \
	guminstancetracker.h \
	gumpagepool.h \
	gumsanitychecker.h

libfrida_gum_heap_1_0_la_SOURCES = \
	gumallocationblock.c \
	gumallocationgroup.c \
	gumallocationtracker.c \
	gumallocatorprobe.c \
	gumboundschecker.c \
	gumcobject.c \
	gumcobjecttracker.c \
	gumheapapi.c \
	guminstancetracker.c \
	gumpagepool.c \
	gumsanitychecker.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	$(GUM_CFLAGS)
