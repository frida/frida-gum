noinst_LTLIBRARIES = libgum-heap-1.0.la

gumincludedir = $(includedir)/gum-1.0/gum/heap
guminclude_HEADERS = \
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

noinst_HEADERS = \
	gumallocatorprobe-priv.h

libgum_heap_1_0_la_SOURCES = \
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
