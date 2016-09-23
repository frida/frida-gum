noinst_LTLIBRARIES = libgum-tests-gumjs.la

os_sources = $(NULL)

if OS_DARWIN
os_sources += \
	script-darwin.m \
	$(NULL)
endif

if OS_ANDROID
os_sources += \
	script-android.c \
	$(NULL)
endif

libgum_tests_gumjs_la_SOURCES = \
	script.c \
	kscript.c \
	$(os_sources) \
	$(NULL)
libgum_tests_gumjs_la_LIBTOOLFLAGS = \
	--tag=CC

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/bindings/gumjs \
	-I $(top_srcdir)/bindings \
	-I $(top_srcdir) \
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/tests \
	$(GUMJS_CFLAGS)
