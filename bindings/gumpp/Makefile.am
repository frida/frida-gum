extra_ldflags =

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/gumpp.version
else
extra_ldflags += -export-symbols-regex "^(Interceptor_obtain|Backtracer_make_accurate|Backtracer_make_fuzzy|ReturnAddressDetails_from_address|SanityChecker_new|SanityChecker_new_with_heap_api|BusyCycleSampler_new|CycleSampler_new|MallocCountSampler_new|WallClockSampler_new|CallCountSampler_new|CallCountSampler_new_by_name|Profiler_new|find_function_ptr|find_matching_functions_array)$$"
endif

lib_LTLIBRARIES = \
	libfrida-gumpp-1.0.la \
	libfrida-gumpp-static-1.0.la

fridaincludedir = $(includedir)/frida-1.0/gumpp
fridainclude_HEADERS = gumpp.hpp

gumpp_sources = \
	backtracer.cpp				\
	interceptor.cpp				\
	invocationcontext.hpp			\
	invocationlistener.cpp			\
	invocationlistener.hpp			\
	objectwrapper.hpp			\
	podwrapper.hpp				\
	profiler.cpp				\
	returnaddress.cpp			\
	runtime.cpp				\
	runtime.hpp				\
	sampler.cpp				\
	sanitychecker.cpp			\
	string.hpp				\
	symbolutil.cpp

libfrida_gumpp_1_0_la_SOURCES =			\
	$(gumpp_sources)
libfrida_gumpp_1_0_la_LDFLAGS =			\
	$(extra_ldflags)			\
	$(GUM_LDFLAGS)
libfrida_gumpp_1_0_la_LIBADD =			\
	$(top_builddir)/gum/libfrida-gum.la	\
	$(GUM_LIBS)
libfrida_gumpp_1_0_la_LIBTOOLFLAGS =		\
	--tag=disable-static

libfrida_gumpp_static_1_0_la_SOURCES =		\
	$(gumpp_sources)
libfrida_gumpp_static_1_0_la_CFLAGS =		\
	-DGUMPP_STATIC
libfrida_gumpp_static_1_0_la_LDFLAGS =		\
	$(extra_ldflags)			\
	$(GUM_LDFLAGS)
libfrida_gumpp_static_1_0_la_LIBADD =		\
	$(top_builddir)/gum/libfrida-gum.la	\
	$(GUM_LIBS)
libfrida_gumpp_static_1_0_la_LIBTOOLFLAGS =	\
	--tag=disable-shared

AM_CPPFLAGS =					\
	-DG_LOG_DOMAIN=\"Frida\"		\
	-include config.h			\
	-I $(top_srcdir)			\
	-I $(top_srcdir)/libs			\
	-I $(top_srcdir)/libs/gum/heap		\
	-I $(top_srcdir)/libs/gum/prof		\
	$(GUM_CFLAGS)
