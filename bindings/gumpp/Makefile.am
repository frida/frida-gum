lib_LTLIBRARIES = libfrida-gumpp-1.0.la

fridaincludedir = $(includedir)/frida-1.0/gum
fridainclude_HEADERS = gumpp.hpp

## FIXME: generate this
libtool_export_options = -export-symbols-regex "^(Interceptor_obtain|Backtracer_make_default|ReturnAddressDetails_from_address|SanityChecker_new|SanityChecker_new_with_heap_api|BusyCycleSampler_new|CycleSampler_new|MallocCountSampler_new|WallClockSampler_new|CallCountSampler_new|CallCountSampler_new_by_name|Profiler_new|find_function_ptr|find_matching_functions_array)$$"

libfrida_gumpp_1_0_la_SOURCES =			\
	backtracer.cpp				\
	interceptor.cpp				\
	invocationcontext.hpp			\
	invocationlistener.cpp			\
	invocationlistener.hpp			\
	objectwrapper.hpp			\
	podwrapper.hpp				\
	profiler.cpp				\
	returnaddress.cpp			\
	sampler.cpp				\
	sanitychecker.cpp			\
	string.hpp				\
	symbolutil.cpp
libfrida_gumpp_1_0_la_LDFLAGS =			\
	$(libtool_export_options)		\
	$(GUM_LDFLAGS)
libfrida_gumpp_1_0_la_LIBADD =			\
	$(top_builddir)/gum/libfrida-gum.la	\
	$(GUM_LIBS)
libfrida_gumpp_1_0_la_LIBTOOLFLAGS =		\
	--tag=disable-static

AM_CPPFLAGS =					\
	-include config.h			\
	-I $(top_srcdir)			\
	-I $(top_srcdir)/libs			\
	-I $(top_srcdir)/libs/gum/heap		\
	-I $(top_srcdir)/libs/gum/prof		\
	$(GUM_CFLAGS)
