lib_LTLIBRARIES = libgumpp-1.0.la

gumppincludedir = $(includedir)/gumpp-1.0
gumppinclude_HEADERS = gumpp.hpp

## FIXME: generate this
libtool_export_options = -export-symbols-regex "^(Interceptor_obtain|SanityChecker_new|SanityChecker_new_with_heap_api|BusyCycleSampler_new|CycleSampler_new|MallocCountSampler_new|WallClockSampler_new|CallCountSampler_new|CallCountSampler_new_by_name|Profiler_new|find_function_ptr|find_matching_functions_array)$$"

libgumpp_1_0_la_SOURCES =		\
	interceptor.cpp			\
	invocationcontext.hpp		\
	invocationlistener.cpp		\
	invocationlistener.hpp		\
	objectwrapper.hpp		\
	podwrapper.hpp			\
	profiler.cpp			\
	sampler.cpp			\
	sanitychecker.cpp		\
	string.hpp			\
	symbolutil.cpp
libgumpp_1_0_la_LDFLAGS =		\
	$(libtool_export_options)	\
	$(GUM_LDFLAGS)
libgumpp_1_0_la_LIBADD =		\
	$(top_builddir)/gum/libgum.la	\
	$(GUM_LIBS)
libgumpp_1_0_la_LIBTOOLFLAGS =		\
	--tag=disable-static

AM_CPPFLAGS =				\
	-include config.h		\
	-I $(top_srcdir)/libs		\
	-I $(top_srcdir)/libs/gum/heap	\
	-I $(top_srcdir)/libs/gum/prof	\
	$(GUM_CFLAGS)
