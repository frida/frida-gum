BUILT_SOURCES = script-runtime-stamp

lib_LTLIBRARIES = libfrida-gumjs-1.0.la
noinst_LTLIBRARIES = libfrida-gumjs.la

fridaincludedir = $(includedir)/frida-1.0/gumjs
fridainclude_HEADERS = \
	gumscript.h \
	gumscriptbackend.h \
	$(NULL)

v8_sources = \
	gumv8scriptbackend.h \
	gumv8scriptbackend.cpp \
	gumv8script.h \
	gumv8script.cpp \
	gumv8script-priv.h \
	gumv8platform.h \
	gumv8platform.cpp \
	gumv8bundle.h \
	gumv8bundle.cpp \
	gumv8scope.h \
	gumv8scope.cpp \
	gumv8core.h \
	gumv8core.cpp \
	gumv8kernel.h \
	gumv8kernel.cpp \
	gumv8memory.h \
	gumv8memory.cpp \
	gumv8process.h \
	gumv8process.cpp \
	gumv8thread.h \
	gumv8thread.cpp \
	gumv8module.h \
	gumv8module.cpp \
	gumv8file.h \
	gumv8file.cpp \
	gumv8socket.h \
	gumv8socket.cpp \
	gumv8interceptor.h \
	gumv8interceptor.cpp \
	gumv8stalker.h \
	gumv8stalker.cpp \
	gumv8eventsink.h \
	gumv8eventsink.cpp \
	gumv8symbol.h \
	gumv8symbol.cpp \
	gumv8instruction.h \
	gumv8instruction.cpp \
	$(NULL)

jsc_sources = \
	gumjscscriptbackend.h \
	gumjscscriptbackend.c \
	gumjscscript.h \
	gumjscscript.c \
	gumjscscript-priv.h \
	gumjscbundle.h \
	gumjscbundle.c \
	gumjscvalue.h \
	gumjscvalue.c \
	gumjscmacros.h \
	gumjsccore.h \
	gumjsccore.c \
	gumjscpolyfill.h \
	gumjscpolyfill.c \
	gumjscglue.cpp \
	gumjsckernel.h \
	gumjsckernel.c \
	gumjscmemory.h \
	gumjscmemory.c \
	gumjscprocess.h \
	gumjscprocess.c \
	gumjscthread.h \
	gumjscthread.c \
	gumjscmodule.h \
	gumjscmodule.c \
	gumjscfile.h \
	gumjscfile.c \
	gumjscsocket.h \
	gumjscsocket.c \
	gumjscinterceptor.h \
	gumjscinterceptor.c \
	gumjscstalker.h \
	gumjscstalker.c \
	gumjscsymbol.h \
	gumjscsymbol.c \
	gumjscinstruction.h \
	gumjscinstruction.c \
	$(NULL)
jsc_includes = \
	-I $(srcdir)/include/JavaScriptCore/API \
	-I $(srcdir)/include/JavaScriptCore/assembler \
	-I $(srcdir)/include/JavaScriptCore/bytecode \
	-I $(srcdir)/include/JavaScriptCore/disassembler \
	-I $(srcdir)/include/JavaScriptCore/heap \
	-I $(srcdir)/include/JavaScriptCore/icu \
	-I $(srcdir)/include/JavaScriptCore/interpreter \
	-I $(srcdir)/include/JavaScriptCore/jit \
	-I $(srcdir)/include/JavaScriptCore/llint \
	-I $(srcdir)/include/JavaScriptCore/parser \
	-I $(srcdir)/include/JavaScriptCore/profiler \
	-I $(srcdir)/include/JavaScriptCore/runtime \
	-I $(srcdir)/include/WTF \
	$(NULL)

platform_sources = $(NULL)
platform_cppflags = $(NULL)
platform_cxxflags = $(NULL)
platform_ldflags = $(NULL)
platform_libadd = $(NULL)

if OS_DARWIN
platform_sources += \
	$(jsc_sources) \
	$(NULL)
platform_cppflags += \
	$(jsc_includes) \
	$(GUMJSC_CFLAGS)
platform_cxxflags += \
	-fno-rtti \
	$(NULL)
platform_ldflags += \
	$(GUMJSC_LDFLAGS) \
	$(NULL)
platform_libadd += \
	$(GUMJSC_LIBS) \
	$(NULL)
endif

libfrida_gumjs_1_0_la_SOURCES = \
	$(NULL)
libfrida_gumjs_1_0_la_LDFLAGS = \
	-export-symbols-regex "^gum_.*" \
	$(GUMJS_LDFLAGS) \
	$(platform_ldflags) \
	$(NULL)
libfrida_gumjs_1_0_la_LIBADD = \
	libfrida-gumjs.la \
	$(GUMJS_LIBS) \
	$(platform_libadd) \
	$(NULL)
libfrida_gumjs_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared \
	$(NULL)

libfrida_gumjs_la_SOURCES = \
	gumscript.c \
	gumscriptbackend.c \
	gumscriptscheduler.h \
	gumscriptscheduler.c \
	gumscripttask.h \
	gumscripttask.c \
	$(v8_sources) \
	$(platform_sources) \
	$(NULL)
libfrida_gumjs_la_CXXFLAGS = \
	$(platform_cxxflags) \
	$(NULL)
libfrida_gumjs_la_LIBTOOLFLAGS = \
	--tag=disable-shared \
	$(NULL)

script_runtime_sources = \
	gumscript-core.js \
	gumscript-source-map.js \
	gumscript-java.js \
	gumscript-objc.js \
	gumscript-debug.js \
	$(NULL)

script-runtime-stamp: generate-runtime.py $(script_runtime_sources)
	@mkdir -p "$(@D)"
	python "$(srcdir)/generate-runtime.py" "$(srcdir)" "$(builddir)"
	@touch $@

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	-I $(top_srcdir)/bindings \
	$(GUMJS_CFLAGS) \
	$(platform_cppflags) \
	$(NULL)
