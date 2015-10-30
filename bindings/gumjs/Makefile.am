BUILT_SOURCES = script-runtime-stamp

lib_LTLIBRARIES = libfrida-gumjs-1.0.la
noinst_LTLIBRARIES = libfrida-gumjs.la

fridaincludedir = $(includedir)/frida-1.0/gumjs
fridainclude_HEADERS = \
	gumscript.h

v8_sources = \
	gumv8script.cpp \
	gumv8script-priv.h \
	gumv8script-runtime.h \
	gumscriptplatform.h \
	gumscriptplatform.cpp \
	gumscriptbundle.h \
	gumscriptbundle.cpp \
	gumscripttask.h \
	gumscripttask.c \
	gumscriptscope.h \
	gumscriptscope.cpp \
	gumscriptcore.h \
	gumscriptcore.cpp \
	gumscriptkernel.h \
	gumscriptkernel.cpp \
	gumscriptmemory.h \
	gumscriptmemory.cpp \
	gumscriptprocess.h \
	gumscriptprocess.cpp \
	gumscriptthread.h \
	gumscriptthread.cpp \
	gumscriptmodule.h \
	gumscriptmodule.cpp \
	gumscriptfile.h \
	gumscriptfile.cpp \
	gumscriptsocket.h \
	gumscriptsocket.cpp \
	gumscriptinterceptor.h \
	gumscriptinterceptor.cpp \
	gumscriptstalker.h \
	gumscriptstalker.cpp \
	gumscripteventsink.h \
	gumscripteventsink.cpp \
	gumscriptsymbol.h \
	gumscriptsymbol.cpp \
	gumscriptinstruction.h \
	gumscriptinstruction.cpp \
	$(NULL)

jsc_sources = \
	gumjscript.c \
	gumjscript-priv.h \
	gumjscript-runtime.h \
	gumjscriptbundle.h \
	gumjscriptbundle.c \
	gumscripttask.h \
	gumscripttask.c \
	gumjscriptvalue.h \
	gumjscriptvalue.c \
	gumjscriptmacros.h \
	gumjscriptcore.h \
	gumjscriptcore.c \
	gumjscriptpolyfill.h \
	gumjscriptpolyfill.c \
	gumjscriptglue.cpp \
	gumjscriptkernel.h \
	gumjscriptkernel.c \
	gumjscriptmemory.h \
	gumjscriptmemory.c \
	gumjscriptprocess.h \
	gumjscriptprocess.c \
	gumjscriptthread.h \
	gumjscriptthread.c \
	gumjscriptmodule.h \
	gumjscriptmodule.c \
	gumjscriptfile.h \
	gumjscriptfile.c \
	gumjscriptsocket.h \
	gumjscriptsocket.c \
	gumjscriptinterceptor.h \
	gumjscriptinterceptor.c \
	gumjscriptstalker.h \
	gumjscriptstalker.c \
	gumjscriptsymbol.h \
	gumjscriptsymbol.c \
	gumjscriptinstruction.h \
	gumjscriptinstruction.c \
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
	gumscript.h \
	gumscript.c \
	gumscriptbackend.h \
	gumscriptbackend.c \
	gumscriptscheduler.h \
	gumscriptscheduler.c \
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
	gumscript-runtime-core.js \
	gumscript-runtime-source-map.js \
	gumscript-runtime-java.js \
	gumscript-runtime-objc.js \
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
