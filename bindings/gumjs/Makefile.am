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
	gumv8value.h \
	gumv8value.cpp \
	gumv8object.h \
	gumv8object.cpp \
	gumv8macros.h \
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
	gumv8stream.h \
	gumv8stream.cpp \
	gumv8socket.h \
	gumv8socket.cpp \
	gumv8interceptor.h \
	gumv8interceptor.cpp \
	gumv8stalker.h \
	gumv8stalker.cpp \
	gumv8eventsink.h \
	gumv8eventsink.cpp \
	gumv8apiresolver.h \
	gumv8apiresolver.cpp \
	gumv8symbol.h \
	gumv8symbol.cpp \
	gumv8instruction.h \
	gumv8instruction.cpp \
	$(NULL)

duk_sources = \
	gumdukscriptbackend.h \
	gumdukscriptbackend.c \
	gumdukscript.h \
	gumdukscript.c \
	gumdukscript-priv.h \
	gumdukbundle.h \
	gumdukbundle.c \
	gumdukvalue.h \
	gumdukvalue.c \
	gumdukobject.h \
	gumdukobject.c \
	gumdukmacros.h \
	gumdukcore.h \
	gumdukcore.c \
	gumdukkernel.h \
	gumdukkernel.c \
	gumdukmemory.h \
	gumdukmemory.c \
	gumdukprocess.h \
	gumdukprocess.c \
	gumdukthread.h \
	gumdukthread.c \
	gumdukmodule.h \
	gumdukmodule.c \
	gumdukfile.h \
	gumdukfile.c \
	gumdukstream.h \
	gumdukstream.c \
	gumduksocket.h \
	gumduksocket.c \
	gumdukinterceptor.h \
	gumdukinterceptor.c \
	gumdukstalker.h \
	gumdukstalker.c \
	gumduksampler.h \
	gumduksampler.c \
	gumdukapiresolver.h \
	gumdukapiresolver.c \
	gumduksymbol.h \
	gumduksymbol.c \
	gumdukinstruction.h \
	gumdukinstruction.c \
	gumdukcompat.h \
	gumdukcompat.c \
	duk_config.h \
	duktape.c \
	duktape.h \
	$(NULL)

backend_sources = $(NULL)
backend_cppflags = $(NULL)
backend_cxxflags = $(NULL)
backend_ldflags = $(NULL)
backend_libadd = $(NULL)

if HAVE_V8
backend_sources += $(v8_sources)
endif

backend_sources += $(duk_sources)

libfrida_gumjs_1_0_la_SOURCES = \
	$(NULL)
libfrida_gumjs_1_0_la_LDFLAGS = \
	-export-symbols-regex "^gum_.*" \
	$(GUMJS_LDFLAGS) \
	$(backend_ldflags) \
	$(NULL)
libfrida_gumjs_1_0_la_LIBADD = \
	libfrida-gumjs.la \
	$(GUMJS_LIBS) \
	$(backend_libadd) \
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
	gumsourcemap.h \
	gumsourcemap.c \
	$(backend_sources) \
	$(NULL)
libfrida_gumjs_la_CXXFLAGS = \
	$(backend_cxxflags) \
	$(NULL)
libfrida_gumjs_la_LIBTOOLFLAGS = \
	--tag=disable-shared \
	$(NULL)

script_runtime_sources = \
	runtime/entrypoint-v8.js \
	runtime/entrypoint-duktape.js \
	runtime/core.js \
	runtime/message-dispatcher.js \
	runtime/error-handler-v8.js \
	runtime/error-handler-duktape.js \
	runtime/console.js \
	runtime/hexdump.js \
	runtime/promise.js \
	runtime/objc.js \
	runtime/java.js \
	frida-debug.js \
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
	-I $(top_srcdir)/libs \
	-I $(top_srcdir)/libs/gum/prof \
	-I $(top_srcdir)/bindings \
	$(GUMJS_CFLAGS) \
	$(backend_cppflags) \
	$(NULL)
