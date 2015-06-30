BUILT_SOURCES = script-runtime-stamp

lib_LTLIBRARIES = libfrida-gumjs-1.0.la
noinst_LTLIBRARIES = libfrida-gumjs.la

fridaincludedir = $(includedir)/frida-1.0/gumjs
fridainclude_HEADERS = \
	gumscript.h

libfrida_gumjs_1_0_la_SOURCES = $(NULL)
libfrida_gumjs_1_0_la_LDFLAGS = \
	-export-symbols-regex "^gum_.*" \
	$(GUMJS_LDFLAGS)
libfrida_gumjs_1_0_la_LIBADD = \
	libfrida-gumjs.la \
	$(GUMJS_LIBS)
libfrida_gumjs_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

libfrida_gumjs_la_SOURCES = \
	gumscript.cpp \
	gumscript-priv.h \
	gumscript-runtime.h \
	gumscriptplatform.h \
	gumscriptplatform.cpp \
	gumscriptbundle.h \
	gumscriptbundle.cpp \
	gumscriptscheduler.h \
	gumscriptscheduler.c \
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
	gumscriptinstruction.cpp
libfrida_gumjs_la_LIBTOOLFLAGS = \
	--tag=disable-shared

script_runtime_sources = \
	gumscript-runtime-core.js \
	gumscript-runtime-dalvik.js \
	gumscript-runtime-objc.js \
	gumscript-debug.js

script-runtime-stamp: generate-runtime.py $(script_runtime_sources)
	@mkdir -p "$(@D)"
	python "$(srcdir)/generate-runtime.py" "$(srcdir)" "$(builddir)"
	@touch $@

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir) \
	-I $(top_srcdir)/gum \
	$(GUMJS_CFLAGS)
