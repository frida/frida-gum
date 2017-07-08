gumjs_headers = [
  'gumscript.h',
  'gumscriptbackend.h',
]

gumjs_sources = [
  'gumscript.c',
  'gumscriptbackend.c',
  'gumscriptscheduler.c',
  'gumscripttask.c',
  'gumsourcemap.c',
  'gummemoryvfs.c',
  'sqlite3.c',
  'gumdukscriptbackend.c',
  'gumdukscript.c',
  'gumdukbundle.c',
  'gumdukvalue.c',
  'gumdukobject.c',
  'gumdukcore.c',
  'gumdukkernel.c',
  'gumdukmemory.c',
  'gumdukprocess.c',
  'gumdukthread.c',
  'gumdukmodule.c',
  'gumdukfile.c',
  'gumdukstream.c',
  'gumduksocket.c',
  'gumdukdatabase.c',
  'gumdukinterceptor.c',
  'gumdukstalker.c',
  'gumdukeventsink.c',
  'gumdukapiresolver.c',
  'gumduksymbol.c',
  'gumdukinstruction.c',
  'gumdukcompat.c',
  'duktape.c',
]

if have_v8
  gumjs_sources += [
    'gumv8scriptbackend.cpp',
    'gumv8script.cpp',
    'gumv8platform.cpp',
    'gumv8bundle.cpp',
    'gumv8scope.cpp',
    'gumv8value.cpp',
    'gumv8object.cpp',
    'gumv8core.cpp',
    'gumv8kernel.cpp',
    'gumv8memory.cpp',
    'gumv8process.cpp',
    'gumv8thread.cpp',
    'gumv8module.cpp',
    'gumv8file.cpp',
    'gumv8stream.cpp',
    'gumv8socket.cpp',
    'gumv8database.cpp',
    'gumv8interceptor.cpp',
    'gumv8stalker.cpp',
    'gumv8eventsink.cpp',
    'gumv8apiresolver.cpp',
    'gumv8symbol.cpp',
    'gumv8instruction.cpp',
  ]
endif

gumjs_runtime_sources = [
  'runtime/entrypoint-v8.js',
  'runtime/entrypoint-duktape.js',
  'runtime/core.js',
  'runtime/message-dispatcher.js',
  'runtime/error-handler-v8.js',
  'runtime/error-handler-duktape.js',
  'runtime/console.js',
  'runtime/hexdump.js',
  'runtime/promise.js',
  'runtime/objc.js',
  'runtime/java.js',
  'frida-debug.js',
]

gumjs_runtime_outputs = [
  'gumdukscript-runtime.h',
  'gumdukscript-promise.h',
  'gumdukscript-objc.h',
  'gumdukscript-java.h',
  'gumv8script-runtime.h',
  'gumv8script-objc.h',
  'gumv8script-java.h',
  'gumv8script-debug.h',
]

install_headers(gumjs_headers, subdir: install_header_basedir + '/gumjs')

gumjs_runtime = custom_target('gumjs-runtime',
  input: gumjs_runtime_sources,
  output: gumjs_runtime_outputs,
  command: [find_program('generate-runtime.py'), meson.current_source_dir(), meson.current_build_dir()],
)
gumjs_sources += [gumjs_runtime]

gumjs = library('frida-gumjs-' + api_version, gumjs_sources,
  include_directories: [bindings_inc],
  dependencies: [gum_dep, gio_dep, json_glib_dep, ffi_dep] + gumjs_extra_deps,
  install: true,
)

gumjs_dep = declare_dependency(link_with: gumjs,
  include_directories: [bindings_inc, include_directories('.')],
  dependencies: [gum_dep, gio_dep, json_glib_dep],
)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-gumjs-' + api_version,
  name: 'GumJS',
  version: gum_version,
  description: 'Gum JavaScript bindings',
  requires: ['frida-gum-' + api_version, 'json-glib-1.0'],
  requires_private: ['gio-2.0', 'libffi', 'capstone'] + gumjs_extra_requires,
  subdirs: install_header_basedir,
  libraries: [gumjs],
  libraries_private: gumjs_extra_libraries,
)
