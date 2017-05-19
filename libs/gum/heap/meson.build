gum_heap_headers = [
  'gumallocationblock.h',
  'gumallocationgroup.h',
  'gumallocationtracker.h',
  'gumallocatorprobe.h',
  'gumboundschecker.h',
  'gumcobject.h',
  'gumcobjecttracker.h',
  'gumheapapi.h',
  'guminstancetracker.h',
  'gumpagepool.h',
  'gumsanitychecker.h',
]

gum_heap_sources = [
  'gumallocationblock.c',
  'gumallocationgroup.c',
  'gumallocationtracker.c',
  'gumallocatorprobe.c',
  'gumboundschecker.c',
  'gumcobject.c',
  'gumcobjecttracker.c',
  'gumheapapi.c',
  'guminstancetracker.c',
  'gumpagepool.c',
  'gumsanitychecker.c',
]

install_headers(gum_heap_headers, subdir: install_header_subdir + '/heap')

gum_heap = library('frida-gum-heap-@0@'.format(api_version), gum_heap_sources,
  include_directories: gum_incdirs,
  dependencies: [gum_dep, gmodule_dep],
  install: true,
)

gum_heap_dep = declare_dependency(link_with: gum_heap)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-gum-heap-@0@'.format(api_version),
  name: 'GumHeap',
  version: gum_version,
  description: 'Heap instrumentation library built on top of Gum',
  requires: ['frida-gum-@0@'.format(api_version)],
  requires_private: ['gmodule-2.0'],
  subdirs: install_header_basedir,
  libraries: [gum_heap],
)
