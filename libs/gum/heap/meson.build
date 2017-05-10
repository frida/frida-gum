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

gum_heap = static_library('frida-gum-heap', gum_heap_sources,
  include_directories: gum_incdirs,
  dependencies: [gum_dep, gmodule_dep],
)

gum_heap_dep = declare_dependency(link_with: gum_heap)
