gumpp_headers = [
  'gumpp.hpp',
]

gumpp_sources = [
  'backtracer.cpp',
  'interceptor.cpp',
  'invocationlistener.cpp',
  'profiler.cpp',
  'returnaddress.cpp',
  'runtime.cpp',
  'sampler.cpp',
  'sanitychecker.cpp',
  'symbolutil.cpp',
]

install_headers(gumpp_headers, subdir: install_header_basedir + '/gumpp')

gumpp = shared_library('frida-gumpp-@0@'.format(api_version), gumpp_sources,
  dependencies: [gum_dep],
  install: true,
)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-gumpp-@0@'.format(api_version),
  name: 'Gum++',
  version: gum_version,
  description: 'Gum C++ bindings',
  requires_private: ['frida-gum-@0@'.format(api_version)],
  subdirs: install_header_basedir,
  libraries: [gumpp],
)
