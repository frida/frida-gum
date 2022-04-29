gum_prof_headers = [
  'gumbusycyclesampler.h',
  'gumcallcountsampler.h',
  'gumcyclesampler.h',
  'gummalloccountsampler.h',
  'gumprofiler.h',
  'gumprofilereport.h',
  'gumsampler.h',
  'gumwallclocksampler.h',
]

gum_prof_sources = [
  'gumcallcountsampler.c',
  'gummalloccountsampler.c',
  'gumprofiler.c',
  'gumprofilereport.c',
  'gumsampler.c',
  'gumwallclocksampler.c',
]

host_cpu_is_intel = host_arch in ['x86', 'x86_64']

if host_cpu_is_intel and host_os_family != 'qnx'
  gum_prof_sources += ['gumcyclesampler-x86.c']
endif

if host_os_family == 'windows'
  gum_prof_sources += 'gumbusycyclesampler-windows.c'
endif

if host_os_family == 'darwin'
  gum_prof_sources += 'gumbusycyclesampler-darwin.c'
  if not host_cpu_is_intel
    gum_prof_sources += 'gumcyclesampler-darwin.c'
  endif
endif

if host_os_family == 'linux'
  gum_prof_sources += 'gumbusycyclesampler-linux.c'
  if not host_cpu_is_intel
    gum_prof_sources += 'gumcyclesampler-linux.c'
  endif
endif

if host_os_family == 'freebsd'
  gum_prof_sources += 'gumbusycyclesampler-freebsd.c'
  if not host_cpu_is_intel
    gum_prof_sources += 'gumcyclesampler-freebsd.c'
  endif
endif

if host_os_family == 'qnx'
  gum_prof_sources += [
    'gumbusycyclesampler-qnx.c',
    'gumcyclesampler-qnx.c',
  ]
endif

install_headers(gum_prof_headers, subdir: install_header_subdir + '/prof')

gum_prof = library('frida-gum-prof-' + api_version, gum_prof_sources,
  c_args: frida_component_cflags,
  include_directories: gum_incdirs,
  dependencies: [gum_dep],
  install: true,
)

gum_prof_dep = declare_dependency(link_with: gum_prof)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-gum-prof-' + api_version,
  name: 'GumProf',
  version: gum_version,
  description: 'Profiling library built on top of Gum',
  requires: ['frida-gum-' + api_version],
  subdirs: install_header_basedir,
  libraries: [gum_prof],
)

meson.override_dependency('frida-gum-prof-' + api_version, gum_prof_dep)
