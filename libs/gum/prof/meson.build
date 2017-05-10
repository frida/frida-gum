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

host_cpu_is_intel = host_machine.cpu() == 'x86' or host_machine.cpu() == 'x86_64'

if host_cpu_is_intel and host_machine.system() != 'qnx'
  gum_prof_sources += ['gumcyclesampler-x86.c']
endif

if host_machine.system() == 'darwin'
  gum_prof_sources += ['gumbusycyclesampler-darwin.c']
  if not host_cpu_is_intel
    gum_prof_sources += ['gumcyclesampler-darwin.c']
  endif
endif

if host_machine.system() == 'linux'
  gum_prof_sources += ['gumbusycyclesampler-linux.c']
  if not host_cpu_is_intel
    gum_prof_sources += ['gumcyclesampler-linux.c']
  endif
endif

if host_machine.system() == 'qnx'
  gum_prof_sources += [
    'gumbusycyclesampler-qnx.c',
    'gumcyclesampler-qnx.c',
  ]
endif

install_headers(gum_prof_headers, subdir: install_header_subdir + '/prof')

gum_prof = static_library('frida-gum-prof', gum_prof_sources,
  include_directories: gum_incdirs,
  dependencies: [glib_dep, gobject_dep],
)

gum_prof_dep = declare_dependency(link_with: gum_prof)
