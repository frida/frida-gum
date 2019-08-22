core_sources = [
  'tls.c',
  'cloak.c',
  'memory.c',
  'process.c',
  'symbolutil.c',
  'apiresolver.c',
  'backtracer.c',
  'interceptor.c',
  'arch-x86/codewriter.c',
  'arch-x86/relocator.c',
  'arch-arm/armwriter.c',
  'arch-arm/armrelocator.c',
  'arch-arm/thumbwriter.c',
  'arch-arm/thumbrelocator.c',
  'arch-arm64/arm64writer.c',
  'arch-arm64/arm64relocator.c',
]

if host_os_family == 'darwin'
  core_sources += [
    'interceptor-darwin.c',
    'exceptor-darwin.c',
  ]
endif

if host_os == 'android'
  core_sources += [
    'interceptor-android.c',
  ]
endif

if host_arch == 'x86' or host_arch == 'x86_64'
  core_sources += [
    'arch-x86/stalker-x86.c',
  ]
  if host_os == 'macos'
    core_sources += [
      'arch-x86/stalker-x86-macos.m',
    ]
  endif
endif

if host_arch == 'arm'
  core_sources += [
    'arch-arm/interceptor-arm.c',
  ]
endif

if host_arch == 'arm64'
  core_sources += [
    'arch-arm64/interceptor-arm64.c',
    'arch-arm64/stalker-arm64.c',
  ]
  if host_os_family == 'darwin'
    core_sources += [
      'arch-arm64/stalker-arm64-darwin.m',
    ]
  endif
endif

gum_tests_core = static_library('gum-tests-core', core_sources,
  include_directories: test_incdirs,
  dependencies: [gum_dep],
)

if host_os_family == 'darwin'
  symlist = 'mapper.symbols'
  executable('mapper-test', 'mapper.c',
    dependencies: [gum_dep],
    link_args: ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)],
    link_depends: [symlist],
  )
endif
