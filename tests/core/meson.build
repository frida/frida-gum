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

if host_machine.system() == 'darwin'
  core_sources += [
    'interceptor-darwin.c',
    'exceptor-darwin.c',
  ]
endif

if host_os == 'macos'
  core_sources += [
    'arch-x86/stalker-x86-macos.m',
  ]
endif

if host_os == 'android'
  core_sources += [
    'interceptor-android.c',
  ]
endif

if host_machine.cpu() == 'x86' or host_machine.cpu() == 'x86_64'
  core_sources += [
    'arch-x86/stalker-x86.c',
  ]
endif

if host_machine.cpu() == 'arm64'
  core_sources += [
    'arch-arm64/stalker-arm64.c',
  ]
endif

gum_tests_core = static_library('gum-tests-core', core_sources,
  include_directories: test_incdirs,
  dependencies: [gum_dep],
)
