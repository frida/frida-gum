gumjs_sources = [
  'script.c',
  'kscript.c',
]

if host_machine.system() == 'darwin'
  gumjs_sources += [
    'script-darwin.m',
  ]
endif

gum_tests_gumjs = static_library('gum-tests-gumjs', gumjs_sources,
  include_directories: test_incdirs,
  dependencies: [gumjs_dep],
)
