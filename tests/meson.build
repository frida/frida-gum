runner_sources = [
  'gumtest.c',
  'testutil.c',
  'stubs/dummyclasses.c',
  'stubs/fakebacktracer.c',
  'stubs/fakeeventsink.c',
  'lowlevel-helpers.c',
]

test_incdirs = [
  include_directories('.'),
  include_directories('stubs'),
]

subdir('core')
subdir('heap')
subdir('prof')
if get_option('enable_gumjs')
  subdir('gumjs')
else
  gum_tests_gumjs = []
endif

subdir('data')

extra_test_deps = []
extra_link_args = []

if get_option('enable_gumjs')
  extra_test_deps += [gumjs_dep]
endif

force_cpp_linking = get_option('enable_gumpp') or have_v8
if force_cpp_linking
  if host_machine.system() == 'darwin'
    # Work around Meson bug: https://github.com/mesonbuild/meson/issues/1766
    runner_sources += ['dummy.mm']
  else
    runner_sources += ['dummy.cpp']
  endif
endif

if host_os == 'macos'
  extra_link_args += ['-Wl,-framework,AppKit']
endif

if host_os == 'ios'
  extra_link_args += ['-Wl,-framework,Foundation']
endif

gum_tests = executable('gum-tests', runner_sources + [test_data_stamp],
  link_with: [
    gum_tests_core,
    gum_tests_heap,
    gum_tests_prof,
    gum_tests_gumjs,
  ],
  dependencies: [gum_dep, gum_heap_dep, gum_prof_dep] + extra_test_deps,
  link_args: extra_link_args,
)

test('Gum', gum_tests)
