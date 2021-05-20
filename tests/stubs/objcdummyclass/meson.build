objcdummyclass_sources = ['DummyClass.h', 'DummyClass.m']

gum_tests_objcdummyclass = static_library('objcdummyclass', objcdummyclass_sources)

custom_target('objcdummyclass-stripped',
  input: gum_tests_objcdummyclass,
  output: 'none',
  command: [
    'strip',
    '-x',
    '@INPUT@',
  ],
  build_by_default: true,
)
