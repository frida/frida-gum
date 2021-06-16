objcdummyclass = static_library('objcdummyclass', [
  'dummyclass.h',
  'dummyclass.m',
])

custom_target('objcdummyclass-stripped',
  input: objcdummyclass,
  output: 'none',
  command: [
    'strip',
    '-x',
    '@INPUT@',
  ],
  build_by_default: true,
)
