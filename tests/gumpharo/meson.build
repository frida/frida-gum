gumpharo_test_sources = [
  'gumpharo.c',
]

gum_tests_gumpharo = static_library('gum-tests-gumpharo', gumpharo_test_sources,
  include_directories: test_incdirs,
  dependencies: [gumpharo_dep],
)

gumpharo_test_image = custom_target('gumpharo-test-image',
  input: gumpharo_image,
  output: 'gum-pharo-tests.image',
  command: [
    python,
    files('build-test-image.py'),
    '--host', gumpharo_host,
    '--image', '@INPUT@',
    '--handwritten', meson.project_source_root() / 'bindings' / 'gumpharo'
                     / 'pharo',
    '--generated-source', gumpharo_primitives,
    '--tests', meson.current_source_dir() / 'pharo',
    '--output', '@OUTPUT@',
  ],
  depends: [gumpharo_host],
  env: gumpharo_image_env,
)

gumpharo_test_runner = '''| result |
result := GumImageTest suite run.
Stdio stdout << result printString; lf.
result hasPassed ifTrue: [ Smalltalk exitSuccess ] ifFalse: [
  (result failures , result errors) do: [ :each |
    Stdio stdout << 'FAILED: ' << each printString; lf ].
  Smalltalk exitFailure ]'''

test('gumpharo-image', gumpharo_host,
  args: ['--headless', gumpharo_test_image, 'eval', gumpharo_test_runner],
  depends: [gumpharo_test_image],
  env: gumpharo_image_env,
  timeout: 300,
)
