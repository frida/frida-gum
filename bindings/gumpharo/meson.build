gumpharo_primitives = custom_target('gumpharo-primitives',
  input: files('Gum-1.0.gir'),
  output: 'gumpharoprimitives.c',
  command: [python, files('generate-bindings.py'), '@INPUT@', '@OUTDIR@'],
)

gumpharo_headers = [
  'gumpharo.h',
]

install_headers(gumpharo_headers, subdir: install_header_basedir / 'gumpharo')

gumpharo_plugin_sources = [
  'gumpharo.c',
  'gumpharolistener.c',
  'gumpharomessage.c',
  gumpharo_primitives,
]

gumpharo_plugin = static_library('frida-gumpharo-plugin-' + api_version,
  gumpharo_plugin_sources,
  c_args: frida_component_cflags,
  include_directories: include_directories('.'),
  dependencies: [
    gum_dep,
    gio_dep,
    pharo_vm_dep.partial_dependency(includes: true, compile_args: true),
  ],
)

gumpharo_plugin_dep = declare_dependency(
  link_whole: gumpharo_plugin,
  include_directories: [bindings_inc, include_directories('.')],
  dependencies: [gum_dep, gio_dep, pharo_vm_dep],
)

gumpharo_host = executable('gum-pharo-host', 'host.c',
  dependencies: [gumpharo_plugin_dep],
)

freetype_dep = dependency('freetype2', required: false)
gumpharo_image_env = environment()
if freetype_dep.found() and freetype_dep.type_name() == 'pkgconfig'
  gumpharo_image_env.set('DYLD_FALLBACK_LIBRARY_PATH',
                         freetype_dep.get_variable('libdir'))
  gumpharo_image_env.set('LD_LIBRARY_PATH',
                         freetype_dep.get_variable('libdir'))
endif

gumpharo_image = custom_target('gumpharo-image',
  output: 'gum-pharo.image',
  command: [
    python,
    files('build-image.py'),
    '--host', gumpharo_host,
    '--handwritten', meson.current_source_dir() / 'pharo',
    '--generated-source', gumpharo_primitives,
    '--output', '@OUTPUT@',
  ],
  depends: [gumpharo_host, gumpharo_primitives],
  env: gumpharo_image_env,
)

gumpharo_image_packed = custom_target('gumpharo-image-packed',
  input: gumpharo_image,
  output: 'gum-pharo.image.gz',
  command: [python, files('compress-image.py'), '@INPUT@', '@OUTPUT@'],
)

gumpharo_image_dep = declare_dependency(sources: [gumpharo_image_packed])

gumpharo = static_library('frida-gumpharo-' + api_version,
  'gumpharoruntime.c',
  'gumpharoimage.S',
  c_args: frida_component_cflags + [
    '-DGUM_PHARO_IMAGE_PATH="' + gumpharo_image_packed.full_path() + '"',
  ],
  link_whole: gumpharo_plugin,
  dependencies: [
    gum_dep,
    gumpharo_image_dep,
    pharo_vm_dep.partial_dependency(includes: true, compile_args: true),
  ],
  install: true,
)

gumpharo_dep = declare_dependency(
  link_whole: gumpharo,
  include_directories: [bindings_inc, include_directories('.')],
  dependencies: [gum_dep, gio_dep, pharo_vm_dep],
)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-gumpharo-' + api_version,
  name: 'GumPharo',
  version: frida_version,
  description: 'Gum Pharo bindings',
  requires: ['frida-gum-' + api_version, 'pharo-vm'],
  subdirs: install_header_basedir,
  libraries: [gumpharo],
)

meson.override_dependency('frida-gumpharo-' + api_version, gumpharo_dep)
