if get_option('graft_tool') \
    .disable_auto_if(meson.is_subproject()) \
    .allowed()
  binary_metadata = [python, releng / 'binary_metadata.py']

  graft_sources = [
    'gumgraft.c',
    custom_target('gum-graft-metadata',
      output: 'gum-graft-metadata.c',
      command: binary_metadata + ['source', 'gum-graft', frida_version, host_abi, '@OUTPUT@'],
      depend_files: [releng / 'binary_metadata.py', releng / 'binary-metadata-assets' / 'metadata.c.in'],
    ),
  ]
  if host_os_family == 'windows'
    graft_sources += import('windows').compile_resources(custom_target('gum-graft-versioninfo',
      output: 'gum-graft.rc',
      command: binary_metadata + ['resource', 'executable', 'gum-graft', frida_version, '@OUTPUT@'],
      depend_files: [releng / 'binary_metadata.py', releng / 'binary-metadata-assets' / 'versioninfo.rc.in'],
    ))
  endif

  executable('gum-graft', graft_sources,
    dependencies: [gum_dep],
    install: true,
  )
endif
