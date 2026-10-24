if host_os_family != 'windows'
  test_function_filenames = []

  test_function_libraries = [
    'targetfunctions',
    'specialfunctions',
  ]

  if host_os_family == 'darwin'
    shlib_extension = 'dylib'
  else
    shlib_extension = 'so'
  endif

  if host_machine.endian() == 'big'
    if host_abi == 'arm' or host_abi == 'armhf'
      host_abi = 'armbe8'
    elif host_abi == 'arm64'
      host_abi = 'arm64be'
    endif
  endif

  foreach l : test_function_libraries
    name = '@0@-@1@-@2@.@3@'.format(l, host_os, host_abi, shlib_extension)
    test_function_filenames += [name]
  endforeach

  if host_os == 'linux' and host_arch == 'x86_64'
    test_function_filenames += [
      'module-registry-target-relocated-phdr-linux-x86_64.so',
    ]
  endif

  test_data = custom_target('gum-tests-data',
    input: test_function_filenames,
    output: test_function_filenames,
    command: ['cp', '@INPUT@', '@OUTDIR@'],
  )
  test_data_deps = [test_data]
  if host_os_family == 'linux'
    elfmapper_target_c_args = []
    elfmapper_target_link_args = []
    if host_os == 'android'
      elfmapper_target_c_args += '-fno-emulated-tls'
      elfmapper_target_link_args += [
        '-Wl,--unresolved-symbols=ignore-all',
        '-Wl,--pack-dyn-relocs=relr',
      ]
    endif
    test_data_deps += shared_library('elfmapper-target', 'elfmapper-target.c',
      name_prefix: '',
      c_args: elfmapper_target_c_args,
      link_args: elfmapper_target_link_args,
    )
  endif
  test_data_stamp = custom_target('gum-tests-data-stamp',
    input: test_data_deps,
    output: '.stamp',
    command: ['touch', '@OUTPUT@'],
  )

  prebuiltcmodule_link_args = []
  if host_is_prospero
    prebuiltcmodule_link_args += '-Wl,--unresolved-symbols=ignore-all'
  endif

  shared_module('prebuiltcmodule', 'prebuiltcmodule.c',
    name_prefix: '',
    link_args: prebuiltcmodule_link_args,
  )

  shared_module('module-registry-target', 'module-registry-target.c',
    name_prefix: '',
  )

  nonzero_vaddr_link_arg = '-Wl,-Ttext-segment=0x400000'
  if host_os == 'linux' and cc.has_link_argument(nonzero_vaddr_link_arg)
    shared_module('module-registry-target-nonzero-vaddr',
      'module-registry-target.c',
      name_prefix: '',
      link_args: nonzero_vaddr_link_arg,
    )
  endif
else
  test_data_stamp = []
endif

module_registry_dependency = shared_library('module-registry-dependency',
  'module-registry-dependency.c',
  name_prefix: '',
)
shared_module('module-registry-dependent', 'module-registry-dependent.c',
  name_prefix: '',
  link_with: module_registry_dependency,
)
