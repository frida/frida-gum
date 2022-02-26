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

  foreach l : test_function_libraries
    name = '@0@-@1@-@2@.@3@'.format(l, host_os, host_abi, shlib_extension)
    test_function_filenames += [name]
  endforeach

  test_data = custom_target('gum-tests-data',
    input: test_function_filenames,
    output: test_function_filenames,
    command: ['cp', '@INPUT@', '@OUTDIR@'],
  )
  test_data_stamp = custom_target('gum-tests-data-stamp',
    input: [test_data],
    output: '.stamp',
    command: ['touch', '@OUTPUT@'],
  )

  shared_module('prebuiltcmodule', 'prebuiltcmodule.c',
    name_prefix: '',
  )
else
  test_data_stamp = []
endif
