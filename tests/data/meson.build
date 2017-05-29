test_function_filenames = []

test_function_libraries = [
  'targetfunctions',
  'specialfunctions',
]

if host_machine.cpu_family() == 'arm'
  if host_machine.cpu().endswith('hf')
    host_arch = 'armhf'
  else
    host_arch = 'arm'
  endif
elif host_machine.cpu_family() == 'mips'
  if host_machine.endian() == 'little'
    host_arch = 'mipsel'
  else
    host_arch = 'mips'
  endif
else
  host_arch = host_machine.cpu_family()
endif

if host_os_family == 'darwin'
  shlib_extension = 'dylib'
else
  shlib_extension = 'so'
endif

foreach l : test_function_libraries
  name = '@0@-@1@-@2@.@3@'.format(l, host_os, host_arch, shlib_extension)
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
