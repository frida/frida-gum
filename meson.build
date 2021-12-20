project('frida-gum', 'c', 'cpp',
  version: '1.0.0',
  meson_version: '>=0.59.0',
  default_options: [
    'c_std=gnu99',
    'cpp_std=c++14',
    'cpp_eh=none',
    'cpp_rtti=false',
  ],
)

gum_version = meson.project_version()
api_version = '1.0'

host_os = host_machine.system()
if host_os == 'android'
  host_os_family = 'linux'
else
  host_os_family = host_os
endif
if host_machine.cpu_family() == 'arm'
  host_arch = 'arm'
  host_abi = 'arm'
elif host_machine.cpu_family() == 'aarch64'
  host_arch = 'arm64'
  host_abi = 'arm64'
elif host_machine.cpu_family() == 'mips'
  host_arch = 'mips'
  if host_machine.endian() == 'little'
    host_abi = 'mipsel'
  else
    host_abi = 'mips'
  endif
else
  host_arch = host_machine.cpu_family()
  host_abi = host_arch
endif

languages = ['c', 'cpp']
if host_os_family == 'darwin'
  languages += ['objc', 'objcpp']
  add_languages('objc', 'objcpp', native: false)
endif

cc = meson.get_compiler('c')

frida_component_cflags = []
ndebug = get_option('b_ndebug')
if ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))
  frida_component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

if host_arch == 'arm'
  is_hardfloat_src = '''
  #ifndef __ARM_PCS_VFP
  # error Not hardfloat
  #endif
  '''
  if cc.compiles(is_hardfloat_src, name: 'hardfloat ABI')
    host_abi = 'armhf'
  endif
endif

have_ptrauth_src = '''#ifdef __clang__
# if __has_feature (ptrauth_calls)
#  define HAVE_PTRAUTH 1
# endif
#endif

#ifndef HAVE_PTRAUTH
# error Pointer authentication not supported
#endif
'''
have_ptrauth = cc.compiles(have_ptrauth_src, name: 'pointer authentication')

target_conditionals_prefix = '#include <TargetConditionals.h>'

is_macos_src = target_conditionals_prefix + '''
#if !TARGET_OS_OSX
# error Not macOS
#endif
'''
if cc.compiles(is_macos_src, name: 'compiling for macOS')
  host_os = 'macos'
endif

is_ios_src = target_conditionals_prefix + '''
#if !TARGET_OS_IOS
# error Not iOS
#endif
'''
if cc.compiles(is_ios_src, name: 'compiling for iOS')
  host_os = 'ios'
endif

if cc.has_header('android/api-level.h')
  host_os = 'android'
endif

if host_arch == 'arm64' and have_ptrauth
  host_abi = 'arm64e'
endif

cdata = configuration_data()
cdata.set_quoted('GUM_VERSION', gum_version)

cdata.set('HAVE_' + host_os_family.to_upper(), 1)
if host_os != host_os_family
  cdata.set('HAVE_' + host_os.to_upper(), 1)
endif

cpu_defines = [
  ['x86', 'HAVE_I386'],
  ['x86_64', 'HAVE_I386'],
  ['arm', 'HAVE_ARM'],
  ['arm64', 'HAVE_ARM64'],
  ['mips', 'HAVE_MIPS'],
]
foreach d : cpu_defines
  if d.get(0) == host_arch
    cdata.set(d.get(1), 1)
  endif
endforeach

if have_ptrauth
  cdata.set('HAVE_PTRAUTH', 1)
endif

headers = [
  'elf.h',
  'link.h',
  'stdint.h',
  'sys/auxv.h',
  'sys/elf.h',
  'asm/ptrace.h',
  'sys/user.h',
]
foreach h : headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach
if cc.compiles('#include <asm/prctl.h>', name: 'asm/prctl.h is available')
  cdata.set('HAVE_ASM_PRCTL_H', 1)
endif

types = [
  'long double',
  'long long int',
  'unsigned long long int'
]
foreach t : types
  if cc.has_type(t)
    cdata.set('HAVE_' + t.underscorify().to_upper(), 1)
  endif
endforeach

glibc_src = '''
#include <features.h>

#if defined (__GLIBC__) && !defined (__UCLIBC__)
#else
# error Not glibc
#endif
'''
if cc.compiles(glibc_src, name: 'compiling for glibc')
  cdata.set('HAVE_GLIBC', 1)
endif

if cc.has_member('struct mallinfo', 'arena', prefix: '#include <malloc.h>')
  cdata.set('HAVE_LIBC_MALLINFO', 1)
endif

if get_option('b_sanitize') == 'address'
  cdata.set('HAVE_ASAN', 1)
endif

threads_dep = dependency('threads')
glib_dep = dependency('glib-2.0', version: '>=2.56')
gobject_dep = dependency('gobject-2.0')
gio_dep = dependency('gio-2.0')
capstone_dep = dependency('capstone', version: '>=5.0.0', fallback: ['capstone', 'capstone_dep'])
ffi_dep = dependency('libffi')

if get_option('tests')
  lzma_dep = dependency('liblzma')
else
  lzma_dep = []
endif

extra_deps = []
extra_requires_private = []
extra_libs_private = []
extra_gir_args_private = []

glib_flavor_src = '''
#include <glib.h>

#ifdef GLIB_STATIC_COMPILATION
# error GLib is static
#endif
'''
have_shared_glib = cc.compiles(glib_flavor_src, name: 'compiling with shared GLib', dependencies: [glib_dep])
if have_shared_glib
  gir = find_program('g-ir-scanner')
else
  gir = disabler()
endif

if cc.has_function('g_thread_set_callbacks', dependencies: [glib_dep])
  cdata.set('HAVE_FRIDA_GLIB', 1)
endif

if cc.has_function('ffi_set_mem_callbacks', dependencies: [ffi_dep])
  cdata.set('HAVE_FRIDA_LIBFFI', 1)
endif

if cc.has_function('pthread_attr_getstack',
    args: ['-D_GNU_SOURCE'],
    dependencies: [threads_dep],
    prefix: '#include <pthread.h>')
  cdata.set('HAVE_PTHREAD_ATTR_GETSTACK', 1)
endif

if host_os == 'linux'
  extra_libs_private += ['-ldl']
  extra_gir_args_private += ['--extra-library=dl']
endif

if host_os == 'android'
  extra_libs_private += ['-llog']
endif

unwind_dep = dependency('libunwind', required: false)
unwind_requires = []
if unwind_dep.found()
  cdata.set('HAVE_LIBUNWIND', 1)
  extra_deps += [unwind_dep]
  extra_requires_private += ['libunwind']
elif host_os_family == 'linux' or host_os_family == 'qnx'
  error('libunwind is required')
endif

if host_os_family == 'linux' or host_os_family == 'qnx'
  elf_dep = dependency('libelf')

  libdwarf_dep = dependency('libdwarf', required: false)
  if not libdwarf_dep.found()
    found = false
    foreach idir : ['/usr/include/libdwarf', '/usr/local/include/libdwarf']
      inc_arg = '-I' + idir
      if not found and cc.has_header('libdwarf.h', args: inc_arg)
        libdwarf_dep = declare_dependency(compile_args: [inc_arg])
        found = true
      endif
    endforeach
    if not found
      error('libdwarf is required')
    endif
  endif

  extra_deps += [elf_dep, libdwarf_dep]

  if host_os_family == 'linux'
    extra_libs_private += ['-ldwarf', '-ldl', '-lz']
    extra_gir_args_private += ['--extra-library=dwarf']
  else
    extra_libs_private += ['-ldwarf', '-lz']
  endif
else
  libdwarf_dep = disabler()
endif

if host_os == 'android'
  minizip_dep = dependency('minizip', required: false)
  if minizip_dep.found()
    cdata.set('HAVE_MINIZIP', 1)
    extra_deps += [minizip_dep]
    extra_requires_private += ['minizip']
  endif
endif

tls_provider_dep = dependency('gioopenssl', required: false)
if tls_provider_dep.found()
  cdata.set('HAVE_GIOOPENSSL', 1)
endif

have_gumpp = not get_option('gumpp').disabled()
if have_gumpp
  cdata.set('HAVE_GUMPP', 1)
endif

have_gumjs = not get_option('gumjs').disabled()
gumjs_extra_requires = []
if have_gumjs
  cdata.set('HAVE_GUMJS', 1)

  quickjs_dep = dependency('quickjs',
    required: get_option('quickjs'),
    fallback: ['quickjs', 'quickjs_dep'],
  )
  cdata.set('HAVE_QUICKJS', quickjs_dep.found())
  if quickjs_dep.found()
    gumjs_extra_requires += 'quickjs'
    quickjs_dep_native = dependency('quickjs', native: true)
  endif

  v8_dep = dependency('v8-8.0',
    version: '>=8.8.273',
    required: get_option('v8'),
  )
  cdata.set('HAVE_V8', v8_dep.found())
  if v8_dep.found()
    gumjs_extra_requires += 'v8-8.0'
  endif

  if not (quickjs_dep.found() or v8_dep.found())
    error('Cannot build JavaScript bindings without any runtimes enabled')
  endif

  if host_os_family == 'windows'
    gio_os_package_name = 'gio-windows-2.0'
  else
    gio_os_package_name = 'gio-unix-2.0'
  endif
  gio_os_package_dep = dependency(gio_os_package_name)
  gumjs_extra_requires += [gio_os_package_name]

  json_glib_dep = dependency('json-glib-1.0')

  libtcc_dep = dependency('libtcc',
    required: host_arch != 'mips',
    fallback: ['tinycc', 'tcc_dep'],
  )
  cdata.set('HAVE_TINYCC', libtcc_dep.found())

  sqlite_dep = dependency('sqlite3', required: get_option('database'))
  cdata.set('HAVE_SQLITE', sqlite_dep.found())

  if get_option('frida_objc_bridge').allowed()
    cdata.set('HAVE_OBJC_BRIDGE', 1)
  endif

  if get_option('frida_swift_bridge').allowed()
    cdata.set('HAVE_SWIFT_BRIDGE', 1)
  endif

  if get_option('frida_java_bridge').allowed()
    cdata.set('HAVE_JAVA_BRIDGE', 1)
  endif

  libsoup_dep = dependency('libsoup-2.4')
endif

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

add_project_arguments(
  '-include', meson.current_build_dir() / 'config.h',
  '-DG_LOG_DOMAIN="Frida"',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_56',
  '-DG_DISABLE_DEPRECATED',
  language: languages)

if host_os_family == 'linux'
  add_project_arguments('-D_GNU_SOURCE=1', language: languages)
endif

if host_os_family == 'qnx'
  add_project_arguments('-D_QNX_SOURCE=1', language: languages)
endif

gum_incdirs = [
  include_directories('.'),
  include_directories('gum'),
  include_directories('gum/arch-x86'),
  include_directories('gum/arch-arm'),
  include_directories('gum/arch-arm64'),
  include_directories('gum/arch-mips'),
  include_directories('libs'),
  include_directories('libs/gum/heap'),
  include_directories('libs/gum/prof'),
]

if host_os_family == 'darwin'
  gum_incdirs += [
    include_directories('gum/backend-darwin'),
  ]
endif

if host_os_family == 'linux' or host_os_family == 'qnx'
  gum_incdirs += [
    include_directories('gum/backend-elf'),
  ]
endif

install_header_basedir = 'frida-' + api_version
install_header_subdir = install_header_basedir + '/gum'

subdir('gum')
subdir('libs')
subdir('bindings')
subdir('vapi')
subdir('tools')

if get_option('tests')
  subdir('tests')
endif
