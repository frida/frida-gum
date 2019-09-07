project('frida-gum', 'c', 'cpp',
  version: '1.0.0',
  default_options: ['c_std=gnu99', 'cpp_std=c++11'],
)

gum_version = meson.project_version()
api_version = '1.0'

host_os_family = host_machine.system()
host_os = host_os_family
if host_machine.cpu_family() == 'arm'
  host_arch = 'arm'
  if host_machine.cpu().endswith('hf')
    host_abi = 'armhf'
  else
    host_abi = 'arm'
  endif
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
  add_languages('objc', 'objcpp')
endif

cc = meson.get_compiler('c')

frida_component_cflags = []
buildtype = get_option('buildtype')
if buildtype == 'release' or buildtype == 'minsize'
  frida_component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

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

cdata = configuration_data()

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

headers = [
  'elf.h',
  'link.h',
  'stdint.h',
  'asm/prctl.h',
  'asm/ptrace.h',
  'sys/elf.h',
  'sys/user.h',
]
foreach h : headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

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

if cc.has_function('log2') and host_os != 'android'
  cdata.set('HAVE_LOG2', 1)
endif

if cc.has_member('struct mallinfo', 'arena', prefix: '#include <malloc.h>')
  cdata.set('HAVE_LIBC_MALLINFO', 1)
endif

asan_src = '''
#ifndef __SANITIZE_ADDRESS__
# ifdef __clang__
#  if __has_feature(address_sanitizer)
#   define __SANITIZE_ADDRESS__
#  endif
# endif
#endif
#ifndef __SANITIZE_ADDRESS__
# error ASAN disabled
#endif
'''
if cc.compiles(asan_src, name: 'compiling with ASan')
  cdata.set('HAVE_ASAN', 1)
endif

glib_dep = dependency('glib-2.0', version: '>=2.60')
gobject_dep = dependency('gobject-2.0')
gmodule_dep = dependency('gmodule-2.0')
gio_dep = dependency('gio-2.0')
capstone_dep = dependency('capstone')
ffi_dep = dependency('libffi')
lzma_dep = dependency('liblzma')

extra_deps = []
extra_requires_private = []
extra_libs_private = []

gumjs_extra_deps = []
gumjs_extra_requires = []
gumjs_extra_libraries = []

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
  have_libelf = cc.has_header('libelf.h')
  if not have_libelf
    error('libelf is required')
  endif
  have_libdwarf = cc.has_header('libdwarf.h')
  if not have_libdwarf
    error('libdwarf is required')
  endif
  if host_os_family == 'linux'
    extra_libs_private += ['-ldwarf', '-lelf', '-ldl', '-lz']
  else
    extra_libs_private += ['-ldwarf', '-lelf', '-lz']
  endif
else
  have_libdwarf = false
endif

if host_os_family == 'windows'
  tls_provider_dep = dependency('glib-schannel-static', required: false)
  if tls_provider_dep.found()
    cdata.set('HAVE_GLIB_SCHANNEL_STATIC', 1)
  endif
else
  tls_provider_dep = dependency('glib-openssl-static', required: false)
  if tls_provider_dep.found()
    cdata.set('HAVE_GLIB_OPENSSL_STATIC', 1)
  endif
endif

have_gumpp = not get_option('gumpp').disabled()
if have_gumpp
  cdata.set('HAVE_GUMPP', 1)
endif

have_gumjs = not get_option('gumjs').disabled()
if have_gumjs
  cdata.set('HAVE_GUMJS', 1)

  json_glib_dep = dependency('json-glib-1.0')
  sqlite_dep = dependency('sqlite3')
  libsoup_dep = dependency('libsoup-2.4')

  if host_os_family == 'windows'
    gio_os_package_name = 'gio-windows-2.0'
  else
    gio_os_package_name = 'gio-unix-2.0'
  endif
  gio_os_package_dep = dependency(gio_os_package_name)
  gumjs_extra_deps += [gio_os_package_dep]
  gumjs_extra_requires += [gio_os_package_name]

  if host_os_family == 'linux' or host_os_family == 'qnx'
    gumjs_extra_libraries += ['-lm']
  endif

  have_duktape = not get_option('duktape').disabled()
  if have_duktape
    cdata.set('HAVE_DUKTAPE', 1)
  endif

  v8_dep = dependency('v8-7.0', version: '>=7.6.48', required: get_option('v8'))
  have_v8 = v8_dep.found()
  if have_v8
    cdata.set('HAVE_V8', 1)
    gumjs_extra_deps += [v8_dep]
    gumjs_extra_requires += ['v8-7.0']
  endif

  if not (have_duktape or have_v8)
    error('Cannot build JavaScript bindings without any runtimes enabled')
  endif
else
  have_duktape = false
  have_v8 = false
endif

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

add_project_arguments(
  '-include', 'config.h',
  '-DG_LOG_DOMAIN="Frida"',
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

if host_os_family == 'linux' or host_os_family == 'qnx'
  gum_incdirs += [
    include_directories('gum/backend-elf'),
  ]
endif

install_header_basedir = 'frida-' + api_version
install_header_subdir = install_header_basedir + '/gum'

subdir('ext')
subdir('gum')
subdir('libs')
subdir('bindings')
subdir('vapi')

if get_option('tests')
  subdir('tests')
endif
