gnome = import('gnome')

gum_headers = [
  'gum.h',
  'gumapiresolver.h',
  'gumbacktracer.h',
  'gumcloak.h',
  'gumcodeallocator.h',
  'gumcodesegment.h',
  'gumdarwingrafter.h',
  'gumdarwinmodule.h',
  'gumdefs.h',
  'gumevent.h',
  'gumeventsink.h',
  'gumexceptor.h',
  'gumfunction.h',
  'gumheapapi.h',
  'guminterceptor.h',
  'guminvocationcontext.h',
  'guminvocationlistener.h',
  'gumkernel.h',
  'gumlibc.h',
  'gummemory.h',
  'gummemoryaccessmonitor.h',
  'gummemorymap.h',
  'gummetalarray.h',
  'gummetalhash.h',
  'gummoduleapiresolver.h',
  'gummodulemap.h',
  'gumprintf.h',
  'gumprocess.h',
  'gumreturnaddress.h',
  'gumspinlock.h',
  'gumstalker.h',
  'gumsymbolutil.h',
  'gumsysinternals.h',
  'gumtls.h',
]

gum_sources = [
  'gum.c',
  'gumapiresolver.c',
  'gumbacktracer.c',
  'gumcloak.c',
  'gumcodeallocator.c',
  'gumcodesegment.c',
  'gumdarwingrafter.c',
  'gumdarwinmodule.c',
  'gumexceptor.c',
  'gumeventsink.c',
  'gumheapapi.c',
  'guminterceptor.c',
  'guminvocationcontext.c',
  'guminvocationlistener.c',
  'gumkernel.c',
  'gumleb.c',
  'gumlibc.c',
  'gummemory.c',
  'gummemorymap.c',
  'gummetalarray.c',
  'gummetalhash.c',
  'gummoduleapiresolver.c',
  'gummodulemap.c',
  'gumprintf.c',
  'gumprocess.c',
  'gumreturnaddress.c',
  'gumstalker.c',
  'arch-x86/gumx86writer.c',
  'arch-x86/gumx86relocator.c',
  'arch-x86/gumx86reader.c',
  'arch-arm/gumarmwriter.c',
  'arch-arm/gumarmrelocator.c',
  'arch-arm/gumthumbwriter.c',
  'arch-arm/gumthumbrelocator.c',
  'arch-arm/gumarmreg.c',
  'arch-arm64/gumarm64writer.c',
  'arch-arm64/gumarm64relocator.c',
  'arch-mips/gummipswriter.c',
  'arch-mips/gummipsrelocator.c',
]

gum_backend_headers = []

if host_os_family == 'windows'
  gum_backend_headers += [
    'backend-windows/gumwindows.h',
    'backend-dbghelp/gumdbghelp.h',
    'backend-dbghelp/gumdbghelpbacktracer.h',
  ]
  gum_sources += [
    'backend-windows/gumexceptor-windows.c',
    'backend-windows/gummemory-windows.c',
    'backend-windows/gummemoryaccessmonitor-windows.c',
    'backend-windows/gumprocess-windows.c',
    'backend-windows/gumtls-windows.c',
    'backend-dbghelp/gumdbghelp.c',
    'backend-dbghelp/gumdbghelpbacktracer.c',
    'backend-dbghelp/gumsymbolutil-dbghelp.c',
  ]
else
  gum_sources += [
    'backend-posix/gummemoryaccessmonitor-posix.c',
  ]
endif

if host_os_family == 'darwin'
  gum_backend_headers += [
    'backend-darwin/gumdarwin.h',
    'backend-darwin/gumdarwinbacktracer.h',
    'backend-darwin/gumdarwinsymbolicator.h',
    'backend-darwin/gumdarwinmapper.h',
    'backend-darwin/gumdarwinmoduleresolver.h',
  ]
  gum_sources += [
    'backend-darwin/gumobjcapiresolver.c',
    'backend-darwin/gumobjcapiresolver.h',
    'backend-darwin/gumdarwinbacktracer.c',
    'backend-darwin/gumsymbolutil-darwin.c',
    'backend-darwin/gumdarwinsymbolicator.c',
    'backend-darwin/gumkernel-darwin.c',
    'backend-darwin/gumtls-darwin.c',
    'backend-darwin/gummemory-darwin.c',
    'backend-darwin/gumprocess-darwin.c',
    'backend-darwin/gumcodesegment-darwin.c',
    'backend-darwin/substratedclient.c',
    'backend-darwin/gumexceptor-darwin.c',
    'backend-darwin/gumdarwinmapper.c',
    'backend-darwin/gumdarwinmoduleresolver.c',
  ]
  if not diet
    gum_sources += [
      'backend-darwin/gumobjcdisposeclasspairmonitor.c',
    ]
  endif
endif

if host_os_family == 'linux'
  gum_backend_headers += [
    'backend-linux/gumlinux.h',
  ]
  gum_sources += [
    'backend-linux/gummemory-linux.c',
    'backend-posix/gummemory-posix.c',
    'backend-linux/gumprocess-linux.c',
    'backend-posix/gumtls-posix.c',
    'backend-posix/gumexceptor-posix.c',
  ]
  if host_os == 'android'
    gum_backend_headers += [
      'backend-linux/gumandroid.h',
    ]
    gum_sources += [
      'backend-linux/gumandroid.c',
    ]
  endif
endif

if host_os_family == 'freebsd'
  gum_backend_headers += [
    'backend-freebsd/gumfreebsd.h',
  ]
  gum_sources += [
    'backend-freebsd/gummemory-freebsd.c',
    'backend-posix/gummemory-posix.c',
    'backend-freebsd/gumprocess-freebsd.c',
    'backend-posix/gumtls-posix.c',
    'backend-posix/gumexceptor-posix.c',
  ]
endif

if host_os_family == 'qnx'
  gum_backend_headers += [
    'backend-qnx/gumqnx.h',
  ]
  gum_sources += [
    'backend-qnx/gumprocess-qnx.c',
    'backend-qnx/gummemory-qnx.c',
    'backend-posix/gummemory-posix.c',
    'backend-qnx/gumtls-qnx.c',
    'backend-posix/gumexceptor-posix.c',
  ]
endif

if host_executable_format == 'elf'
  gum_headers += [
    'backend-elf/gumelfmodule.h',
  ]
  gum_sources += [
    'backend-elf/gumelfmodule.c',
  ]
endif

gum_x86_headers = [
  'arch-x86/gumx86writer.h',
  'arch-x86/gumx86relocator.h',
  'arch-x86/gumx86reader.h',
]
if host_arch == 'x86' or host_arch == 'x86_64'
  gum_x86_headers += [
    'arch-x86/gumx86backtracer.h',
  ]
  gum_sources += [
    'arch-x86/gumx86backtracer.c',
    'backend-x86/gumcpucontext-x86.c',
    'backend-x86/guminterceptor-x86.c',
    'backend-x86/gumstalker-x86.c',
  ]
  if cc.get_argument_syntax() == 'msvc'
    if host_arch == 'x86'
      gum_sources += 'backend-x86/gumspinlock-ia32-msc.c'
    elif host_arch == 'x86_64'
      gum_sources += 'backend-x86/gumspinlock-amd64-msc.c'
    endif
  else
    gum_sources += [
      'backend-x86/gumspinlock-x86.c',
      'backend-x86/gumstalker-x86-glue.S',
    ]
  endif
endif

gum_arm_headers = [
  'arch-arm/gumarmwriter.h',
  'arch-arm/gumarmrelocator.h',
  'arch-arm/gumthumbwriter.h',
  'arch-arm/gumthumbrelocator.h',
  'arch-arm/gumarmreg.h',
]
if host_arch == 'arm'
  gum_arm_headers += [
    'arch-arm/gumarmbacktracer.h',
    'arch-arm/gumarmreader.h',
    'arch-arm/gumthumbreader.h',
  ]
  gum_sources += [
    'arch-arm/gumarmbacktracer.c',
    'arch-arm/gumarmreader.c',
    'arch-arm/gumthumbreader.c',
    'backend-arm/gumcpucontext-arm.c',
    'backend-arm/guminterceptor-arm.c',
    'backend-arm/gumspinlock-arm.c',
    'backend-arm/gumstalker-arm.c',
    'backend-arm/gumstalker-arm-glue.S',
  ]
endif

gum_arm64_headers = [
  'arch-arm64/gumarm64writer.h',
  'arch-arm64/gumarm64relocator.h',
]
if host_arch == 'arm64'
  gum_arm64_headers += [
    'arch-arm64/gumarm64backtracer.h',
    'arch-arm64/gumarm64reader.h',
  ]
  gum_sources += [
    'arch-arm64/gumarm64backtracer.c',
    'arch-arm64/gumarm64reader.c',
    'backend-arm64/gumcpucontext-arm64.c',
    'backend-arm64/guminterceptor-arm64.c',
    'backend-arm64/guminterceptor-arm64-glue.S',
    'backend-arm64/gumspinlock-arm64.c',
    'backend-arm64/gumstalker-arm64.c',
    'backend-arm64/gumstalker-arm64-glue.S',
  ]
endif

gum_mips_headers = [
  'arch-mips/gummipswriter.h',
  'arch-mips/gummipsrelocator.h',
]
if host_arch == 'mips'
  gum_mips_headers += [
    'arch-mips/gummipsbacktracer.h',
    'arch-mips/gummipsreader.h',
  ]
  gum_sources += [
    'arch-mips/gummipsbacktracer.c',
    'arch-mips/gummipsreader.c',
    'backend-mips/gumcpucontext-mips.c',
    'backend-mips/guminterceptor-mips.c',
    'backend-mips/gumspinlock-mips.c',
    'backend-mips/gumstalker-mips.c',
  ]
endif

if libunwind_dep.found()
  gum_backend_headers += [
    'backend-libunwind/gumunwbacktracer.h',
  ]
  gum_sources += [
    'backend-libunwind/gumunwbacktracer.c',
  ]
endif

if libdwarf_dep.found()
  gum_sources += [
    'backend-libdwarf/gumsymbolutil-libdwarf.c',
  ]
endif

install_headers(gum_headers + gum_backend_headers, subdir: install_header_subdir)
install_headers(gum_x86_headers, subdir: install_header_subdir + '/arch-x86')
install_headers(gum_arm_headers, subdir: install_header_subdir + '/arch-arm')
install_headers(gum_arm64_headers, subdir: install_header_subdir + '/arch-arm64')
install_headers(gum_mips_headers, subdir: install_header_subdir + '/arch-mips')

gum_enums = gnome.mkenums('gum-enum-types',
  sources: gum_headers,
  c_template: 'gumenumtypes.c.template',
  h_template: 'gumenumtypes.h.template',
  install_dir: get_option('includedir') / install_header_subdir,
  install_header: true,
)

gum_enums_dep = declare_dependency(sources: gum_enums)

gum_enum_h = gum_enums[1]

gum_public_deps = [glib_dep, capstone_dep, gum_enums_dep]
gum_internal_deps = [glib_dep, capstone_dep, threads_dep]
if not diet
  gum_public_deps += gobject_dep
  gum_internal_deps += gobject_dep
endif
if ffi_dep.found()
  gum_internal_deps += ffi_dep
endif

gum = library('frida-gum-' + api_version, gum_sources + gum_enums,
  c_args: frida_component_cflags,
  include_directories: gum_incdirs,
  link_args: extra_libs_private,
  dependencies: gum_internal_deps + extra_deps,
  install: true,
)

if gir.found()
  gir_args = [
    '--quiet',
    '-DGUM_GIR_COMPILATION',
  ]

  gnome.generate_gir(gum,
    sources: gum_sources + gum_headers + [gum_enum_h],
    namespace: 'Gum',
    nsversion: api_version,
    identifier_prefix: 'Gum',
    symbol_prefix: 'gum',
    export_packages: 'gum',
    includes: ['GLib-2.0', 'GObject-2.0', 'Gio-2.0'],
    header: 'gum/gum.h',
    extra_args: gir_args + extra_gir_args_private,
    install: true,
  )
endif

gum_dep = declare_dependency(link_with: gum,
  include_directories: gum_incdirs,
  compile_args: extra_cflags,
  link_args: extra_libs_private,
  dependencies: gum_public_deps,
)

pkg = import('pkgconfig')
pkg.generate(gum,
  filebase: 'frida-gum-' + api_version,
  name: 'Gum',
  version: gum_version,
  description: 'Low-level code instrumentation library',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'capstone'],
  requires_private: extra_requires_private,
  subdirs: install_header_basedir,
  extra_cflags: extra_cflags,
  libraries_private: extra_libs_private,
)

meson.override_dependency('frida-gum-' + api_version, gum_dep)
