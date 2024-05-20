symsrv_prefix = get_option('prefix') / get_option('libdir') / 'frida'
uninstalled_symsrv_prefix = meson.current_source_dir()

if host_os_family == 'windows' and host_arch in ['x86', 'x86_64']
  symsrv_dll = files(host_cpu_mode / 'symsrv.dll')
  install_data(symsrv_dll, install_dir: symsrv_prefix / host_cpu_mode)
endif
