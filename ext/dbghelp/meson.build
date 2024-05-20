dbghelp_prefix = get_option('prefix') / get_option('libdir') / 'frida'
uninstalled_dbghelp_prefix = meson.current_source_dir()

if host_os_family == 'windows' and host_arch in ['x86', 'x86_64']
  dbghelp_dll = files(host_cpu_mode / 'dbghelp.dll')
  install_data(dbghelp_dll, install_dir: dbghelp_prefix / host_cpu_mode)
endif
