vapis = [
  'frida-gum-@0@.vapi'.format(api_version),
]

if host_os_family == 'darwin'
  vapis += ['frida-gum-darwin-@0@.vapi'.format(api_version)]
endif

if host_os_family == 'linux'
  vapis += ['frida-gum-linux-@0@.vapi'.format(api_version)]
endif

if get_option('enable_gumjs')
  vapis += ['frida-gumjs-@0@.vapi'.format(api_version)]
endif

install_data(vapis, install_dir: 'share/vala/vapi')
