#!/bin/sh

pkgconfig=$1
needs_exe_wrapper=$2

sdk=macosx

cat << EOF
[constants]
common_flags = ['-target', 'x86_64-apple-macos10.9', '-isysroot', '$(xcrun --sdk $sdk --show-sdk-path)']
linker_flags = ['-Wl,-dead_strip']

[binaries]
c = ['$(xcrun --sdk $sdk -f clang)'] + common_flags
cpp = ['$(xcrun --sdk $sdk -f clang++)'] + common_flags
objc = ['$(xcrun --sdk $sdk -f clang)'] + common_flags
objcpp = ['$(xcrun --sdk $sdk -f clang++)'] + common_flags
strip = '$(xcrun --sdk $sdk -f strip)'
pkgconfig = '$pkgconfig'

[built-in options]
c_link_args = linker_flags
cpp_link_args = linker_flags

[host_machine]
system = 'darwin'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[properties]
needs_exe_wrapper = $needs_exe_wrapper
EOF
