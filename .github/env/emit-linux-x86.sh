#!/bin/sh

pkgconfig=$1
needs_exe_wrapper=$2

cat << EOF
[constants]
c_like_flags = ['-ffunction-sections', '-fdata-sections']
linker_flags = ['-Wl,--gc-sections', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now']

[binaries]
c = ['gcc', '-m32']
cpp = ['g++', '-m32']
ar = 'ar'
nm = 'nm'
readelf = 'readelf'
strip = 'strip'
pkgconfig = '$pkgconfig'

[built-in options]
c_args = c_like_flags
cpp_args = c_like_flags
c_link_args = linker_flags
cpp_link_args = linker_flags

[host_machine]
system = 'linux'
cpu_family = 'x86'
cpu = 'i686'
endian = 'little'

[properties]
needs_exe_wrapper = $needs_exe_wrapper
EOF
