#!/bin/sh

pkgconfig=$1
needs_exe_wrapper=$2

toolpfx=mips64el-linux-gnuabi64-

cat << EOF
[constants]
base_flags = ['-march=mips64r2', '-mabi=64']
c_like_flags = ['-ffunction-sections', '-fdata-sections']
linker_flags = ['-static-libgcc', '-Wl,--gc-sections', '-Wl,-z,noexecstack']

[binaries]
c = '${toolpfx}gcc'
cpp = '${toolpfx}g++'
ar = '${toolpfx}ar'
nm = '${toolpfx}nm'
readelf = '${toolpfx}readelf'
strip = '${toolpfx}strip'
pkgconfig = '$pkgconfig'

[built-in options]
c_args = base_flags + c_like_flags
cpp_args = base_flags + c_like_flags
c_link_args = base_flags + linker_flags
cpp_link_args = base_flags + linker_flags + ['-static-libstdc++']

[host_machine]
system = 'linux'
cpu_family = 'mips64'
cpu = 'mips64r2'
endian = 'little'

[properties]
needs_exe_wrapper = $needs_exe_wrapper
EOF
