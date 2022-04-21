#!/bin/sh

pkgconfig=$1
needs_exe_wrapper=$2

toolpfx=$QNX_HOST/usr/bin/arm-unknown-nto-qnx6.5.0eabi-
sysroot=$QNX_TARGET/armle-v7

cat << EOF
[constants]
base_flags = ['--sysroot=$sysroot', '-march=armv7-a']
c_like_flags = ['-mno-unaligned-access', '-ffunction-sections', '-fdata-sections']
linker_flags = ['-static-libgcc', '-Wl,--gc-sections']

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
system = 'qnx'
cpu_family = 'arm'
cpu = 'armv7'
endian = 'little'

[properties]
needs_exe_wrapper = $needs_exe_wrapper
EOF
