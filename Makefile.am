ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	libs \
	gum \
	bindings \
	tests \
	vapi

pcfiles = \
	frida-gum-1.0.pc

if ENABLE_GUMPP
pcfiles += \
	frida-gumpp-1.0.pc
endif

if ENABLE_GUMJS
pcfiles += \
	frida-gumjs-1.0.pc
endif

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

if OS_ANDROID
RPFX = /data/local/tmp
MKDIR = mkdir
RM = rm
DEBUG_PORT = 5042

if ARCH_I386
android_arch = x86
android_toolchain = x86-4.9
android_toolprefix = i686-linux-android
android_libdir = /system/lib
endif
if ARCH_ARM
android_arch = arm
android_toolchain = arm-linux-androideabi-4.9
android_toolprefix = arm-linux-androideabi
android_libdir = /system/lib
endif
if ARCH_ARM64
android_arch = arm64
android_toolchain = aarch64-linux-android-4.9
android_toolprefix = aarch64-linux-android
android_libdir = /system/lib64
endif

push: all
	adb shell "rm -rf \"${RPFX}/tests/\""
	adb shell "${MKDIR} \"${RPFX}/tests/\" && ${MKDIR} \"${RPFX}/tests/data/\""
	cp "$(top_builddir)/tests/gum-tests" "$(top_builddir)/tests/gum-tests.stripped"
	$$STRIP --strip-all "$(top_builddir)/tests/gum-tests.stripped"
	adb push "$(top_builddir)/tests/gum-tests.stripped" "${RPFX}/tests/gum-tests"
if ARCH_I386
	adb push "$(top_srcdir)/tests/data/targetfunctions-android-ia32.so" "${RPFX}/tests/data/"
	adb push "$(top_srcdir)/tests/data/specialfunctions-android-ia32.so" "${RPFX}/tests/data/"
endif
if ARCH_ARM
	adb push "$(top_srcdir)/tests/data/targetfunctions-android-arm.so" "${RPFX}/tests/data/"
	adb push "$(top_srcdir)/tests/data/specialfunctions-android-arm.so" "${RPFX}/tests/data/"
endif
if ARCH_ARM64
	adb push "$(top_srcdir)/tests/data/targetfunctions-android-arm64.so" "${RPFX}/tests/data/"
	adb push "$(top_srcdir)/tests/data/specialfunctions-android-arm64.so" "${RPFX}/tests/data/"
endif

check: push
	adb shell "\"${RPFX}/tests/gum-tests\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_NDK_ROOT}/prebuilt/android-$(android_arch)/gdbserver/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/gum-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	${ANDROID_NDK_ROOT}/prebuilt/darwin-x86_64/bin/gdb -x "$(top_builddir)/tests/android-gdb.setup"

pull:
	adb pull /system/bin/linker "$(top_builddir)/tests"
	adb pull $(android_libdir)/libc.so "$(top_builddir)/tests"
	adb pull $(android_libdir)/libstdc++.so "$(top_builddir)/tests"
	adb pull $(android_libdir)/libm.so "$(top_builddir)/tests"
	adb pull $(android_libdir)/libz.so "$(top_builddir)/tests"

$(top_builddir)/tests/android-gdb.setup: $(top_builddir)/tests/gum-tests
	echo "set solib-search-path $(abs_top_builddir)/tests:$(abs_top_srcdir)/tests/data:${ANDROID_SYSROOT}/usr/lib" > $@
	echo "directory ${ANDROID_SYSROOT}/usr/include" >> $@
	echo "directory $(abs_top_srcdir)/gum" >> $@
	echo "file $(abs_top_builddir)/tests/gum-tests" >> $@
	echo "target remote :${DEBUG_PORT}" >> $@
endif

if OS_IOS
RURL = root@${IOS_IPADDR}
RPFX = /Library/Frida
RSYNC = rsync -az

check: all
	ssh "${RURL}" "mkdir -p \"${RPFX}/tests/data/\""
	${RSYNC} \
		"$(top_builddir)/tests/gum-tests" \
		"${RURL}:\"${RPFX}/tests/\""
	${RSYNC} \
		"$(top_srcdir)/tests/data/targetfunctions-ios-arm.dylib" \
		"$(top_srcdir)/tests/data/targetfunctions-ios-arm64.dylib" \
		"$(top_srcdir)/tests/data/specialfunctions-ios-arm.dylib" \
		"$(top_srcdir)/tests/data/specialfunctions-ios-arm64.dylib" \
		"${RURL}:\"${RPFX}/tests/data/\""
	ssh "${RURL}" "\"${RPFX}/tests/gum-tests\""
endif
