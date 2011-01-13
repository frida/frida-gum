ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	ext \
	libs \
	gum \
	tests \
	vapi

pcfiles = \
        gum-1.0.pc

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

if OS_IOS
RURL := root@${IOS_IPADDR}
RPFX := /Library/Frida

check: all
	ssh "${RURL}" "mkdir -p \"${RPFX}/tests/data/\" && rm -f \"${RPFX}/tests/gum-tests\" && rm -f \"${RPFX}/tests/data/targetfunctions-arm.dylib\" && rm -f \"${RPFX}/tests/data/specialfunctions-arm.dylib\""
	scp -Bq "$(top_builddir)/tests/gum-tests" "${RURL}:\"${RPFX}/tests/\""
	scp -Bq "$(top_builddir)/tests/data/targetfunctions-arm.dylib" "${RURL}:\"${RPFX}/tests/data/\""
	scp -Bq "$(top_builddir)/tests/data/specialfunctions-arm.dylib" "${RURL}:\"${RPFX}/tests/data/\""
	ssh "${RURL}" "\"${RPFX}/tests/gum-tests\""
endif
