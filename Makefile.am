ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	ext \
	gum \
	tests \
	vapi

pcfiles = \
        gum-1.0.pc

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

RURL := root@${IOS_IPADDR}
RPFX := /Library/Frida

check: all
	ssh "${RURL}" "mkdir -p ${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/gum-tests" "${RURL}:${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/core/targetfunctions-arm.dylib" "${RURL}:${RPFX}/tests/targetfunctions.dylib"
	scp -Bq "$(top_builddir)/tests/core/specialfunctions-arm.dylib" "${RURL}:${RPFX}/tests/specialfunctions.dylib"
	ssh "${RURL}" "${RPFX}/tests/gum-tests"
