SUBDIRS = \
	gum \
	tests \
	vapi

pcfiles = \
        gum-1.0.pc

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

RURL := root@${IOS_IPADDR}
RPFX := /Developer/Frida

check: all
	ssh "${RURL}" "mkdir -p ${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/gum-tests" "${RURL}:${RPFX}/tests/"
	ssh "${RURL}" "${RPFX}/tests/gum-tests"
