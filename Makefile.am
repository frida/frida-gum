RURL := root@${IOS_IPADDR}
RPFX := ${prefix}

SUBDIRS = \
	gum \
	tests

check: all
	ssh "${RURL}" "mkdir -p ${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/gum-tests" "${RURL}:${RPFX}/tests/"
	ssh "${RURL}" "${RPFX}/tests/gum-tests"
