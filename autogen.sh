#!/bin/bash

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

pushd $srcdir &>/dev/null

if [ "$1" = "clean" ]; then
  [ -f "Makefile" ] && make maintainer-clean

  rm -f aclocal.m4 configure missing install-sh \
    depcomp ltmain.sh config.guess config.sub \
    config.h.in `find . -name Makefile.in` compile
  rm -rf autom4te.cache

  popd &>/dev/null
  exit 0
fi

# README and INSTALL are required by automake, but may be deleted by clean
# up rules. to get automake to work, simply touch these here, they will be
# regenerated from their corresponding *.in files by ./configure anyway.
touch README INSTALL

autoreconf -ifv
result=$?

popd &>/dev/null

[ $result -ne 0 ] && exit $result

./configure $*
