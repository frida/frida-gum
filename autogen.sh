#!/bin/bash

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

pushd $srcdir &>/dev/null

if [ "$1" = "clean" ]; then
  [ -f "Makefile" ] && make maintainer-clean

  rm -f INSTALL README aclocal.m4 compile config.guess config.h \
    config.h.in config.log config.status config.sub configure depcomp \
    gum-1.0.pc install-sh libtool ltmain.sh missing stamp-h1 \
    `find . -name Makefile` `find . -name Makefile.in`
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

if [ $result -eq 0 ] && [ "$(uname -s)" == "Darwin" ] || [ "$(uname -s)" == "Linux" ]; then
  pushd bindings/gumjs/ &>/dev/null
  npm install
  result=$?
  popd &>/dev/null
fi

popd &>/dev/null

exit $result
