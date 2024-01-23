#!/bin/bash

gum_tests=$(dirname "$0")

runner_tarball=$(mktemp "/tmp/gum-tests.XXXXXX")

function dispose {
  rm -f "$runner_tarball"
}
trap dispose EXIT

set -ex

cd "$gum_tests/../../build"
. frida_thin-env-qnx-armeabi.rc

cd tmp_thin-qnx-armeabi/frida-gum
ninja

cd tests
tar -cf "$runner_tarball" gum-tests data/
/opt/sabrelite/run.sh "$runner_tarball" /opt/frida/gum-tests
