#!/bin/sh

host_os=$1
host_arch=arm64

case $host_os in
  ios)
    device="ios-12.5.7-arm64"
    ;;
  android)
    device="android-8.1.0-arm64"
    ;;
  *)
    echo "Usage: $0 ios|android" > /dev/stderr
    exit 1
esac

if [ -z "$GH_TOKEN" ]; then
  echo "Missing GH_TOKEN environment variable" > /dev/stderr
  exit 1
fi

build_os=$(echo $(uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$,macos,'))
build_arch=$(uname -m)

gum_tests=$(dirname "$0")

runner_tarball=$(mktemp -t gum-tests.XXXXXX)
runner_script=$(mktemp -t gum-tests.XXXXXX)

marker="*** Finished with exit code: "

function dispose {
  rm -f "$runner_tarball"
  rm -f "$runner_script"
}
trap dispose EXIT

set -ex

cd "$gum_tests/../../build"
. frida-env-$build_os-$build_arch.rc

cd tmp-$host_os-$host_arch/frida-gum
ninja

cd tests
tar czf "$runner_tarball" gum-tests data/

case $host_os in
  ios)
    cat << EOF > "$runner_script"
cd /usr/local
rm -rf opt/frida
mkdir -p opt/frida
cd opt/frida
tar xf \$ASSET_PATH
./gum-tests
EOF
    ;;
  android)
    cat << EOF > "$runner_script"
cd /data/local/tmp
tar xf \$ASSET_PATH
./gum-tests
EOF
    ;;
esac

curl \
    https://corellium.frida.re/devices/$device \
    -F "token=$GH_TOKEN" \
    -F "asset=@$runner_tarball" \
    -F "script=<$runner_script" \
    -F "marker=$marker" \
    -v
