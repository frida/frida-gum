#!/bin/sh

src=$(dirname $0)
os=$1
arch=$2

if [ -z "$os" -o -z "$arch" ]; then
  echo "usage: $0 <os> <arch>"
  exit 1
fi

set -e

pushd $src/../../data > /dev/null
libdir=$(pwd)
popd > /dev/null

set -x

rm -rf build
meson setup \
    --cross-file $src/../../../../build/frida*-$os-$arch.txt \
    --libdir "$libdir" \
    --strip \
    -Dstem_suffix="-$os-$arch" \
    build
meson install -C build
