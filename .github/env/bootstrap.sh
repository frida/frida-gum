#!/bin/sh

build_os_arch=$1
host_os_arch=$2

envdir=`dirname $0`
outdir=/tmp

set -ex

mkdir -p $outdir/toolchain $outdir/native-sdk $outdir/cross-sdk
deps_url=https://build.frida.re/deps/20220316
curl $deps_url/toolchain-$build_os_arch.tar.bz2 | tar -C $outdir/toolchain  -xjf -
curl $deps_url/sdk-$build_os_arch.tar.bz2       | tar -C $outdir/native-sdk -xjf -
curl $deps_url/sdk-$host_os_arch.tar.bz2        | tar -C $outdir/cross-sdk  -xjf -

for machine in native cross; do
  (
    echo "#!/bin/sh"
    echo "export PKG_CONFIG_PATH=$outdir/$machine-sdk/lib/pkgconfig"
    echo "exec $outdir/toolchain/bin/pkg-config --define-variable=frida_sdk_prefix=$outdir/$machine-sdk --static \"\$@\""
  ) > $outdir/$machine-pkg-config
  chmod +x $outdir/$machine-pkg-config
done

$envdir/emit-$build_os_arch.sh $outdir/native-pkg-config false > $outdir/native.txt
$envdir/emit-$host_os_arch.sh  $outdir/cross-pkg-config  true  > $outdir/cross.txt
