#!/bin/sh

build_os_arch=$1
host_os_arch=$2

build_arch=$(echo $build_os_arch | cut -d"-" -f2)
host_arch=$(echo $host_os_arch | cut -d"-" -f2)

envdir=`dirname $0`
outdir=/tmp

set -ex

mkdir -p $outdir/toolchain $outdir/native-sdk $outdir/cross-sdk
deps_url=https://build.frida.re/deps/20221111
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

case ${build_arch}__${host_arch} in
  x86_64__x86)
    needs_exe_wrapper=false
    ;;
  *)
    needs_exe_wrapper=true
    ;;
esac

$envdir/emit-$build_os_arch.sh $outdir/native-pkg-config false              > $outdir/native.txt
$envdir/emit-$host_os_arch.sh  $outdir/cross-pkg-config  $needs_exe_wrapper > $outdir/cross.txt
