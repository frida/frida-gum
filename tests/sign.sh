#!/bin/sh

host_os="$1"
runner_binary="$2"
runner_entitlements="$3"
signed_runner_binary="$4"

if [ -z "$CODESIGN" ]; then
  echo "CODESIGN not set"
  exit 1
fi

case $host_os in
  macos)
    if [ -z "$MAC_CERTID" ]; then
      echo "MAC_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  ios)
    if [ -z "$IOS_CERTID" ]; then
      echo "IOS_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  *)
    echo "Unexpected host OS"
    exit 1
    ;;
esac

cp "$runner_binary" "$signed_runner_binary"

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MAC_CERTID" -i "re.frida.GumTests" "$signed_runner_binary" || exit 1
    ;;
  ios)
    "$CODESIGN" -f -s "$IOS_CERTID" --entitlements "$runner_entitlements" "$signed_runner_binary" || exit 1
    ;;
esac
