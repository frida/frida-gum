# Cross-platform mapper — handoff notes

**Temporary.** Remove this file (and its commit) before landing PR #1189.

Branch: `cross-platform-mapper` (frida/frida-gum). These notes let agents
on macOS and Linux pick up the parts that cannot be built or validated on
the Windows/arm64 host where the work was done.

## What is already done (CI-green on the full matrix, run 39685933484)

The full CI matrix is green, including the macOS native jobs (x86_64,
arm64, arm64e), which build and run gum-tests — so the Mach-O backend and
the `GumDarwinModuleResolver` retrofit are compiled and tested on a Mac.


A generic `GumMapper` facade that detects the binary format and dispatches
to a Mach-O / PE / ELF backend, plus a `GumModuleResolver` interface and a
cross-process `GumProcessMemory` memory accessor.

- `gum/gummapper.{c,h}` — facade (magic sniff → backend vtable).
- `gum/gummoduleresolver.{c,h}` — resolver interface.
- `gum/gumnativemoduleresolver.{c,h}` — in-process resolver (PE/ELF).
- `gum/gumpemodule.{c,h}` — portable PE parser.
- `gum/backend-windows/gumpemapper.{c,h}` — PE backend.
- `gum/gumelfmapper.{c,h}` — ELF backend.
- `gum/backend-darwin/gummachomapper.{c,h}` — Mach-O backend (renamed from
  `gumdarwinmapper`; `GumDarwinModule`→`GumMachoModule`, etc.).
- `gum/gumprocessmemory.{c,h}` — local/remote alloc/free/read/write/protect.

Tests: `tests/core/{pemapper,elfmapper,machomapper,processmemory}.c`,
registered in `tests/gumtest.c`. Build + run:

```
./configure --enable-gumpp --enable-gumjs --enable-tests && make
./build/tests/gum-tests -p /Core/PeMapper      # etc.
```

PE static TLS is complete: native x86/x64/arm64 and under ARM64 emulation,
local + remote + multiple modules. See the memory note `cross-platform-mapper`
for the emulation/TLS internals.

## Done — ELF mapper on every Linux arch and libc (Linux agent)

`gumelfmapper.c` emits its runtime stub (constructor, destructor, static
TLS accessor) on x86, x86_64, ARM, arm64 and MIPS (o32 and n64). Static
TLS no longer touches the mapper's own process: the stub carries a
per-module `__tls_get_addr` (`___tls_get_addr` on i386) backed by a
pthread key in a writable page after the stub's code, created by the
constructor and deleted by the destructor. arm64 toolchains default to
TLS descriptors, so `R_AARCH64_TLSDESC` slots point at a resolver in the
stub that wraps the accessor and returns a thread-pointer offset. MIPS
has no relocation records for its global GOT, so the mapper fills it
from `DT_PLTGOT`/`DT_MIPS_LOCAL_GOTNO`/`DT_MIPS_GOTSYM`, and applies the
0x8000 DTP bias. Relocation processing picks REL vs RELA semantics per
ABI. `pthread_*`, `calloc`, `memcpy`, `free` are resolved through the
`GumModuleResolver`, so a remote target needs a resolver that yields that
target's addresses.

RELR-packed relative relocations (`SHT_RELR` and `SHT_ANDROID_RELR`) are
applied too; lld emits them for modern Android modules. Gum must keep
working on Android API 21, so the mapper only relies on API 21 bionic
symbols, and the Android test target is linked at API 21 with
`-fno-emulated-tls`, `--pack-dyn-relocs=relr` and
`--unresolved-symbols=ignore-all` (bionic 21 has no `__tls_get_addr`; the
mapper satisfies that import itself).

Fixed along the way: `gummipswriter.c` BEQ opcode and label offset,
MIPS64 ADDU encoding (was OR), new `lw32` helper; `gumelfmodule.c`
MIPS64 `r_info` parsing.

Tests: `Core/ElfMapper/*` are registered on every Linux arch, including
Android. The target library is built into `tests/data/` so it travels
with `gum-tests`. The remote tests fork a victim so the native resolver's
addresses stay valid; they skip where `process_vm_writev` is unavailable
(qemu-user).

Verified 2026-10-22, in-process tests pass everywhere; remote tests pass
where marked:

| flavor            | runtime                                   | remote |
|-------------------|-------------------------------------------|--------|
| linux-x86_64      | native                                    | yes    |
| linux-x86         | x-tools container, sysroot loader, native | yes    |
| linux-x86_64-musl | x-tools container, musl loader, native    | yes    |
| linux-arm64       | qemu-aarch64 in container                 | skip   |
| linux-arm64be     | qemu-aarch64_be in container              | skip   |
| linux-armhf       | qemu-arm in container                     | skip   |
| linux-armbe8      | qemu-armeb in container                   | skip   |
| linux-mipsel      | multiarch/debian-debootstrap:mipsel-buster| skip   |
| linux-mips        | multiarch/debian-debootstrap:mips-buster  | skip   |
| linux-mips64el    | multiarch/debian-debootstrap:mips64el-buster | skip |
| android-arm64     | Pixel 10 via adb (bionic, TLSDESC)        | yes    |
| android-x86_64    | AVD android-30 google_apis x86_64 (KVM)   | yes    |
| android-x86       | AVD android-30 google_apis x86 (KVM)      | yes    |
| android-arm       | AVD android-25 google_apis armeabi-v7a, emulator 30.3.5 | yes |

Not verified: linux-arm64-musl builds, but `gum_init` fails under
qemu-user with "Unable to locate the libc" (libc detection, not the
mapper). linux-mips64 (big-endian) builds; no runtime available. The
x-tools MIPS sysroots ship glibc 2.5 whose libpthread hangs `dlsym`
under qemu-user, hence the Debian buster containers (only `libatomic.so.1`
is borrowed from the sysroot).

android-arm: the current emulator (37.x) refuses 32-bit arm system
images, so the arm AVD runs on emulator 30.3.5 (build 7033400, the
oldest still downloadable from Google's repository), installed as
`~/.local/opt/android-sdk/emulator-30.3.5`. It needs an (empty)
`$SDK/platforms` directory to exist, boots the android-25 armeabi-v7a
image in under two minutes, and `adb` works as usual.

Android SDK for the AVDs lives in `~/.local/opt/android-sdk` (JDK in
`~/.local/opt/jdk17`, AVDs in `~/.config/.android/avd`, named
`gum-<abi>`). Run headless: `emulator -avd gum-x86_64 -port 5554
-no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect`,
then `adb -s emulator-5554 push build/android-x86_64/tests/{gum-tests,data}
/data/local/tmp/gum/` and run `gum-tests -p /Core/ElfMapper` there.

How to build and run a flavor: `mkdir -p build/<flavor> && cd
build/<flavor> && ../../configure --host=<host> --enable-tests && ninja`,
inside `ghcr.io/frida/x-tools-linux-<arch>:latest` with the repo mounted
(`--host=$XTOOLS_HOST`; add `--without-prebuilds=sdk:host` for armbe8 and
arm64be), or on the host with `ANDROID_NDK_ROOT` set for
`--host=android-arm64`. Run `build/<flavor>/tests/gum-tests -p
/Core/ElfMapper` under the matching runtime from the table.

`GumProcessMemory` is an interface (alloc/alloc_near/free/read/write/
protect/mark_code). `GumNativeProcessMemory` is gum's provider: local, or remote via
ReadProcessMemory/mach_vm/process_vm_*; on Linux its remote `protect`,
`mark_code`, `alloc` and `free` fail since they need code execution in
the target, so the remote tests pre-allocate the region as RWX before
forking. frida-core is meant to pass its own implementation (ptrace,
or its driver where present). Mappers never run code in the target
themselves: everything that must execute there is emitted into the
runtime and runs when the consumer calls the constructor. The PE
mapper's emulated-x64 TLS path therefore creates its loader thread from
the constructor, and only needs `alloc_near` from the provider for the
BaseThreadInitThunk hook region.

## TODO 2 — Adopt GumProcessMemory in frida-core  (separate repo)

frida-core already has its own process_vm_* logic; `GumProcessMemory` is the
intended public replacement. Port core to it. Out of scope for this repo.
