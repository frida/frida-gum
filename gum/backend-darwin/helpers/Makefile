helpers := \
	build/fixupchainprocessor.dylib \
	$(NULL)

sources := \
	fixupchainprocessor.c \
	$(NULL)

ios_cc := $(shell xcrun --sdk iphoneos -f clang)
cflags := -Wall -Werror -pipe -Oz -g
ldflags := -Wl,-dead_strip

build: $(helpers)

build/%.dylib: %.c $(sources)
	@mkdir -p $(@D)
	$(ios_cc) \
		-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
		-arch arm64e \
		$(cflags) \
		-fno-ptrauth-calls \
		-fno-ptrauth-returns \
		-fno-stack-check \
		-fno-stack-protector \
		$< \
		-o $@ \
		-dynamiclib \
		$(ldflags)

.PHONY: build
