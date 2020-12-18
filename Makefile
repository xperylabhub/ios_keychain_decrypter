GCC_BIN="`xcrun --sdk iphoneos --find clang`"
SDK="`xcrun --sdk iphoneos --show-sdk-path`"
ARCH_FLAGS=-arch arm64

LDFLAGS	=\
	-F$(SDK)/System/Library/Frameworks/\
	-framework Foundation\
	-framework Security\
	-framework IOKit\
	-I.

GCC_ARM = $(GCC_BIN) -Os -Wimplicit -isysroot $(SDK) $(ARCH_FLAGS)

keyclass_unwrapper: keyclass_unwrapper.c IOKit.c
	@$(GCC_ARM) $(LDFLAGS) -o $@ $^
	codesign -s - --entitlements Entitlements.plist $@

clean:
	rm -f keyclass_unwrapper *.o

