KPM_BUILD_GOALS := all green.kpm build/green.kpm
ifeq ($(strip $(MAKECMDGOALS)),)
    NEED_KPM_BUILD := 1
else ifneq ($(filter $(KPM_BUILD_GOALS),$(MAKECMDGOALS)),)
    NEED_KPM_BUILD := 1
endif

ifdef NEED_KPM_BUILD
    ifndef TARGET_COMPILE
        $(error TARGET_COMPILE not set)
    endif
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

BUILD_DIR := build
TARGET := $(BUILD_DIR)/green.kpm
CLIENT := $(BUILD_DIR)/green
CC := $(TARGET_COMPILE)gcc

ANDROID_NDK ?= $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))
ANDROID_API ?= 35
NDK_HOST_TAG ?= darwin-x86_64
ANDROID_CC ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin/aarch64-linux-android$(ANDROID_API)-clang

LOCAL_INCLUDE_DIRS := include
KERNEL_INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(LOCAL_INCLUDE_DIRS),-I$(dir)) \
                 $(foreach dir,$(KERNEL_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS += -Os -fno-stack-protector -fno-builtin -nostdinc -fno-PIC \
          -mno-outline-atomics -mcmodel=large \
          -fno-asynchronous-unwind-tables -fno-unwind-tables

KPM_SRCS := green.c \
            common/symbol.c \
            emu/emu.c \
            hook/shadow_hook.c \
            hook/shadow_hook_pgtable.c \
            hook/shadow_hook_fault.c
KPM_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(KPM_SRCS))
KPM_HEADERS := $(wildcard include/*.h include/green/*.h)

.PHONY: all green.kpm
all: $(TARGET)

green.kpm: $(TARGET)

$(TARGET): $(KPM_OBJS)
	mkdir -p $(dir $@)
	$(CC) -r -o $@ $^

$(BUILD_DIR)/%.o: %.c $(KPM_HEADERS)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: client
client: $(CLIENT)

CLI_SRCS := cli/main.c common/common.c cli/shadow.c
CLI_HEADERS := include/green/abi.h include/green/cli.h include/green/shadow.h

$(CLIENT): $(CLI_SRCS) $(CLI_HEADERS)
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -static -s -O2 -Wall -Wextra -Iinclude -o $@ $(CLI_SRCS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f green.kpm green.o
