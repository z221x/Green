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
            shadow/shadow.c \
            shadow/shadow_pgtable.c \
            shadow/shadow_fault.c
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

CLI_GUM_VENDOR_DIR := green_hook/vendor/gum
CLI_GUM_SHIM_FLAGS := -Igreen_hook/vendor -Igreen_hook/vendor/gum -Igreen_hook/shim
# gummemory-green.c doubles as the gum platform layer (page size, ptrauth,
# internal allocator, memory access) required to link the writer.
CLI_GUM_SRCS := green_hook/gummemory-green.c \
                $(CLI_GUM_VENDOR_DIR)/gumlibc.c \
                $(CLI_GUM_VENDOR_DIR)/gummetalarray.c \
                $(CLI_GUM_VENDOR_DIR)/gummetalhash.c \
                $(CLI_GUM_VENDOR_DIR)/arch-arm64/gumarm64writer.c
SERVER_SRCS := server/main.c common/common.c common/agentops.c server/server.c \
               $(CLI_GUM_SRCS)
CLI_HEADERS := include/green/abi.h include/green/cli.h include/green/shadow.h

$(CLIENT): $(SERVER_SRCS) $(CLI_HEADERS)
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -O2 -Wall -Wextra -Iinclude -Iagent \
		$(CLI_GUM_SHIM_FLAGS) -o $@ $(SERVER_SRCS) -ldl

.PHONY: testhook
TESTHOOK := $(BUILD_DIR)/test_hook

# green_hook 用例：验证 patch 执行 / 读原始 / 恢复 三条 gum 语义。
GUM_VENDOR_DIR := green_hook/vendor/gum
GUM_SHIM_FLAGS := -Igreen_hook/vendor -Igreen_hook/vendor/gum -Igreen_hook/shim
GUM_SRCS := green_hook/gummemory-green.c \
            $(GUM_VENDOR_DIR)/gumlibc.c \
            $(GUM_VENDOR_DIR)/gummetalarray.c \
            $(GUM_VENDOR_DIR)/gummetalhash.c \
            $(GUM_VENDOR_DIR)/arch-arm64/gumarm64writer.c

testhook: $(TESTHOOK)

$(TESTHOOK): tests/test_hook.c green_hook/green_gum.h $(GUM_SRCS) include/green/abi.h
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -static -s -O2 -Wall -Wextra -mbranch-protection=none \
		-Iinclude $(GUM_SHIM_FLAGS) -Igreen_hook -o $@ tests/test_hook.c $(GUM_SRCS)

.PHONY: agent
AGENT_PAYLOAD := $(BUILD_DIR)/libgreen_agent.so
# Payload: transport + embedded QuickJS (no gum).  Privileged page-table
# operations are performed by the root-side broker inside the green CLI.
GUM_PREFIX := vendor/prefix
agent: $(AGENT_PAYLOAD)

$(AGENT_PAYLOAD): agent/green_agent.c agent/green_agent.h
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -fPIC -shared -O2 -Wall -Wextra -pthread \
		-Iagent -I$(CURDIR)/$(GUM_PREFIX)/include/quickjs \
		-o $@ agent/green_agent.c $(GUM_PREFIX)/lib/libquickjs.a -lm -llog -pthread

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f green.kpm green.o
