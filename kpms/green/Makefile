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

SERVER_SRCS := server/main.c common/common.c common/agentops.c server/server.c
CLI_HEADERS := include/green/abi.h include/green/cli.h include/green/shadow.h

$(CLIENT): $(SERVER_SRCS) $(CLI_HEADERS)
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -O2 -Wall -Wextra -Iinclude \
		-Igreen_hook/agent -o $@ $(SERVER_SRCS) -ldl

.PHONY: testhook
TESTHOOK := $(BUILD_DIR)/test_shadow_auth
TEST_DIR := test

testhook: $(TESTHOOK)

$(TESTHOOK): $(TEST_DIR)/test_shadow_auth.c include/green/abi.h
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	mkdir -p $(dir $@)
	$(ANDROID_CC) -D_GNU_SOURCE -static -s -O2 -Wall -Wextra \
		-Iinclude -o $@ $(TEST_DIR)/test_shadow_auth.c

.PHONY: agent
AGENT_PAYLOAD := $(BUILD_DIR)/libgreen_agent.so
# Payload: stock Frida GumJS + patched frida-java-bridge.  The payload talks
# to KPM shadow directly using the token provisioned by the root server; no
# broker, prelude or handwritten interceptor is linked.
agent: $(AGENT_PAYLOAD)


$(AGENT_PAYLOAD): green_hook/agent/green_agent_standard.c \
		green_hook/agent/green_shadow_client.c \
		green_hook/agent/gummemory-green-payload.c \
		green_hook/agent/green_agent.h \
		green_hook/agent/frida-java-bridge/fjb.iife.js \
		green_hook/agent/link-payload.sh
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK not set"; exit 1)
	@mkdir -p $(dir $@)
	ANDROID_NDK="$(ANDROID_NDK)" $(SHELL) green_hook/agent/link-payload.sh


.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f green.kpm green.o
