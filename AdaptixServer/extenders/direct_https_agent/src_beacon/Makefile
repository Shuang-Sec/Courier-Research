# 文件作用：Windows beacon 对象文件构建脚本：用 mingw 同时编译 x64/x86 的 agent C++ 对象。
# SOURCES 列出会被编译进 Windows agent 的 C++ 源文件。
SOURCES := \
	beacon/Agent.cpp \
	beacon/AgentConfig.cpp \
	beacon/AgentInfo.cpp \
	beacon/ApiLoader.cpp \
	beacon/Commander.cpp \
	beacon/ConnectorHTTP.cpp \
	beacon/Crypt.cpp \
	beacon/Downloader.cpp \
	beacon/Encoders.cpp \
	beacon/JobsController.cpp \
	beacon/MainAgent.cpp \
	beacon/MemorySaver.cpp \
	beacon/Packer.cpp \
	beacon/ProcLoader.cpp \
	beacon/WaitMask.cpp \
	beacon/crt.cpp \
	beacon/main.cpp \
	beacon/std.cpp \
	beacon/utils.cpp

CXX_X64 := x86_64-w64-mingw32-g++
CXX_X86 := i686-w64-mingw32-g++
ASM_SYNTAX := -masm=intel

BEACON_DIR := "beacon"
FILES_DIR := "files"
HTTP_DIST_DIR := "objects_http"

HTTP_OBJECTS_X64 := $(patsubst beacon/%.cpp, $(HTTP_DIST_DIR)/%.x64.o, $(SOURCES))
HTTP_OBJECTS_X86 := $(patsubst beacon/%.cpp, $(HTTP_DIST_DIR)/%.x86.o, $(SOURCES))

DIRECT_HTTPS_PROBE_STAGE ?= -1
DIRECT_HTTPS_LAZY_HTTP_SEND ?= 0
DIRECT_HTTPS_LAZY_WININET_INIT ?= 0
DIRECT_HTTPS_LITE_CONNECTOR ?= 0
DIRECT_HTTPS_WININET_INIT_ORDER ?= 0
DIRECT_HTTPS_SANDBOX_PROBE_STAGE ?= -1
DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ?= 0
DIRECT_HTTPS_REQUIRE_TRIGGER_FILE ?= 0
DIRECT_HTTPS_EXIT_BEFORE_SEND ?= 0
DIRECT_HTTPS_CAPTURE_PORT_8001 ?= 0
DIRECT_HTTPS_MEMORY_LOADER_DIAG ?= 0
DIRECT_HTTPS_CHECKIN_ONLY ?= 0
DIRECT_HTTPS_NO_API_HASHING ?= 1
DIRECT_HTTPS_MINIMAL_IDENTITY ?= 0
DIRECT_HTTPS_SKIP_UNUSED_API_INIT ?= 0
DIRECT_HTTPS_FAST_FIRST_LOOPS ?= 0
DIRECT_HTTPS_BEAT_DIALECT ?= 0
DIRECT_HTTPS_LEARNING_MINIMAL ?= 0
DIRECT_HTTPS_FILE_COMMANDS_ONLY ?= 0
DIRECT_HTTPS_HEARTBEAT_ONLY ?= 0
DIRECT_HTTPS_HELLO_ONLY ?= 0
DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS ?= 0
DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS ?= 0

SECURITY_FLAGS := -fno-stack-protector \
                 -fno-strict-overflow \
                 -fno-delete-null-pointer-checks \
                 -fno-strict-aliasing \
                 -fno-builtin

OPTIMIZATION_FLAGS := -fno-exceptions \
                     -fno-unwind-tables \
                     -fno-asynchronous-unwind-tables \
                     -ffunction-sections \
                     -fdata-sections

COMMON_FLAGS := -I $(BEACON_DIR) \
                -fpermissive \
                -w \
                $(ASM_SYNTAX) \
                -fPIC \
                -D DIRECT_HTTPS_CHECKIN_ONLY=$(DIRECT_HTTPS_CHECKIN_ONLY) \
                -D DIRECT_HTTPS_NO_API_HASHING=$(DIRECT_HTTPS_NO_API_HASHING) \
                -D DIRECT_HTTPS_MINIMAL_IDENTITY=$(DIRECT_HTTPS_MINIMAL_IDENTITY) \
                -D DIRECT_HTTPS_SKIP_UNUSED_API_INIT=$(DIRECT_HTTPS_SKIP_UNUSED_API_INIT) \
                -D DIRECT_HTTPS_PROBE_STAGE=$(DIRECT_HTTPS_PROBE_STAGE) \
                -D DIRECT_HTTPS_LAZY_HTTP_SEND=$(DIRECT_HTTPS_LAZY_HTTP_SEND) \
                -D DIRECT_HTTPS_LAZY_WININET_INIT=$(DIRECT_HTTPS_LAZY_WININET_INIT) \
                -D DIRECT_HTTPS_LITE_CONNECTOR=$(DIRECT_HTTPS_LITE_CONNECTOR) \
                -D DIRECT_HTTPS_WININET_INIT_ORDER=$(DIRECT_HTTPS_WININET_INIT_ORDER) \
                -D DIRECT_HTTPS_SANDBOX_PROBE_STAGE=$(DIRECT_HTTPS_SANDBOX_PROBE_STAGE) \
                -D DIRECT_HTTPS_DELAY_BEFORE_SEND_MS=$(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS) \
                -D DIRECT_HTTPS_REQUIRE_TRIGGER_FILE=$(DIRECT_HTTPS_REQUIRE_TRIGGER_FILE) \
                -D DIRECT_HTTPS_EXIT_BEFORE_SEND=$(DIRECT_HTTPS_EXIT_BEFORE_SEND) \
                -D DIRECT_HTTPS_CAPTURE_PORT_8001=$(DIRECT_HTTPS_CAPTURE_PORT_8001) \
                -D DIRECT_HTTPS_MEMORY_LOADER_DIAG=$(DIRECT_HTTPS_MEMORY_LOADER_DIAG) \
                -D DIRECT_HTTPS_FAST_FIRST_LOOPS=$(DIRECT_HTTPS_FAST_FIRST_LOOPS) \
                -D DIRECT_HTTPS_BEAT_DIALECT=$(DIRECT_HTTPS_BEAT_DIALECT) \
                -D DIRECT_HTTPS_LEARNING_MINIMAL=$(DIRECT_HTTPS_LEARNING_MINIMAL) \
                -D DIRECT_HTTPS_FILE_COMMANDS_ONLY=$(DIRECT_HTTPS_FILE_COMMANDS_ONLY) \
                -D DIRECT_HTTPS_HEARTBEAT_ONLY=$(DIRECT_HTTPS_HEARTBEAT_ONLY) \
                -D DIRECT_HTTPS_HELLO_ONLY=$(DIRECT_HTTPS_HELLO_ONLY) \
                -D DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS=$(DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS) \
                -D DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS=$(DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS) \
                $(SECURITY_FLAGS) \
                $(OPTIMIZATION_FLAGS)

.PHONY: all clean pre x64 x86

# C++ 编译器的单个进程会占用较多内存。默认使用单并行，避免在
# AdaptixClient 已经占用较多内存时由多个 cc1plus 同时触发系统 OOM。
# 需要加快本地构建时可通过 DIRECT_HTTPS_JOBS=2（或更高值）覆盖。
DIRECT_HTTPS_JOBS ?= 1
ifeq ($(MAKELEVEL), 0)
    MAKEFLAGS += -j$(DIRECT_HTTPS_JOBS) --no-print-directory
endif

# all 目标：清理旧对象，准备模板/stub，然后同时生成 x64 和 x86 对象文件。
all: clean pre x64 x86

# pre 目标：创建输出目录，并复制构建 payload 时需要的 config 模板和 stub。
pre:
	@mkdir -p $(HTTP_DIST_DIR)
	@cp $(FILES_DIR)/config.tpl $(HTTP_DIST_DIR)/config.cpp
	@cp $(FILES_DIR)/stub.x64.bin $(HTTP_DIST_DIR)/stub.x64.bin
	@cp $(FILES_DIR)/stub.x86.bin $(HTTP_DIST_DIR)/stub.x86.bin

# clean 目标：删除旧对象目录，避免链接到过期文件。
clean:
	@rm -rf $(HTTP_DIST_DIR) objects_smb objects_tcp objects_dns
	@mkdir -p $(HTTP_DIST_DIR)

# x64 目标：编译 64 位对象文件。
x64: $(HTTP_OBJECTS_X64)

# x86 目标：编译 32 位对象文件。
x86: $(HTTP_OBJECTS_X86)

$(HTTP_DIST_DIR)/%.x64.o: beacon/%.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_HTTP -c $< -o $@

$(HTTP_DIST_DIR)/%.x86.o: beacon/%.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_HTTP -c $< -o $@
