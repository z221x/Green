# Green

Green 是一个基于 KernelPatch Module (KPM) 的 ARM64 逆向工具集。项目采用“核心框架 + 工具模块 + CLI 子命令”的结构，后续可以继续增加新的工具，并允许工具之间复用公共 API。

## 结构

```text
kpms/green/
├── green.c                  # KPM 入口与工具调度
├── emu/
│   └── emu.c                # 可复用的 ARM64 单指令读写模拟器
├── include/
│   ├── green.h
│   ├── green/abi.h          # 用户态 / 内核态共享 ABI 常量
│   ├── green/tool.h         # Green 工具抽象
│   ├── green/cli.h          # CLI 工具抽象与公共 helper
│   ├── green/shadow.h       # CLI shadow client API
│   ├── green/shadow_internal.h # KPM shadow 内部接口
│   ├── green/emu.h          # 单指令模拟器公共接口
│   ├── green/symbol.h       # 内核符号地址与解析接口
│   └── green/hook.h         # shadow 工具对外 API
├── shadow/
│   ├── shadow.c             # shadow 工具生命周期、prctl ABI、页对象管理
│   ├── shadow_pgtable.c     # 页表切换、TLB/cache 维护
│   └── shadow_fault.c       # page fault / GUP / exit_mmap 处理与同页模拟
├── green_hook/              # green_hook：gum 源码级接入
│   ├── IO_MAP.md            # gum 内存 I/O 与调用点梳理、替换映射
│   ├── gummemory-green.c    # gum 内存后端：hook 读写走 shadow
│   ├── green_gum.h          # green 扩展（release）声明
│   ├── vendor/gum/          # frida-gum 源码（逐字未改）：GumArm64Writer 等
│   └── shim/                # glib/capstone 最小垫片（仅外部依赖）
├── agent/
│   ├── green_agent.c        # 注入 payload、工具分发 socket、QuickJS bridge
│   │                        # 与 Frida 风格 API 层（Interceptor/Process/Module）
│   ├── green_agent.h        # 可扩展 agent/broker 协议接口
│   ├── example_hook.js      # QuickJS hook 示例
│   └── README.md            # 注入、协议、JS API 和扩展说明
├── common/
│   ├── common.c             # CLI 公共解析、solist、prctl、process_vm helpers
│   ├── agentops.c           # 注入器 / agent 协议客户端 / broker 原语
│   └── symbol.c             # KPM 内核符号提取与地址解析
├── tests/
│   └── test_hook.c          # green_hook 端到端用例（patch/读原始/恢复）
├── server/
│   └── server.c             # frida 式守护进程（TCP 27042，主机 CLI 入口）
├── cli/
│   ├── main.c               # 设备端 CLI 工具分发入口
│   ├── README.md            # CLI 扩展说明
│   ├── shadow.c             # shadow 子命令
│   └── hook.c               # hook 子命令（设备端调试用 attach/spawn）
```

## 当前工具：shadow

Green 的 shadow 工具重新实现了一个 patch-oriented 的 R^X / W^X shadow-page hook 核心：

- 目标虚拟页保留两份物理页：original page 和 shadow page。
- 执行时 PTE 指向 shadow page，并设置为用户态仅执行（`--x`）。
- 用户态读取代码触发 data abort 后，临时切到 original page 只读不可执行（`r--`），读取校验看到原始代码。
- 再次执行触发 instruction abort 后，切回 shadow page。
- 代码和数据位于同一页时，使用 `emu/` 中的单指令 ARM64 模拟器从 original page 读取数据并推进 `pt_regs->pc`，避免整页切换造成 fault 循环。
- hook `follow_page_pte` 时临时暴露 original PTE，覆盖 `/proc/pid/mem`、`process_vm_readv`、`ptrace` 等 GUP 读取路径。
- hook `exit_mmap` 自动释放进程退出时遗留的 shadow 页。
- 控制入口是 `prctl`，只允许 root 调用。注入到目标进程的 agent 没有内核特权：broker 请求（页面快照 + GumArm64Writer 编码 + prctl）由设备端 `green hook`/`green server` 或主机端 Python CLI 代为执行（详见 `agent/README.md` 与 `../../host/README.md`）。

内核符号统一由 `common/symbol.c` 提取和解析，地址变量及公共声明集中在 `include/green/symbol.h`；其他 KPM 工具只通过该头文件使用已解析地址。

与参考项目不同：

- 没有照搬 wxshadow 代码；当前实现仅保留核心页表切换思路。
- 删除 BRK 断点命中后修改寄存器功能。
- 当前主能力是 hidden patch / inline branch / NOP；后续工具可以通过 `green_shadow_patch_kernel()` 复用 shadow patch 能力。

## 构建

```sh
cd kpms/green
make TARGET_COMPILE=aarch64-elf-
make client
make testhook
make agent
```

CLI 工具示例（单二进制）：

```sh
adb push build/green /data/local/tmp/green
adb shell su -c "/data/local/tmp/green shadow count -p <pid>"

# hook：注入 + 加载 JS hook 脚本一步完成
adb push build/libgreen_agent.so /data/local/tmp/libgreen_agent.so
adb push agent/example_hook.js /data/local/tmp/hook.js
adb shell su -c "/data/local/tmp/green hook attach -p <pid> -l /data/local/tmp/hook.js"
adb shell su -c "/data/local/tmp/green hook attach -f <package> -c \"log('hello')\""
```

所有构建产物统一输出到 `build/`：

```text
build/
├── green.kpm              # KPM
├── green                  # Android ARM64 CLI
├── test_hook              # green_hook 端到端用例（需 root + 已加载 KPM）
├── libgreen_agent.so      # 注入目标进程的 agent payload
└── *.o                    # KPM 中间目标文件
```

如果需要按设备上的 KernelPatch 版本构建：

```sh
make TARGET_COMPILE=aarch64-elf- KP_DIR=/path/to/KernelPatch-0.13.3
```

## green_hook（gum 源码级接入）

`green_hook/` 直接编译 frida-gum 源码（`green_hook/vendor/gum/`，未修改），hook 时的内存读写全部替换为 shadow 操作（详见 `green_hook/IO_MAP.md`）：

- `gum_memory_patch_code()`：gum via_remap 骨架，remap 对实现为快照/提交 —— apply 回调由真实 `GumArm64Writer` 发射重定向，提交时逐页 `prctl(PR_GREEN_SHADOW_PATCH)`；执行看到补丁，读取看到原始字节。
- `gum_memory_read()`：仍走 `process_vm_readv`，GUP hook 返回原始页。
- `green_gum_release_page()` ↔ gum `deactivate_trampoline`：恢复原始 PTE。
- 指令编码全部来自 gum 源码（实测输出 `58000050 d61f0200 .quad`），无任何手写二进制 hook；shim 仅覆盖 glib/capstone 枚举等外部依赖。

用例（设备上以 root 运行，需先加载 KPM）：

```sh
make testhook
adb push build/test_hook /data/local/tmp/
adb shell su -c /data/local/tmp/test_hook
```

验证点：

1. `target_fn()` 被重定向到 `replacement_fn()`（执行看到 shadow 补丁）；
2. GUP 读与直接读均返回原始字节（读取看到 original page）；
3. `ldr x16,#8` 从 shadow 页自身的 literal pool 取地址（同页自读模拟）；
4. release 后 `target_fn()` 恢复原行为。

## CLI 用法

```sh
# 解析 linker64 的 solist 链表，打印所有已加载库
./build/green shadow solist -p <pid>

# maps 仍作为兼容别名，但不再从 maps 枚举 so
./build/green shadow maps -p <pid>

# 查看当前 shadow 页数量
./build/green shadow count -p <pid>

# 写入任意 hidden patch，hex 为小端机器码
./build/green shadow patch -p <pid> -a 0xADDR -x d503201f

# 按 linker64 solist 中的库名 + 偏移寻址
./build/green shadow patch -p <pid> -b libc.so -o 0x12345 -x d503201f

# NOP N 条 AArch64 指令
./build/green shadow nop -p <pid> -a 0xADDR -n 2

# 写入近跳 B target，范围 +/-128MB
./build/green shadow branch -p <pid> -a 0xADDR -t 0xTARGET

# 释放指定页 / 全部页
./build/green shadow release -p <pid> -a 0xADDR
./build/green shadow release -p <pid>
```

## prctl ABI

| 命令 | 值 | 参数 |
|------|----|------|
| `PR_GREEN_SHADOW_PATCH` | `0x47524801` | `pid, addr, user_buf, len` |
| `PR_GREEN_SHADOW_RELEASE` | `0x47524802` | `pid, addr, 0, 0`，`addr=0` 表示全部释放 |
| `PR_GREEN_SHADOW_COUNT` | `0x47524803` | `pid, 0, 0, 0` |

## 扩展方式

### 新增 KPM 工具

1. 实现一个 `const struct green_tool your_tool`。
2. 在 `green.c` 的 `green_tools[]` 中加入它。
3. 如果要复用 shadow 能力，include `<green/hook.h>` 后调用：

```c
green_shadow_patch_kernel(pid, addr, patch, patch_len);
green_shadow_release_task(pid, addr);
```

### 新增 CLI 工具

1. 在 `cli/` 新增 `<tool>.c`。
2. 需要声明时，在 `include/green/` 新增对应头文件。
3. 暴露 `const struct green_cli_tool green_cli_<tool>_tool`。
4. 在 `common/common.c` 的工具表中注册。
5. 可 include `<green/shadow.h>` 复用 shadow 的 patch/release/count/branch 编码能力。

## 限制

- 当前只支持 ARM64 + 4K 用户页粒度。
- `emu/` 支持常见 GPR 标量 `LDR/STR`、`LDUR/STUR`、寄存器偏移、前/后索引、`LDRSB/LDRSH/LDRSW`、literal load、`LDP/STP`，以及 SIMD/FP `LDR B/H/S/D/Q`、literal load、`LDP S/D/Q`；exclusive、跨页访问暂不模拟。
- `patch` 不能跨目标页。
- 当前拒绝 ARM64 contiguous PTE 页面。
- 直接修改目标进程页表；测试前请保证设备可恢复。
