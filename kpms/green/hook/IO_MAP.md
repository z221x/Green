# green_hook — gum 源码级接入与 shadow 内存 I/O 替换

`green_hook` 直接编译 frida-gum 的源码（`hook/vendor/gum/`，逐字未改），
把 gum 在 hook 时的内存读写替换为 green shadow 页操作。替换发生在
**源码层面**：gum 的平台后端接缝（`gummemory-linux.c` 在上游扮演的角色）
由 `hook/gummemory-green.c` 承担；指令编码完全来自 gum 自己的
`GumArm64Writer`，没有任何手写二进制 hook。

## 一、编译的 gum 源码（vendor，未修改）

| 文件 | 作用 |
|---|---|
| `arch-arm64/gumarm64writer.c` | ARM64 指令发射器（hook 重定向的编码来源） |
| `gummetalarray.c` / `gummetalhash.c` | writer 的 literal pool 容器 |
| `gumlibc.c` | gum_memcpy/memset/memmove |
| `gumdefs.h` / `gummemory.h` / `gummemory-priv.h` | gum 类型与内存 API |

`arch-arm64/gumarm64reader.c` 已 vendor 但暂不编译（需要真实 capstone
反汇编器 `cs_disasm_iter`）。

## 二、shim（仅外部依赖，不含任何指令编码）

| 文件 | 内容 |
|---|---|
| `shim/glib.h` | writer/容器用到的 glib 原语：类型、`g_slice_*`→malloc、原子、断言、字节序宏 |
| `shim/capstone.h` | `arm64_reg` / `arm64_cc` 枚举（writer 只用枚举值，不反汇编） |
| `shim/gumprocess.h` | `GumOS`（枚举在 gumdefs.h）+ `gum_process_get_native_os` 声明 |
| `shim/gum/gumenumtypes.h` | 空占位 |

## 三、hook 时的读写替换（`gummemory-green.c`）

沿用 gum 前端 `gum_memory_patch_code_pages_via_remap()` 的算法骨架，
remap 对（`try_remap_writable_pages` / `dispose_writable_pages`）实现为
**快照 / 提交**：

```text
gum_memory_patch_code(target, size, apply, data)   ← gum 前端逻辑
  ├─ gum_memory_try_remap_writable_pages(page, n)
  │     快照 original 页（process_vm_readv，GUP 对 shadow 页返回原始 PFN）
  ├─ apply(snapshot + page_offset, data)
  │     回调内由 GumArm64Writer 发射重定向（真实 gum 源码）
  └─ gum_memory_dispose_writable_pages(snapshot, n)
        每页 prctl(PR_GREEN_SHADOW_PATCH, 0, page, snapshot, 4096)
        内核在 shadow 副本上叠加快照 → 执行看到补丁、读取看到原始
```

写入器输出（host 实测，vendor 源码直接产出）：

```asm
58000050  ldr x16, #8      ; GumArm64Writer put_ldr_reg_address(X16, repl)
d61f0200  br  x16          ; GumArm64Writer put_br_reg(X16)
.quad replacement          ; writer 自动追加的 literal pool
```

`ldr x16,#8` 执行在 shadow 页上读同页 literal —— 由 `emu/` 同页自读
模拟器从 **shadow** 字节取回（`shadow/shadow_fault.c`），重定向地址因此可用。

## 四、gum 内存 I/O → green 后端映射

| gum 函数（上游 Linux 后端） | green 后端实现 |
|---|---|
| `gum_memory_patch_code[_pages]` | via_remap 骨架 + 快照/提交（见上） |
| `gum_memory_write` | `PR_GREEN_SHADOW_PATCH`（绝不对 RX 页 memcpy） |
| `gum_memory_read` | `process_vm_readv`（GUP hook 已返回原始 PFN） |
| `gum_try_mprotect` / `gum_mprotect` | 原生 mprotect（仅 gum 自建 code allocator 页会走到） |
| `gum_clear_cache` | no-op（内核 patch 时已做 I-cache/TLB 维护） |
| `gum_memory_can_remap_writable` | `TRUE`（把前端路由进 remap 路径） |
| deactivate_trampoline（卸载） | `green_gum_release_page()` → `PR_GREEN_SHADOW_RELEASE` |

## 五、gum 调用点链路（上游 → green_hook）

```text
gum_interceptor_transaction_commit        guminterceptor.c:1638
  └─ gum_memory_patch_code_pages          ★ green: 快照/提交
       └─ gum_apply_updates
            └─ _gum_interceptor_backend_activate_trampoline
                 写 B / ADRP+BR / LDR+BR   ★ green: GumArm64Writer (vendor)
卸载:
gum_interceptor_deactivate → memcpy 回填   ★ green: green_gum_release_page
```

gum 自建内存（code allocator 的 mmap/mprotect、trampoline 页）与目标
进程代码页无关，保留原生路径。
