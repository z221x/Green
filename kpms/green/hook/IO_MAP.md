# green_hook — gum 内存 I/O 与 shadow 替换映射

`green_hook` 以 `kpms/green/tmp/frida-gum/gum` 源码为参考实现，把 gum 在
Linux/Android ARM64 上的底层内存 I/O 全部替换为 green shadow 页操作：

- **写代码页（hook 安装）**：gum 用 `mprotect(RW) → memcpy → mprotect(RX)`,
  green_hook 用 `prctl(PR_GREEN_SHADOW_PATCH)` 写 shadow 页；执行看到补丁、
  读取看到原始字节。
- **读代码页（完整性校验）**：gum 用 `process_vm_readv`/`memcpy`, green_hook
  原样保留 —— shadow 的 GUP hook 与 read-fault 切换天然让读取看到原始页。
- **恢复（hook 卸载）**：gum 回填 `overwritten_prologue`, green_hook 用
  `prctl(PR_GREEN_SHADOW_RELEASE)` 一步恢复原始 PTE。

## 一、gum 底层内存 I/O 函数清单

来源：`gum/gummemory.c`、`gum/backend-linux/gummemory-linux.c`。

| gum 函数 | 位置 | Linux 实现 | 用途 | green_hook 替换 |
|---|---|---|---|---|
| `gum_memory_patch_code` | gummemory.c:368 | 收集页 → `patch_code_pages` | 在目标代码页写入补丁 | `green_gum_memory_patch_code` → `PR_GREEN_SHADOW_PATCH` |
| `gum_memory_patch_code_pages` | gummemory.c:434 | Linux 走 `via_mprotect` | 事务批量落盘 | 同上（逐页提交） |
| `gum_memory_patch_code_pages_via_mprotect` | gummemory.c:616 | `mprotect RW → apply → mprotect RX` | 真正写入 | shadow 写（内核侧 `green_shadow_sync_code` 已含 I-cache/TLB 维护） |
| `gum_memory_read` | gummemory-linux.c:307 | `process_vm_readv` → 直接 `memcpy` 兜底 | 读取目标代码 | `green_gum_memory_read`（保留 `process_vm_readv`; GUP hook 返回原始 PFN） |
| `gum_memory_write` | gummemory-linux.c:367 | `process_vm_writev` → `memcpy` 兜底 | 极少用于代码页 | `green_gum_memory_write` → `PR_GREEN_SHADOW_PATCH` |
| `gum_mprotect` / `gum_try_mprotect` | gummemory-linux.c:415 | `mprotect(2)` | 权限切换 | `green_gum_mprotect`（保留原生；仅用于 gum 自建 code allocator 页，与 shadow 无关） |
| `gum_clear_cache` | gummemory-linux.c:454 | `__builtin___clear_cache` | I-cache 同步 | `green_gum_clear_cache`（no-op；shadow patch 时内核已同步） |
| `gum_memory_can_remap_writable` | gummemory-linux.c | 恒 `FALSE` | 路径选择 | shadow 版恒 `FALSE`（不需要 remap 路径） |
| `gum_memory_mark_code` | gummemory.c:964 | QNX 专用 | — | 不需要 |
| `gum_ensure_code_readable` | gummemory.c:1857 | Android 上 no-op | — | 不需要 |

## 二、调用点（hook 写入链路）

gum interceptor 在 ARM64 上安装一个 hook 的完整链路：

```text
gum_interceptor_attach                        guminterceptor.c
  └─ gum_interceptor_transaction_commit       guminterceptor.c:1560
       └─ gum_memory_patch_code_pages         guminterceptor.c:1638   ★写入口
            └─ gum_apply_updates              guminterceptor.c:1671
                 └─ _gum_interceptor_backend_activate_trampoline
                                              guminterceptor-arm64.c:1072
                      写入 B imm / ADRP+BR / LDR+BR 重定向
  └─ gum_arm64_relocator                      arch-arm64/gumarm64relocator.c
       被覆盖指令重定位进 trampoline（写入自有内存, 不落目标页）
  └─ thunks 页: gum_memory_patch_code         guminterceptor-arm64.c:1277
卸载:
gum_interceptor_deactivate → gum_memcpy(prologue, overwritten_prologue)
                                              guminterceptor-arm64.c:1157  ★恢复入口
```

green_hook 对应替换：

| gum 调用点 | green_hook |
|---|---|
| `gum_memory_patch_code_pages`（安装重定向） | `green_gum_memory_patch_code(addr, size, apply, data)` |
| `gum_memcpy(prologue, overwritten…)`（恢复） | `green_gum_release_page(addr)` → `PR_GREEN_SHADOW_RELEASE` |
| `gum_memory_read`（快照/校验） | `green_gum_memory_read`（无需改动，天然读到原始页） |
| `gum_clear_cache` | no-op（内核 patch 路径已做 `green_shadow_sync_code`） |

非代码页的内存操作（`gum_code_allocator` 自建 trampoline 页的
`gum_mprotect`、`gum_memory_allocate` 的 `mmap`）不涉及目标进程代码，
全部保留原生实现。

## 三、重定向指令（取自 gumarm64writer 编码）

green_hook 的 `arm64_writer` 按 gum `gumarm64writer.c` 的指令编码移植：

| gum API | 编码 | 用途 |
|---|---|---|
| `put_b_imm` | `0x14000000 \| ((d/4) & 0x3ffffff)` | ±128MB 近跳 |
| `put_ldr_reg_u64` + literal | `0x58000000 \| (imm19<<5) \| rt` | LDR Xt, literal |
| `put_br_reg` | `0xd61f0000 \| (rt<<5)` | BR Xt（无 PAC extra=0） |
| `put_adrp_reg_address` | `0x90000000 \| (lo<<29) \| (hi<<5) \| rt` | ±4GB 近跳 |
| `put_nop` | `0xd503201f` | 填充 |

安装 hook 时 green_hook 默认写 gum 的 full redirect：

```asm
ldr x16, #8        ; 从 shadow 页自身的 literal pool 取地址
br  x16
.quad replacement  ; 同页数据 → 由同页自读模拟器从 shadow 页取回
```

注意：`ldr x16, #8` 的 literal 落在 shadow 页内，同页自读 fault 由
`emu/` 模拟器处理，且模拟器对同页数据读 **shadow** 字节（已在
`shadow/shadow_fault.c` 中修正），重定向地址因此能被正确读出。

## 四、shadow 侧已具备的支撑

| 能力 | 位置 | 对 gum 语义的意义 |
|---|---|---|
| patch 写入 + 执行 | `PR_GREEN_SHADOW_PATCH` | `patch_code` 的隐身版 |
| 读取见原始页（跨进程） | GUP hook（`follow_page_pte`） | `gum_memory_read` 语义不变 |
| 读取见原始页（本进程） | read fault → PTE 切换 | 同上 |
| 同页执行+读 | `emu/emu.c` 单指令模拟 | literal pool / 自读代码不死循环 |
| 恢复 | `PR_GREEN_SHADOW_RELEASE` | `deactivate_trampoline` 的等价物 |
