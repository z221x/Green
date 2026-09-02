# 已知问题与解决方案

本文档记录 frida-gum 移植到 green payload 过程中遇到的所有问题、根本原因和解决方案。

## 架构差异导致的问题

frida-server 以 root 运行、独立于目标进程；green payload 以 APP uid 注入目标进程内部。
这导致所有依赖 root 权限或独立进程的操作都需要适配。

### 1. 内存写：SELinux execmod 拦截

**现象**：`gum_memory_patch_code` / `gum_memory_write` 在 payload 内调用 mprotect+memcpy
修改代码页时，SELinux 的 `execmod` 策略对 `app_data_file` 拒绝写入。

**原因**：frida-server 以 root 运行（SELinux context 为 `u:r:magisk:s0` 或类似），
mprotect 和写入不受 execmod 限制。payload 以 `untrusted_app` 运行，受 SELinux 约束。

**解决方案**：gum 的内存写操作通过 broker 通道转发到 root 侧 server，
server 调用 `prctl(PR_GREEN_SHADOW_PATCH)` 由内核模块创建 shadow 页。
- 实现：`agent/gummemory-green-payload.c` 覆盖 gum 的内存后端
- `gum_memory_patch_code` → 快照原始页 → apply 修改 → broker 提交 shadow 页
- `gum_memory_write` → 同上

### 2. glib 自动初始化缺失

**现象**：payload 内首次在非主线程调用 `g_main_context_new_with_flags` 时
SIGSEGV，fault addr 0x8，崩溃在 `g_ptr_set_add`（glib 线程状态簿记）。

**原因**：frida 的 glib fork（subprojects/glib）删除了自动初始化构造器
（`glib_init_ctor`）。上游 glib 通过 `__attribute__((constructor))` 在 .so 加载时
调用 `glib_init()` → `_g_thread_init()` 初始化线程状态表
（`g_thread_rec_mutexes` 等 GPtrSet）。frida 改为需要嵌入方显式调用。
`libglib-2.0.a` 的 `glib_init` 符号存在但无人调用 → 线程状态表保持 NULL。

**解决方案**：payload 构造函数中调用 `glib_init()` → `gum_init_embedded()`。
```c
// green_agent.c - green_agent_start_once()
extern void glib_init (void);
glib_init ();
gum_init_embedded ();
g_script_backend = gum_script_backend_obtain_qjs ();
```

**教训**：静态链接 glib/gobject 时必须审计所有 `__attribute__((constructor))`
是否在 .init_array 中正确注册并被 dlopen 执行。

### 3. gumjs 消息不回流（console.log/send 无输出）

**现象**：脚本加载成功，但 console.log 和 send() 的输出既不出现在 logcat
也不回流到主机。

**原因**：gumjs 的 `gum_quick_script_emit` 将消息作为 idle source 挂到
`self->main_context`（即 `g_main_context_default()`）。该上下文需要一个
线程持续迭代（`g_main_loop_run`）。payload 中没有线程迭代 default context，
消息源永远不触发。

**解决方案**：payload 启动时创建专用线程运行 default context 的 GMainLoop。
```c
// green_agent.c - green_main_loop_thread()
static void * green_main_loop_thread (void * unused)
{
  GMainLoop * loop = g_main_loop_new (g_main_context_default (), TRUE);
  g_main_loop_run (loop);  /* 永不返回：驱动消息派发 */
  return NULL;
}
```

### 4. APP 进程注入后死亡

**现象**：gumjs payload 注入 Android APP 后，APP 在数秒到数分钟内死亡
（无 tombstone，进程直接消失）。

**原因**（多重）：
- glib 的 gmain 线程 + ART 的线程在同进程中交互（GC 暂停、signal 处理等）
- 36MB payload .so 的内存开销（glib+gum+quickjs+tcc+capstone+dwarf+unwind）
- `gum_init_embedded()` 可能触发与 ART 冲突的全局初始化

**当前缓解**：
- 使用 hookme（简单 C 进程）验证 payload 功能
- APP 测试使用最简脚本（无 hook），仅验证注入和加载
- APP 的 Module 枚举（841 模块）和 NativeFunction 已验证可用

**待解决**：需要分析 glib 线程与 ART 的具体冲突点（GC safepoint、
signal mask、TLS slot 竞争等）。

---

## Interceptor.attach 实现细节

### 当前状态：✅ 可用

`Interceptor.attach(target, { onEnter, onLeave })` 已完整实现。

**流程**：
1. JS 调用 `__green_interceptor_attach(target, onEnterFn, onLeaveFn)`
2. C 层在槽页（mmap RW→写→mprotect RX）写入：
   - slot+0: `MOVZ W17, #hook_id; LDR X16, [PC,#8]; BR X16; .quad trampoline`
   - slot+32: 重定位的目标函数前 N 条指令（GumArm64Relocator）
3. broker 提交 target 页的 shadow（入口 16 字节改为 `LDR X16,=slot; BR X16`）
4. 运行时：target 调用 → redirect → slot stub → trampoline
5. trampoline: onEnter(args) → green_call_asm(slot+32) 执行原函数 → onLeave
6. `ret` 返回原调用者

### 小函数（≤16 字节）的处理

当重定位遇到 `ret`/无条件跳转（eob）时，重定位停止。
此时槽内的重定位代码就是**完整的函数体**（如 `add w0,w0,#1; ret`）。
`ret` 自然返回到 `green_call_asm` 的 BLR 下一条指令。
不需要跳回 `target+reloc_size`——因为函数已经结束了。

**不需要额外处理**：frida 的 relocator 正确处理了 eob，
我们的代码在 eob 时停止重定位并使用已有的重定位代码。

### onEnter / onLeave 回调

- `onEnter(args)`：args 是包含 x0-x7 的数组（QuickJS number）
- `onLeave(retval)`：retval 是原始返回值；当前不支持 `retval.replace()`
  （需要 GumInvocationContext 的 set_return_value，尚未接线）

### 重入保护

QuickJS runtime 通过 `g_js_lock`（PTHREAD_MUTEX_RECURSIVE）串行化。
同线程重入（hook 的 JS 回调中调用了被 hook 的函数）会导致死锁——
这是已知限制，frida 自身通过 GumInvocationTracker 解决。

---

## NativeFunction / NativeCallback 实现细节

### NativeFunction

- `new NativeFunction(addr, retType, argTypes)` 返回 JS 包装函数
- 调用时通过 `green_call_asm`（arm64 裸汇编）加载 x0-x7 并 BLR
- 返回值通过 JS_NewBigInt64 精确传递
- 支持类型：int/uint/long/ulong/char/pointer/int64/uint64/size_t
- **不支持**：float/double 参数与返回值（需要额外的 fp 汇编桩）

### NativeCallback

- `new NativeCallback(fn, retType, argTypes)` 返回可传给原生代码的地址
- 实现：在 mmap RW 页上写 arm64 桩（MOVZ id → LDR X16 =trampoline → BR X16），
  然后 mprotect RX
- trampoline 收到 x0-x7 后包装为 JS 数组调用 fn，返回值转 int64

---

## gum 内存后端适配（gummemory-green-payload.c）

frida-gum 的 `gummemory.c.o` 引用以下后端函数（全部由 green_hook 提供实现）：

| 函数 | 作用 | 适配 |
|------|------|------|
| `gum_query_page_size` | 返回 4096 | 直接返回 |
| `gum_query_ptrauth_support` | PAC 支持 | DISABLED |
| `gum_process_get_native_os` | 返回 GUM_OS_ANDROID | 直接返回 |
| `gum_internal_malloc/calloc/free` | gum 内部堆 | malloc/calloc/free |
| `gum_memory_read` | 跨进程读 | process_vm_readv(self) |
| `gum_memory_write` | 跨进程写 | broker shadow 提交 |
| `gum_memory_allocate` | 分配代码页 | mmap MAP_JIT |
| `gum_memory_patch_code` | 补丁代码 | 快照→apply→broker 提交 |
| `gum_ensure_code_readable` | 确保代码可读 | no-op（进程内读永远可行） |
| `gum_clear_cache` | 清 icache | no-op（内核 shadow 提交时已清理） |
| `gum_sign_code_address` 等 | PAC 相关 | no-op（禁用 PAC） |

`--allow-multiple-definition` 链接标志确保我们的实现覆盖 libgum 的弱符号。

---

## 测试环境

- 设备：Xiaomi 12 (cupid)，Android 15 (OS2.0.203.0.VLCMIXM)
- KernelPatch：APatch 环境，KPM 已加载
- 注入目标：hookme（简单 C 进程）+ com.goldrush.goldenretriever（真实 Android APP）

## 验证清单

- [x] NativeFunction 调用 getpid 返回正确值
- [x] NativeCallback 创建并通过 NativeFunction 调用返回正确值
- [x] Module.enumerateModulesSync 枚举 841 个模块
- [x] Module.getBaseAddress / findBaseAddress 解析 libc.so 基址
- [x] Memory.readUtf8String / readByteArray 安全读
- [x] console.log / send() 实时回流主机
- [x] Interceptor.attach + onEnter 触发
- [x] Interceptor.replace（原 hook() 路径）
- [ ] Interceptor.attach + onLeave（retval 传递）
- [ ] Interceptor.attach 对小函数（≤16 字节 prologue）的完整支持
- [ ] recv() 双向消息
- [ ] rpc.exports
- [ ] Memory.writeByteArray 对代码页的写入（需要 broker 路径）
