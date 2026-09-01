# host CLI（Python，跨平台）

`cli/green.py` 是运行在主机上的命令行客户端，通过 TCP 与手机端的
`green server` 守护进程通信（frida-server 模式）。

```text
主机 (python3 green.py)  ──TCP 27042──►  手机 green server (root)
                                          ├─ 进程枚举 /proc
                                          ├─ ptrace 注入 libgreen_agent.so
                                          ├─ broker：页面快照 + GumArm64Writer
                                          │   + prctl(PR_GREEN_SHADOW_*)
                                          └─ 脚本日志回流
                                               │ unix @green.agent.<pid>
                                               ▼
                                          目标进程内 QuickJS
```

## 使用

```sh
# 手机端（root）：
adb push kpms/green/build/green /data/local/tmp/green
adb push kpms/green/build/libgreen_agent.so /data/local/tmp/libgreen_agent.so
adb shell su -c 'chmod 755 /data/local/tmp/green /data/local/tmp/libgreen_agent.so'
adb shell su -c '/data/local/tmp/green server'          # 监听 0.0.0.0:27042

# 主机端：
adb forward tcp:27042 tcp:27042
python3 cli/green.py ps [filter]
python3 cli/green.py attach -p <pid> -l script.js      # 脚本文件（主机路径）
python3 cli/green.py attach -f com.example.app \
    -c "console.log('pid', Process.id)"
python3 cli/green.py --host <device-ip> --port 27042 ps   # 免 adb forward
```

`attach` 会保持连接并实时回流脚本 `console.log()/log()/send()` 输出，
Ctrl-C 断开（hook 与 shadow 页保留，重复 attach 会重载脚本）。

## 协议

帧格式（小端）：`u32 magic("GGR1") | u16 type | u16 flags | u32 len | payload`。

| type | 方向 | 含义 |
|------|------|------|
| 1 LIST | c→s | 枚举进程 → PROCS |
| 2 ATTACH | c→s | `pid: i32, has_pkg: u8, pkg: char[128], script_len: u32, script` → LOG 流 + RESULT |
| 3 SPAWN | c→s | `pkg: char[128]` → RESULT（未实现） |
| 0x80 LOG | s→c | `pid: i32, len: u32, text`（脚本输出） |
| 0x81 RESULT | s→c | `ok: i32, len: u32, msg` |
| 0x82 PROCS | s→c | `count: u32, [pid: i32, name_len: u16, name]` |

payload 内部：脚本输出通过 broker 通道的 one-way `GREEN_BROKER_LOG` 帧回流到
server（与 hook 的 PATCH 请求同一连接，靠 g_js_lock 串行化）。

## 脚本 API（与 Frida 的兼容性）

已支持：

| API | 说明 |
|-----|------|
| `Interceptor.replace(addr, fn)` | 完整。`fn(args)` 收到 `[x0..x7]` 数组，返回值作为 `x0` |
| `Interceptor.revert(addr)` | 完整。释放该地址所在 shadow 页 |
| `Process.id / arch / platform` | 完整 |
| `Process.enumerateModulesSync()` | 文件映射模块列表（native 解析，含 base/size/path/protection） |
| `Module.getBaseAddress(name)` / `findBaseAddress(name)` | 返回 base **数值**（非 NativePointer） |
| `Memory.readUtf8String / readCString(addr[,len])` | 经 `/proc/self/mem`，不触发 SIGSEGV |
| `Memory.readByteArray(addr, len)` | 返回 ArrayBuffer |
| `console.log/info/warn/error`、`log()` | logcat + 回流主机 |
| `send(obj)` | JSON 序列化后回流主机 |
| `selfTestTarget()` | 内置自测函数地址 |

尚未支持（与 Frida 的差距）：

- `Interceptor.attach`（onEnter/onLeave 且保留原函数执行）——需要跳板页 +
  指令重定位（集成 vendored frida-gum relocator）或 KPM 侧 bypass 标志；
  当前 `attach` 会抛出明确错误提示改用 `replace`；
- `Interceptor.replace` 的 NativePointer 包装、`NativeFunction`；
- `Memory.write*`、`Memory.alloc`、`Memory.protect`；
- `Module.enumerateExports/Symbols`（需解析 ELF dynsym）；
- `Stalker`、`Java.*`/`ObjC.*` 桥、`spawn`/`gating`、early instrumentation。
