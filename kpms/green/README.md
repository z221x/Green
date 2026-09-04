# Green

基于 KernelPatch Module (KPM) 的 Android ARM64 动态 hook 框架，采用 frida-server 架构。

## 架构

```
主机 (cli/green.py)  ──TCP 27042──►  手机 green server (root)
  ps / attach / shadow                  ├─ ptrace 注入 libgreen_agent.so
                                        ├─ broker: shadow 页面操作
                                        └─ JS 消息流回流
                                             │ unix @green.agent.<pid>
                                             ▼
                                        目标进程内 QuickJS + frida API
```

## 目录结构

```
kpms/green/
├── green.c                  # KPM 入口（内核侧）
├── shadow/                  # KPM shadow 引擎
│   ├── shadow.c             #   生命周期、prctl ABI、页对象管理
│   ├── shadow_pgtable.c     #   页表切换、TLB/cache 维护
│   └── shadow_fault.c       #   fault/GUP/exit_mmap + 同页模拟
├── emu/emu.c                # ARM64 单指令模拟器
├── green_hook/              # vendored frida-gum 源码接入
│   ├── gummemory-green.c    #   gum 内存后端（shadow 提交）
│   ├── vendor/gum/          #   frida-gum 源码（Writer/Relocator 等）
│   └── shim/                #   glib/capstone 头文件垫片
├── include/green/           # 共享头文件（abi/wire/agentops/cli）
├── common/
│   ├── common.c             # CLI 公共 helper
│   ├── agentops.c           # 注入器 + agent 协议 + broker 原语
│   └── symbol.c             # KPM 内核符号解析
├── server/                  # ★ 手机端守护进程（≈ frida-server）
│   ├── main.c               #   入口：直接运行（--port）
│   └── server.c             #   TCP 守护进程 + shadow 远程操作
├── cli/                     # ★ 主机端 CLI（Python，仅运行时代码）
│   ├── green.py             #   ps/attach/shadow 全部功能
│   └── README.md            #   使用说明 + wire 协议
├── agent/                   # ★ 注入目标进程的 payload
│   ├── green_agent.c        #   transport + QuickJS + JS API
│   ├── green_agent.h        #   agent/broker 协议
│   ├── prelude.js           #   JS API 层（Interceptor/Memory/Module）
│   ├── frida-java-bridge/   #   官方 bridge bundle + Green Java 适配
│   │   ├── fjb.iife.js
│   │   └── java_bridge.c
│   ├── gummemory-green-payload.c  # broker 内存后端
│   ├── gumprofiler-stub.c   #   profiler 符号桩
│   ├── link-payload.sh      #   payload 链接脚本
│   └── README.md
├── test/                    # 回归测试与设备探针
│   ├── test_hook.c          #   KPM 回归测试
│   ├── demo_app_hook.js     #   应用 hook 示例
│   ├── example_hook.js      #   Native hook 示例
│   ├── test_java_hook.sh    #   设备部署/attach 驱动脚本
│   ├── java_api_probe.js    #   Java API 回归探针
│   ├── java_hook_probe.js   #   Java hashCode hook 探针
│   └── native_api_probe.js  #   Native/Memory API 探针
├── build/                   # 构建产物（gitignored）
├── doc/KNOWN-ISSUES.md      # 已知问题与解决方案
├── vendor/                  # frida-gum 源码 + 构建产物（gitignore）
├── Makefile
└── README.md
```

## 快速开始

### 构建

```sh
# 1. 初始化 vendor（首次）
cd vendor && ./setup.sh

# 2. 构建 KPM（需要 KernelPatch 环境）
make TARGET_COMPILE=aarch64-elf- KP_DIR=../../kernel

# 3. 构建 CLI + server + payload
make client agent
```

### 部署

```sh
adb push build/green /data/local/tmp/green
adb push build/libgreen_agent.so /data/local/tmp/libgreen_agent.so
adb shell su -c 'chmod 755 /data/local/tmp/green /data/local/tmp/libgreen_agent.so'

# 启动守护进程
adb shell su -c '/data/local/tmp/green'

# 主机端
adb forward tcp:27042 tcp:27042
python3 cli/green.py ps
```

### Hook 脚本

```js
// example_hook.js — frida 语法
console.log("pid:", Process.id);

var openPtr = Module.getExportByName("libc.so", "open");
console.log("open @", openPtr);

Interceptor.attach(openPtr, {
    onEnter: function (args) {
        console.log("open:", args[0].readCString());
    },
    onLeave: function (retval) {
        console.log("open returned:", retval.toInt32());
        // retval.replace(0);  // 修改返回值
    }
});
```

```sh
python3 cli/green.py attach -p <pid> -l test/example_hook.js
python3 cli/green.py attach -f com.example.app -l test/example_hook.js
```

## JS API

| API | 状态 |
|-----|------|
| `Interceptor.attach` (onEnter + onLeave) | ✅ |
| `Interceptor.replace / revert` | ✅ |
| `retval.replace(value)` | ✅ |
| `NativeFunction` | ✅ |
| `NativeCallback` | ✅ |
| `NativePointer` (read*/write*/算术) | ✅ |
| `Int64 / UInt64` | ✅ |
| `Module.getBaseAddress / getExportByName` | ✅ |
| `Process.id / arch / platform` | ✅ |
| `Process.enumerateModules()` | ✅ |
| `Memory.alloc / free / protect / read* / write*` | ✅ |
| `console.log` / `send()` → 主机流 | ✅ |
| `recv(type, callback)` | ✅ |
| `rpc.exports` | ✅ |
| `File.read / write` | ✅ |
| `Thread.sleep` | ✅ |

## shadow 命令（主机端）

```sh
python3 cli/green.py shadow maps   -p PID [filter]
python3 cli/green.py shadow count  -p PID
python3 cli/green.py shadow patch  -p PID -a 0xADDR -x d503201f
python3 cli/green.py shadow nop    -p PID -a 0xADDR -n 2
python3 cli/green.py shadow branch -p PID -a 0xADDR -t 0xTARGET
python3 cli/green.py shadow release -p PID [-a 0xADDR]
```

## shadow 页面原理

- 目标虚拟页保留两份物理页：original page 和 shadow page
- 执行时 PTE 指向 shadow page（`--x`）
- 数据读取 fault 后临时切到 original page（`r--`）
- 再次执行 fault 后切回 shadow page
- 同页自读通过 ARM64 单指令模拟器从 shadow 读取
- GUP 读取（`process_vm_readv`、`ptrace`）看到 original 页
- `exit_mmap` 自动清理

## prctl ABI

| 命令 | 值 | 参数 |
|------|----|------|
| `PR_GREEN_SHADOW_PATCH` | `0x47524801` | `pid, addr, user_buf, len` |
| `PR_GREEN_SHADOW_RELEASE` | `0x47524802` | `pid, addr(0=全部), 0, 0` |
| `PR_GREEN_SHADOW_COUNT` | `0x47524803` | `pid, 0, 0, 0` |

## 限制

- 仅支持 ARM64 + 4K 页
- `patch` 不能跨页
- 拒绝 contiguous PTE
- 详见 `doc/KNOWN-ISSUES.md`
