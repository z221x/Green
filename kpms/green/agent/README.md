# Green agent

`green_agent` 由两部分组成：

- `libgreen_agent.so`：注入目标进程的 payload，提供按 PID 命名的抽象 Unix socket、
  工具分发器以及内嵌 QuickJS 运行时。
- `green hook`：root 侧 CLI，负责注入、协议通信、跨进程页面快照、
  GumArm64Writer 重定向编码和 KPM `prctl` 调用。

Java 相关实现集中在 `agent/frida-java-bridge/`：其中的 IIFE 是官方
`frida-java-bridge` 的 Green 适配构建产物，JNI 辅助代码也位于同一目录；
`prelude.js` 和 Gum/CModule 绑定属于 Java、Native 共用的宿主兼容层。

## 权限模型

目标进程内的 agent 不执行特权操作：

- 不调用 `prctl(PR_GREEN_SHADOW_*)`；
- 不直接读写页表；
- 不链接 frida-gum；
- 只通过 root 主动建立的 broker socket 转发 patch/release/count 请求。

一次 CLI 请求使用两条连接：

```text
conn A：CLI 命令 -> agent tool -> 最终响应
conn B：root BROKER_ATTACH -> agent 发回页面操作请求
```

JS 调用 `hook(target, callback)` 时，agent 通过 conn B 发送目标地址和
`green_agent_js_trampoline` 地址。root CLI 随后：

1. 用 `process_vm_readv()` 快照目标页；
2. 用 GumArm64Writer 写入 `LDR X16 + BR X16 + literal` 重定向；
3. 调用 `PR_GREEN_SHADOW_PATCH` 提交 shadow 页；
4. 将执行结果返回 agent，脚本才继续运行。

因此注入目标即使是普通 Android APP uid，也不拥有 KPM 权限。

## 构建

```sh
make -C kpms/green client agent
```

产物：

```text
kpms/green/build/green
kpms/green/build/libgreen_agent.so
```

## 注入与使用

先把 payload 和脚本推到设备的固定位置：

```sh
adb push libgreen_agent.so /data/local/tmp/libgreen_agent.so
adb push test/example_hook.js   /data/local/tmp/hook.js
```

然后一条命令完成注入 + broker + 脚本加载：

```sh
# 指定 pid
green hook attach -p PID -l /data/local/tmp/hook.js

# 指定包名（自动解析运行中的进程；payload 自动复制进应用 cache 目录）
green hook attach -f com.example.app -l /data/local/tmp/hook.js

# 内联 JS 代码
green hook attach -p PID -c "log('hello'); hook(selfTestTarget(), function(a){ return a + 100; })"
```

`attach` 内部流程：解析目标 → 未注入则自动注入（app 目标会把 payload 复制到其
cache 目录并 chown 到应用 uid）→ 附着 root broker → 部署脚本到目标可读路径 →
`JS_LOAD` 求值。重复执行会重新加载脚本（IIFE 包装，无重声明问题）。

## QuickJS hook API

```js
log("script loaded");

const target = selfTestTarget();
hook(target, function (args) {
    log("arg0=" + args[0]);
    return args[0] + 100;
});
```

- `log(value...)`：输出到 Android logcat 的 `green-js` tag；
- `selfTestTarget()`：返回 agent 内置测试函数地址；
- `hook(address, callback)`：将地址重定向到 JS callback。

callback 接收一个包含 ARM64 `x0` 到 `x7` 的数组；其整数返回值作为 `x0` 返回给
原调用者。当前桥接层只保存一个 callback，重复调用 `hook()` 会替换 callback。

QuickJS context 会在目标进程中持续存在。脚本使用 IIFE 包装后执行，因此可重复加载；
运行 callback 的线程可能不同于加载线程，agent 会在每次进入 QuickJS 前刷新 native
stack top，并用 mutex 串行化 runtime 访问。

## KPM 回归测试

```sh
make testhook && adb push build/test_hook /data/local/tmp/
adb shell su -c /data/local/tmp/test_hook
```

验证 shadow 语义：patch 执行生效 / 读取见原始字节 / release 恢复。

测试源码位于 `test/test_hook.c`；Java/Native 设备探针位于 `test/`，所有构建
中间文件和最终产物统一写入 `build/`。

## 扩展

通过 `green_agent_register_tool()` 注册新的 tool id 与 handler，可复用同一套注入、
socket 和 root broker 传输，无需为每个工具重新实现注入器。
