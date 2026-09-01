# Green agent

`green_agent` 由两部分组成：

- `libgreen_agent.so`：注入目标进程的 payload，提供按 PID 命名的抽象 Unix socket、
  工具分发器以及内嵌 QuickJS 运行时。
- `green agent`：root 侧 CLI，负责注入、协议通信、跨进程页面快照、
  GumArm64Writer 重定向编码和 KPM `prctl` 调用。

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

## 注入

payload 必须位于目标进程可读取、可执行的位置：

```sh
green agent inject --pid PID \
  --so /data/user/0/<package>/cache/libgreen_agent.so

green agent ping --pid PID
```

CLI 的每个命令都会自动附着临时 root broker，无需单独启动 broker 进程。

## QuickJS hook

示例脚本见 `agent/example_hook.js`：

```js
log("script loaded");

const target = selfTestTarget();
hook(target, function (args) {
    log("arg0=" + args[0]);
    return args[0] + 100;
});
```

当前原生 API：

- `log(value...)`：输出到 Android logcat 的 `green-js` tag；
- `selfTestTarget()`：返回 agent 内置测试函数地址；
- `hook(address, callback)`：将地址重定向到 JS callback。

callback 接收一个包含 ARM64 `x0` 到 `x7` 的数组；其整数返回值作为 `x0` 返回给
原调用者。当前桥接层只保存一个 callback，重复调用 `hook()` 会替换 callback。

加载并运行内置 probe：

```sh
green agent js --pid PID --file /data/local/tmp/example_hook.js
```

成功输出：

```text
status=0 value=0x0 script loaded from .../green_hook.js
status=0 value=0x65 probe during=101
```

QuickJS context 会在目标进程中持续存在。脚本使用 IIFE 包装后执行，因此可重复加载；
运行 callback 的线程可能不同于加载线程，agent 会在每次进入 QuickJS 前刷新 native
stack top，并用 mutex 串行化 runtime 访问。

## 原生 hook 自测

```sh
green agent self-test --pid PID
```

该命令验证完整链路：原始结果 `2` -> shadow 重定向结果 `101` -> release 后恢复 `2`。

## 扩展

通过 `green_agent_register_tool()` 注册新的 tool id 与 handler，可复用同一套注入、
socket 和 root broker 传输，无需为每个工具重新实现注入器。
