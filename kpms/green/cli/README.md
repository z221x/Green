# Green CLI

`green` 使用两级命令分发：

```text
green <tool> <command> [options]
```

当前工具：

```text
green shadow maps
green shadow count
green shadow patch
green shadow nop
green shadow branch
green shadow release

green agent inject
green agent ping
green agent js
green agent self-test
green agent hook
green agent release
```

`green agent` 负责向目标进程注入 `libgreen_agent.so`。每次命令会建立一条命令
连接和一条临时 root broker 连接；QuickJS 脚本通过 `green agent js --pid PID
--file SCRIPT` 部署并执行。详细协议与 JS API 见 `../agent/README.md`。

## 添加工具

1. 在 `cli/` 新增 `<tool>.c`；公共实现放在 `common/`。
2. 需要声明时，在 `include/green/` 新增对应头文件。
3. 实现一个 `const struct green_cli_tool green_cli_<tool>_tool`。
4. 在 `common.c` 的 `green_cli_tools[]` 中注册。
5. 在工具内部复用 `<green/cli.h>` 提供的参数、maps、hex 和 prctl helper。
6. 需要复用 shadow 编码/调用时 include `<green/shadow.h>`。

CLI 不直接依赖 KPM 内部实现；用户态和内核态只通过 `include/green/abi.h` 共享 ABI 常量。

跨进程内存访问统一使用 `process_vm_readv()` / `process_vm_writev()`；`solist` 枚举只读取目标进程 linker64 的内存，不从 maps 枚举 so。
