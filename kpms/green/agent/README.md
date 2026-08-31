# Green agent

`green_agent` 由两部分组成：

- `libgreen_agent.so`：注入目标进程的进程内载荷。它启动一个按 PID 命名的抽象 Unix
  socket，分发已注册的工具请求。首个注册的工具是 `green_hook`。
- `green agent` 子命令（位于 `kpms/green/cli`）：root 侧注入器、broker 和协议客户端。

## 权限模型（重要）

**agent 绝对不执行任何 KPM 操作。** 它：

- 不调用 `prctl(PR_GREEN_SHADOW_*)`；
- 不读写目标页表；
- 不链接任何 gum 源码，是一个纯传输层（约 11KB）。

Agent 的 hook 请求只携带两个地址（`target` 与 `replacement`）。特权操作全部由
root 侧 broker 完成：

```text
agent（目标进程内，无特权，纯传输）
   |  1. socket 请求：{target 地址, replacement 地址}
   ▼
green agent broker（root，位于唯一 CLI 中）
   |  2. process_vm_readv 跨进程快照原始页
   |  3. GumArm64Writer 在快照中生成重定向
   |  4. prctl(PR_GREEN_SHADOW_PATCH/RELEASE/COUNT)
   ▼
KPM（页表读写）
```

- `green agent broker --pid <pid>` 监听方向与直觉相反：**root 主动连接** agent 的
  `@green.agent.<pid>` socket 并发送 `BROKER_ATTACH`（SELinux 禁止
  `untrusted_app → root` 方向的 `connectto`，反向则允许）。此后该连接专用于转发
  agent 的特权请求。
- broker 只服务 peer uid 等于目标进程 uid 的连接，因此一个 broker 实例只绑定一个
  目标进程。
- agent 自身的 socket 是 `@green.agent.<pid>`；不启动 broker 时仅 `PING` 可用。

## 构建

```sh
make -C kpms/green agent
```

产物：

```text
kpms/green/build/libgreen_agent.so
```

## 注入与使用

载荷必须能被目标 APP 读取和执行；把它拷入 APP 自己的数据目录并赋予 APP 的 uid。
然后以 root 执行：

```sh
# 1. 注入
green agent inject --pid PID \
  --so /data/user/0/<package>/cache/libgreen_agent.so

# 2. 为该目标附着 root broker
green agent broker --pid PID

# 3. 存活检查 + green_hook 自测（真实 GumArm64Writer + shadow 后端）
green agent ping --pid PID
green agent self-test --pid PID

# 4. 按进程内绝对地址显式 hook
green agent hook --pid PID --target 0xTARGET --replacement 0xREPLACEMENT
green agent release --pid PID --target 0xTARGET
```

`self-test` 在注入目标内走完整链路：broker 跨进程快照 + writer 生成补丁 → KPM
shadow 页 → 目标内执行验证（`before=2 during=101 after=2`）→ release 恢复。

## 扩展

通过 `green_agent_register_tool()` 注册新的 tool id 与 handler，即可让后续 Green
工具复用同一传输通道和注入器，无需修改协议。
