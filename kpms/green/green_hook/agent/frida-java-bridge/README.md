# Green 的 frida-java-bridge 集成

本目录集中保存 Java bridge 的 Green 适配层：

- `fjb.iife.js`：由官方 `frida-java-bridge` 7.0.13 打包得到的 IIFE，包含
  Android ART/JVM 的 Java API 实现；其中保留了 Green 为 QuickJS、ART 15
  和 KPM shadow 内存模型做的少量补丁。
- Java bridge 只依赖标准 GumJS 的 `NativeFunction`、`NativeCallback` 和
  `CModule`，不再链接 Green 自定义 JNI/trampoline C 入口。

## 与官方实现的关系

官方源码仍位于 `vendor/frida-java-bridge/`，用于审阅版本和重新生成
bundle；`fjb.iife.js` 不是独立 fork 的完整源码，而是针对 Green 宿主做过
适配的构建产物。重新同步上游时，应先对比官方 `dist/fjb.iife.js`，再保留
Green 的补丁，不能直接覆盖。

Java bridge 依赖的 Gum writer/relocator 和 CModule 绑定来自 vendored
Frida GumJS；Green 不再维护一份 prelude 或手写 writer。
