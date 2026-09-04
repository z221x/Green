# Green 的 frida-java-bridge 集成

本目录集中保存 Java bridge 的 Green 适配层：

- `fjb.iife.js`：由官方 `frida-java-bridge` 7.0.13 打包得到的 IIFE，包含
  Android ART/JVM 的 Java API 实现；其中保留了 Green 为 QuickJS、ART 15
  和 KPM shadow 内存模型做的少量补丁。
- `java_bridge.c`：Green 早期 JNI/ArtMethod 辅助入口。当前标准 FJB
  `ArtMethodMangler` 路径主要使用 `NativeCallback`，该文件仍作为底层
  注册和兼容入口保留。

## 与官方实现的关系

官方源码仍位于 `vendor/frida-java-bridge/`，用于审阅版本和重新生成
bundle；`fjb.iife.js` 不是独立 fork 的完整源码，而是针对 Green 宿主做过
适配的构建产物。重新同步上游时，应先对比官方 `dist/fjb.iife.js`，再保留
Green 的补丁，不能直接覆盖。

Java bridge 依赖的 `prelude.js`、Gum writer/relocator 和 CModule 绑定是
共享 Frida 运行时，仍放在 `agent/` 根目录，供 Java 与 Native API 共用。
