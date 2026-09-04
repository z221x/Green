# Green tests

该目录存放不会被 payload 链接进目标进程的回归测试和设备探针。

## KPM shadow 回归

```sh
ANDROID_NDK=/path/to/android-ndk make -C kpms/green testhook
adb push kpms/green/build/test_hook /data/local/tmp/
adb shell su -c /data/local/tmp/test_hook
```

## Android API 探针

`test_java_hook.sh` 会推送 `build/` 中的 server/payload，启动目标包并 attach
探针。通过 `PROBE_SCRIPT` 选择测试内容：

```sh
ADB=/path/to/adb \
PROBE_SCRIPT="$PWD/kpms/green/test/java_api_probe.js" \
kpms/green/test/test_java_hook.sh com.example.app
```

可用探针：

- `java_api_probe.js`：Java 对象、重载、静态方法/字段、数组、集合和枚举；
- `java_hook_probe.js`：`String.hashCode` 原始调用与 hook 回归；
- `native_api_probe.js`：NativePointer、Memory、NativeFunction 和 attach。
- `example_hook.js`、`demo_app_hook.js`：通用 Native/应用 hook 示例。
