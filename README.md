# CaptureHttpsOnContainer
Capture network traffic in the Android security container

The Application layer captures network data logic in Hook.java.

The Native layer captures network data logic in libNativeHook.so, the code calling the logic in the container is:
```java
System.loadLibrary("NativeHook");
```
