# CaptureHttpsOnContainer
Capture network traffic in the Android security container

1. The Application layer captures network data logic in Hook.java.

2. The Native layer captures network data logic in libNativeHook.so, the code calling the logic in the container is:
```java
System.loadLibrary("NativeHook");
```
the network data is saved at "手机存储/newout/sslread.txt" and "手机存储/newout/sslwrite.txt"
