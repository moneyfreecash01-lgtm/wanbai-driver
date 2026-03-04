# Kernel Module Debugging Guide

This guide provides instructions on how to properly retrieve kernel logs and debug kernel panics for your Android kernel module. Ensure your device is rooted and you have access to a shell with `su` privileges.

## 1. Monitoring Live Kernel Logs

To get real-time kernel logs while your module is loading or running:

1. Open a terminal or ADB shell on your device.
2. Gain root access:
   ```bash
   su
   ```
3. Run `dmesg` to view the kernel log buffer. To follow the logs in real-time, use the `-w` (watch) flag:
   ```bash
   dmesg -w
   ```
   *(Press `Ctrl+C` to stop watching.)*

**Tips for live logs:**
- **Clear existing logs:** To clear logs before loading your module so you only see new events, run:
  ```bash
  dmesg -c
  ```
- **Filter logs:** To filter logs specifically for the `wanbai-driver` (which prefixes its logs with `wanbai:`):
  ```bash
  dmesg -w | grep -i "wanbai"
  ```
- **Alternative:** You can continuously read from the kernel message buffer directly:
  ```bash
  cat /proc/kmsg
  ```

## 2. Retrieving Kernel Panic Logs After a Reboot

If your kernel module triggers a kernel panic or a hard reboot, live logs will be lost. However, the kernel usually saves the panic logs to memory, which you can read *after* rebooting.

1. After the device reboots from a panic, open a shell (e.g. via Termux or ADB).
2. Gain root access:
   ```bash
   su
   ```

### Method A: pstore (Modern Android Kernels)
Most modern Android devices (> Kernel 4.x/5.x) use the `pstore` driver to store panic logs. List the contents of the `/sys/fs/pstore/` directory:
```bash
ls -l /sys/fs/pstore/
```
To view the console logs from the crash, look for files named `console-ramoops-0` or `dmesg-ramoops-0`. Read them with:
```bash
cat /sys/fs/pstore/console-ramoops-0
# or
cat /sys/fs/pstore/dmesg-ramoops-0
```

### Method B: last_kmsg (Older Android Kernels)
On older kernels, panic logs are usually stored under `/proc`:
```bash
cat /proc/last_kmsg
```
*(If this file doesn't exist, your kernel uses Method A.)*

**Tips for Panic Logs:**
- Redirect outputs to a file on your sdcard so you can pull it to your PC for easier reading and sharing:
  ```bash
  cat /sys/fs/pstore/console-ramoops-0 > /sdcard/panic_log.txt
  ```
- Search for **"Call trace:"** inside the text. The Call Trace will show you the exact sequence of kernel/module functions that led to the crash.
- Check the **PC (Program Counter)** and **LR (Link Register)** addresses mentioned in the crash log output. These point directly to the instruction that caused the panic.

## 3. Investigating the Crash
- If your module crashes the device, always grab the `console-ramoops-0` file immediately after the phone turns back on.
- Find the instruction address (e.g., `pc is at <function_name+offset/size>`) and the call trace.
- Compare these against the functions in your module's source code to trace where the invalid pointer dereference or fault happened.
