# Dynamic analysis for API monitoring

Dynamic analysis using inline hooking to monitor API calls in Windows processes. It can be extended to track many 
other Windows API functions and system activities.

* [api_monitor.cpp](api_monitor.cpp)
* [HookEngine.h](hook_engine.h)
* [api_monitor.h](api_monitor.h)
* [Logger.h](logger.h)

## Features

The tool monitors:

* File operations
* Process creation
* Network connections
* Registry access

It can be easily extended by adding new hook functions in `api_monitor.h` and registering them in the 
`InstallHooks()` method.

## Compilation

Compile the program (x86 or x64 depending on target).

1. Open Developer Command Prompt for VS (search in Start menu).
2. Navigate to the folder containing the .cpp file.
3. Run:

For x64 (For x86, no additional setup is needed (default):

```commandline
vcvarsall.bat x64
```

4. Then compile:

```commandline
cl /EHsc /Zi /Fe:api_monitor.exe api_monitor.cpp /link /SUBSYSTEM:CONSOLE
```

## Usage

Run as Administrator:

1. Right-click api_monitor.exe → Run as Administrator (hooks require admin privileges).
2. Enter target process name. Example:

```commandline
Enter target process name (e.g., notepad.exe): notepad.exe
```

The tool will find the PID and inject the monitoring thread.

3. Observe API calls in real-time
   * Open Notepad and perform file operations (e.g., save a file).
   * The console will log API calls like:

```commandline
[14:25:03.422] CreateFileW called: C:\test.txt
[14:25:03.425] CreateFileW returned: 00000214
[14:25:05.123] WriteFile called - Handle: 540, Size: 15
[14:25:05.123] Data: 48 65 6C 6C 6F 20 57 6F 72 6C 64 21 0D 0A ...
```

4. Press Enter to stop monitoring

## Debugging Hooks

If hooks fail, check:

* Target process is running.
* Running as Administrator.
* Correct architecture (x86/x64) match.

## Logs

All output is saved to api_monitor.log in the same directory.

## Troubleshooting

| Issue	* * * | Solution* * * * * * * * * * * *   |
|-------------------|-----------------------------------------------------------|
| "Failed to hook"	 | Ensure target process is not protected (e.g., antivirus). |
| No logs	* *   | Run as Admin. Check api_monitor.log permissions.* *   |
| Crashes	* *   | Verify architecture (x86/x64) matches the target.* *  |