# Analysing Anti-Reverse engineering tricks

## Detection capabilities

This tool can identify:

* Debugger checks
* Virtual machine/sandbox detection
* Timing-based anti-analysis
* Code packing and obfuscation
* API hooking techniques
* Process manipulation attempts
* Environment fingerprinting

The analyser provides a comprehensive report of all detected anti-reverse engineering techniques used by the target 
process, for malware analysis and security research.

## Build Instructions (Visual Studio):

* Create a new C++ Console Application project
* Add the source code
* Link against psapi.lib and dbghelp.lib
* Build in Release mode for best results

Compilation:

```commandline
# On Windows with Visual Studio (Developer Command Prompt):
cl /EHsc anti_re_analyser.cpp /link psapi.lib dbghelp.lib
```

This creates anti_re_analyser.exe

## Usage

Execution:

```commandline
anti_re_analyser.exe 1234
```

Where 1234 is the PID of the process you want to analyse

## Use Case example

Imagine you suspect malware.exe is using anti-RE tricks:

1. Find its PID in Task Manager (e.g., PID 5678)
2. Run:

```commandline
anti_re_analyser.exe 5678
```

Get a report like:

```commandline
[Debugger Detection]
  * PEB.BeingDebugged flag
  * Hardware breakpoints detected

[Sandbox Detection]
  * Accelerated clock detected

[Code Obfuscation]
  * VMProtect detected
```
