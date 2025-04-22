# Windows Reverse Engineering framework

This framework provides a solid foundation for analyzing Windows executables for security weaknesses. 

## Features

* PE File Parser – Parses headers, sections, and imports
* Process Analyzer – Reads memory, enumerates modules
* Vulnerability Scanners – Checks for DEP, ASLR, and more
* Error Handling – Robust logging and exception handling
* Modular Design – Easy to add new scanners

## Build instructions

```
g++ -std=c++17 -o win_reveng win_reveng.cpp -lcapstone -ldbghelp -lpsapi
```

## Usage

### Analyzing a PE File (Static Analysis)

```
win_reveng <path_to_exe>
```
Example:

```
win_reveng C:\malware\suspicious.exe
```

Output:
```
[INFO] [pe_parser] Parsing PE headers...
[INFO] [dep_scanner] Checking DEP/NX compatibility
[INFO] [aslr_scanner] Checking ASLR compatibility
```

### Analyzing a Running Process (Dynamic Analysis)

```
win_reveng -p <process_id>
```
Example:

```
win_reveng -p 1337
```

Output:

```
[INFO] [process_analyzer] Attached to PID 1337
[INFO] [dep_scanner] Checking runtime DEP status
[INFO] [aslr_scanner] Checking runtime ASLR status
```

### Finding process IDs

To get a process ID (PID) for dynamic analysis:

```
tasklist
```

or (PowerShell):

```
Get-Process | Select-Object Id, ProcessName
```

## Extending the framework

### Add a new scanner

```
class heap_spray_scanner : public vulnerability_scanner {
public:
    void scan_static(const pe_parser& pe) override { /* ... */ }
    void scan_dynamic(process_analyzer& proc) override { /* ... */ }
    std::string get_name() const override { return "heap_spray_scanner"; }
};
```

or 

```
class stack_cookie_scanner : public vulnerability_scanner {
public:
    void scan_static(const pe_parser& pe) override {
        log_msg(LOG_INFO, "Checking stack cookies (/GS)", get_name());
    }
    void scan_dynamic(process_analyzer& proc) override {
        log_msg(LOG_INFO, "Checking runtime stack protection", get_name());
    }
    std::string get_name() const override { return "stack_cookie_scanner"; }
};
```

### Register it

```
engine.register_scanner(std::make_unique<heap_spray_scanner>());
engine.register_scanner(std::make_unique<stack_cookie_scanner>());
```