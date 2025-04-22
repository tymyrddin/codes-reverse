# macOS Reverse Engineering framework

A framework for analyzing Mach-O binaries and detecting vulnerabilities.

## Features

Core Components:

* Mach-O Parser - Analyzes headers, segments, and imports
* Process Inspector - Reads memory, maps regions, checks loaded libraries
* Vulnerability Scanners - Verifies code signing, DYLD security, and memory protections
* Error Handling - Tiered logging with module context and exception safety
* Modular Architecture - Plug-and-play scanner system for custom checks

Key Checks:

* Code signing validation
* DYLD environment safety
* Memory permission analysis
* Universal binary support
* Runtime process inspection

Extensible through:

* Custom scanner interfaces
* Static + dynamic analysis phases
* Mach API integration
* Standardized reporting format

## Building and Dependencies

To build this program on macOS:

* macOS SDK (Xcode)
* C++17 compiler
* Capstone disassembly framework (optional for instruction analysis)

Build command:

```
clang++ -std=c++17 -o macho_reveng macho_reveng.cpp -lcapstone
```

## Usage 

### Static analysis

```
./macho_reveng /path/to/binary
```

### Dynamic analysis

```
./macho_reveng -p 1234
```

## Extending with new scanners

```
class stack_cookie_scanner : public vulnerability_scanner {
public:
    void scan_static(const macho_binary_analyzer& binary) override {
        log_msg(LOG_INFO, "checking stack cookies", get_name());
    }
    void scan_dynamic(process_inspector& proc) override {
        log_msg(LOG_INFO, "checking runtime stack protection", get_name());
    }
    std::string get_name() const override { return "stack_cookie_scanner"; }
};
```






