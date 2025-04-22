# Linux Reverse Engineering framework

A framework for reverse engineering Linux applications to identify vulnerabilities.

## Features

ELF Parser

* Handles 32/64-bit ELF binaries
* Extracts sections, segments & symbols
* Checks security features (NX, PIE, RELRO)

Dynamic Analysis

* Process attachment via ptrace
* Safe memory reading operations
* Breakpoint support (unimplemented stub)

Vulnerability Detection

* Stack Canary Detection
* Format String Checks
* Modular scanner system (easy to extend)

Production-Grade Infrastructure

* Tiered logging (debug → critical)
* RAII resource management
* Detailed error handling with module context

## Building and dependencies

Requirements to build:

* C++17 compiler
* Capstone disassembly framework (for instruction analysis)
* Standard Linux development headers

Example build command:
bash
```
g++ -std=c++17 -o elf_reveng elf_reveng.cpp -lcapstone -ldl
```

## Usage

### Basic

```
# Analyze an ELF binary
./elf_reveng <path_to_binary>

# Example:
./elf_reveng /usr/bin/ls
```

Output format:

```
[INFO] [binary_analyzer] Starting analysis of: /usr/bin/ls
[INFO] [stack_canary_scanner] Scanning for stack canary vulnerabilities
[INFO] [format_string_scanner] Scanning for format string vulnerabilities
[INFO] [binary_analyzer] Completed analysis of: /usr/bin/ls
```

### Static analysis

```
binary_analyzer bin("target.elf");
bin.analyze();
```

### Dynamic analysis

```
process_tracer tracer(pid);
tracer.attach();
// Read memory/set breakpoints
```

### Error handling

* All errors include module context
* Log levels: debug → critical
* RAII for resource cleanup

## Extending the framework

### Included scanners

* `stack_canary_scanner`: Checks for stack protection mechanisms
* `format_string_scanner`: Detects format string vulnerabilities

### Adding a new vulnerability scanner

* Create a class inheriting from VulnerabilityScanner
* Implement the scan() and name() methods
* Register your scanner with the ReverseEngineeringEngine

### Example

1. Create a new scanner class:

```
class heap_overflow_scanner : public vulnerability_scanner {
public:
    void scan(const binary_analyzer& binary) override {
        logger::log(logger::level::info, "checking for heap overflows", name());
    }
    std::string name() const override { return "heap_overflow_scanner"; }
};
```

2. Register it in main()

```
engine.register_scanner(std::make_unique<heap_overflow_scanner>());
```

