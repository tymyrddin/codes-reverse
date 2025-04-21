# Virtual Function Reverse Engineering Tool

This tool provides comprehensive analysis capabilities for reverse engineering 
C++ binaries, particularly useful for malware analysis where understanding 
object-oriented structures is crucial.

## Build instructions

```commandline
# Install Capstone library:
sudo apt-get install libcapstone-dev

# Compile with:
g++ -std=c++17 -ldl -lcapstone -o vtable_analyser vtable_analyser.cpp

# Run against a binary:
./vtable_analyser /path/to/binary [output.txt]
```

## Example Output:

```commandline
=== Virtual Table at 0x55a1b2d3b280 ===
Module: ./malware_sample
Class: MalwareCore

Virtual Functions:
  [0] 0x55a1b2d3a110  mov rdi, rbx | call 0x55a1b2d3a200 | ret
  [1] 0x55a1b2d3a150  push rbp | mov rbp, rsp | sub rsp, 0x20
  [2] 0x55a1b2d3a190  jmp 0x55a1b2d3a250 | nop | nop

Cross-References:
  0x55a1b2d3b300 references:
    -> 0x55a1b2d3a150
    -> 0x55a1b2d3a190
```

## Features

Virtual Table Detection:

* Scans memory for patterns matching virtual function tables
* Validates potential vtables by checking function pointer sequences
* Handles both 32-bit and 64-bit binaries

Memory Analysis:

* Examines executable memory regions
* Works with loaded modules in the process address space
* Includes basic memory protection handling

Complete RTTI Analysis:

* Parses typeinfo structures to extract class names
* Handles both GCC and MSVC RTTI formats
* Includes basic name demangling

Cross-Reference Analysis:

* Finds all references between virtual tables
* Tracks which functions reference which vtables
* Uses Capstone engine to disassemble and analyze instructions

Function Disassembly:

* Disassembles the first few instructions of each virtual function
* Shows mnemonics and operands for quick analysis
* Identifies direct vtable references in code

Output Generation:

* Detailed dump of discovered virtual tables
* Function pointer listings with indices
* Module origin information for each vtable

Malware Analysis Capabilities:

* Can analyze packed binaries when properly loaded
* Works with position-independent code (PIC/PIE)
* Handles C++ RTTI when available

## Limitations and considerations

* Memory Protection: Some pages may not be readable without special privileges
* False Positives: Data structures may coincidentally look like vtables
* Packed Binaries: May require unpacking before analysis
* Anti-RE Techniques: Malware may employ vtable obfuscation