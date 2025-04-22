# PE/ELF header parser

A program that can parse both PE (Portable Executable, Windows) and ELF (Executable and Linkable Format, Linux) file 
headers for binary analysis.

[parser.cpp](parser.cpp)


## Features

* Handles both 32-bit and 64-bit PE/ELF executables
* Properly distinguishes between PE32 and PE32+ formats
* Handles both ELF32 and ELF64 structures
* For ELF: Parses and displays all section headers and program headers
* For PE: Parses and displays all section headers
* Shows detailed information including addresses, sizes, and flags
* Comprehensive header information: Extracts and displays key header fields
* Error handling: Proper error checking for malformed files
* Portable: Uses standard C++ with no platform-specific code (except for the PE/ELF structures)

## Compile

Compile with:

```commandline
g++ -o parser parser.cpp -std=c++11
```

## Usage

Run against an executable:

```commandline
./parser /path/to/executable
```
