# Memory analysis

* [memory_analysis.h](memory_analysis.h)
* [memory_analysis.cpp](memory_analysis.cpp)
* [custom_allocator.h](custom_allocator.h)
* [Makefile](Makefile)
* [usage.cpp](usage.cpp)

## Features

* Multi-Tool Support: Works with AddressSanitizer, Valgrind, or custom tracking
* Thread Safety: All tracking operations are mutex-protected
* Comprehensive Tracking: Records file/line information for allocations
* Canary Protection: Detects buffer overflows in custom allocator mode
* Configurable Violation Handling: Custom handlers for different environments
* Low Overhead: Minimal impact when disabled in release builds
* Automatic Leak Detection: Integrated atexit handler for leak checking
* Build System Integration: Easy to enable/disable through compiler flags