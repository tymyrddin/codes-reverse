// memory_analysis.h
#pragma once

#include <cstddef>
#include <string>
#include <functional>
#include <memory>

class MemoryAnalysisSystem {
public:
    enum class Tool {
        NONE,
        ADDRESS_SANITIZER,
        VALGRIND,
        CUSTOM_ALLOCATOR
    };

    static void initialize(Tool selected_tool = detect_available_tool());
    static void shutdown();

    static void track_allocation(void* ptr, size_t size, const char* file = nullptr, int line = 0);
    static void track_deallocation(void* ptr);
    static void verify_memory_integrity();
    static void check_for_leaks();

    static void set_violation_handler(std::function<void(const std::string&)> handler);
    static void register_atexit_handler();

    static Tool current_tool();

private:
    static Tool detect_available_tool();
    static void default_violation_handler(const std::string& message);

    // Implementation details
    class Impl;
    static std::unique_ptr<Impl> impl_;
};