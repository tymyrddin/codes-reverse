// memory_analysis.cpp
#include "memory_analysis.h"
#include <unordered_map>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <mutex>

#ifdef __SANITIZE_ADDRESS__
constexpr bool ASAN_ENABLED = true;
#else
constexpr bool ASAN_ENABLED = false;
#endif

class MemoryAnalysisSystem::Impl {
public:
    struct AllocationInfo {
        size_t size;
        std::string file;
        int line;
        uint8_t canary;
    };

    std::unordered_map<void*, AllocationInfo> active_allocations;
    std::function<void(const std::string&)> violation_handler;
    std::mutex allocation_mutex;
    MemoryAnalysisSystem::Tool active_tool;

    Impl(Tool tool) : active_tool(tool) {}

    void add_allocation(void* ptr, size_t size, const char* file, int line) {
        std::lock_guard<std::mutex> lock(allocation_mutex);

        if (active_tool == Tool::CUSTOM_ALLOCATOR) {
            uint8_t* canary_location = static_cast<uint8_t*>(ptr) + size;
            *canary_location = 0xAA;

            active_allocations[ptr] = {
                size,
                file ? file : "unknown",
                line,
                0xAA
            };
        }
    }

    void remove_allocation(void* ptr) {
        std::lock_guard<std::mutex> lock(allocation_mutex);

        if (active_tool != Tool::CUSTOM_ALLOCATOR) return;

        auto it = active_allocations.find(ptr);
        if (it == active_allocations.end()) {
            report_violation("Invalid deallocation of untracked pointer");
            return;
        }

        const auto& info = it->second;
        uint8_t* canary_location = static_cast<uint8_t*>(ptr) + info.size;
        if (*canary_location != 0xAA) {
            report_violation("Buffer overflow detected in allocation from " +
                           info.file + ":" + std::to_string(info.line));
        }

        active_allocations.erase(it);
    }

    void verify_all_allocations() {
        std::lock_guard<std::mutex> lock(allocation_mutex);

        if (active_tool != Tool::CUSTOM_ALLOCATOR) return;

        for (const auto& entry : active_allocations) {
            const auto& info = entry.second;
            uint8_t* canary_location = static_cast<uint8_t*>(entry.first) + info.size;
            if (*canary_location != 0xAA) {
                report_violation("Buffer overflow detected in allocation from " +
                                info.file + ":" + std::to_string(info.line));
            }
        }
    }

    void check_leaks() {
        std::lock_guard<std::mutex> lock(allocation_mutex);

        if (active_tool != Tool::CUSTOM_ALLOCATOR) return;

        if (!active_allocations.empty()) {
            std::string message = "Memory leaks detected:\n";
            for (const auto& entry : active_allocations) {
                const auto& info = entry.second;
                message += "  " + std::to_string(info.size) + " bytes at " +
                          info.file + ":" + std::to_string(info.line) + "\n";
            }
            report_violation(message);
        }
    }

    void report_violation(const std::string& message) {
        if (violation_handler) {
            violation_handler(message);
        } else {
            default_violation_handler(message);
        }
    }

    static void default_violation_handler(const std::string& message) {
        std::cerr << "MEMORY VIOLATION: " << message << std::endl;
    }
};

std::unique_ptr<MemoryAnalysisSystem::Impl> MemoryAnalysisSystem::impl_;

MemoryAnalysisSystem::Tool MemoryAnalysisSystem::detect_available_tool() {
    if (ASAN_ENABLED) {
        return Tool::ADDRESS_SANITIZER;
    }
    return Tool::CUSTOM_ALLOCATOR;
}

void MemoryAnalysisSystem::initialize(Tool selected_tool) {
    if (impl_) return;

    Tool actual_tool = selected_tool;
    if (selected_tool == Tool::NONE) {
        actual_tool = detect_available_tool();
    }

    impl_ = std::make_unique<Impl>(actual_tool);

    if (actual_tool == Tool::CUSTOM_ALLOCATOR) {
        std::atexit([](){
            MemoryAnalysisSystem::check_for_leaks();
        });
    }
}

void MemoryAnalysisSystem::shutdown() {
    impl_.reset();
}

void MemoryAnalysisSystem::track_allocation(void* ptr, size_t size, const char* file, int line) {
    if (impl_) {
        impl_->add_allocation(ptr, size, file, line);
    }
}

void MemoryAnalysisSystem::track_deallocation(void* ptr) {
    if (impl_) {
        impl_->remove_allocation(ptr);
    }
}

void MemoryAnalysisSystem::verify_memory_integrity() {
    if (impl_) {
        impl_->verify_all_allocations();
    }
}

void MemoryAnalysisSystem::check_for_leaks() {
    if (impl_) {
        impl_->check_leaks();
    }
}

void MemoryAnalysisSystem::set_violation_handler(std::function<void(const std::string&)> handler) {
    if (impl_) {
        impl_->violation_handler = handler;
    }
}

MemoryAnalysisSystem::Tool MemoryAnalysisSystem::current_tool() {
    return impl_ ? impl_->active_tool : Tool::NONE;
}

Integration Macros
cpp

// memory_integration.h
#pragma once

#include "memory_analysis.h"

#ifdef MEMORY_ANALYSIS_ENABLED

#define MEM_TRACK_ALLOC(ptr, size) \
    MemoryAnalysisSystem::track_allocation(ptr, size, __FILE__, __LINE__)

#define MEM_TRACK_FREE(ptr) \
    MemoryAnalysisSystem::track_deallocation(ptr)

#define MEM_VERIFY_INTEGRITY() \
    MemoryAnalysisSystem::verify_memory_integrity()

#define MEM_INIT() \
    MemoryAnalysisSystem::initialize()

#define MEM_SHUTDOWN() \
    MemoryAnalysisSystem::shutdown()

#else

#define MEM_TRACK_ALLOC(ptr, size)
#define MEM_TRACK_FREE(ptr)
#define MEM_VERIFY_INTEGRITY()
#define MEM_INIT()
#define MEM_SHUTDOWN()

#endif