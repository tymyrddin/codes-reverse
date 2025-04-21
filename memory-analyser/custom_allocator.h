// custom_allocator.h
#pragma once

#include "memory_integration.h"
#include <cstdlib>
#include <new>

class TrackingAllocator {
public:
    static void* allocate(size_t size) {
        void* ptr = malloc(size + CANARY_SIZE);
        if (!ptr) throw std::bad_alloc();

        MEM_TRACK_ALLOC(ptr, size);
        return ptr;
    }

    static void deallocate(void* ptr) noexcept {
        if (!ptr) return;

        MEM_TRACK_FREE(ptr);
        free(ptr);
    }

    static void* reallocate(void* ptr, size_t new_size) {
        if (!ptr) return allocate(new_size);

        MEM_TRACK_FREE(ptr);
        void* new_ptr = realloc(ptr, new_size + CANARY_SIZE);
        if (!new_ptr) throw std::bad_alloc();

        MEM_TRACK_ALLOC(new_ptr, new_size);
        return new_ptr;
    }

private:
    static constexpr size_t CANARY_SIZE = sizeof(uint8_t);
};