#pragma once
#include <windows.h>
#include <map>
#include <vector>
#include "logger.h"

struct hook_info {
    LPVOID original_function;
    LPVOID hook_function;
    BYTE original_bytes[20];
    BYTE jump_bytes[20];
    bool is_hooked;
};

class hook_engine {
public:
    static bool install_hook(LPVOID target_func, LPVOID hook_func, hook_info& info) {
        if (!target_func || !hook_func) return false;

        info.original_function = target_func;
        info.hook_function = hook_func;
        info.is_hooked = false;

        memcpy(info.original_bytes, target_func, sizeof(info.original_bytes));

#ifdef _WIN64
        info.jump_bytes[0] = 0xFF;
        info.jump_bytes[1] = 0x25;
        *reinterpret_cast<DWORD*>(&info.jump_bytes[2]) = 0;
        *reinterpret_cast<ULONG_PTR*>(&info.jump_bytes[6]) = reinterpret_cast<ULONG_PTR>(hook_func);
#else
        info.jump_bytes[0] = 0xE9;
        *reinterpret_cast<DWORD*>(&info.jump_bytes[1]) =
            reinterpret_cast<DWORD>(hook_func) - reinterpret_cast<DWORD>(target_func) - 5;
#endif

        DWORD old_protect;
        if (!VirtualProtect(target_func, sizeof(info.jump_bytes), PAGE_EXECUTE_READWRITE, &old_protect)) {
            return false;
        }

        memcpy(target_func, info.jump_bytes, sizeof(info.jump_bytes));

        DWORD temp;
        VirtualProtect(target_func, sizeof(info.jump_bytes), old_protect, &temp);

        info.is_hooked = true;
        return true;
    }

    static bool remove_hook(hook_info& info) {
        if (!info.is_hooked) return true;

        DWORD old_protect;
        if (!VirtualProtect(info.original_function, sizeof(info.original_bytes), PAGE_EXECUTE_READWRITE, &old_protect)) {
            return false;
        }

        memcpy(info.original_function, info.original_bytes, sizeof(info.original_bytes));

        DWORD temp;
        VirtualProtect(info.original_function, sizeof(info.original_bytes), old_protect, &temp);

        info.is_hooked = false;
        return true;
    }

    static LPVOID get_function_address(const wchar_t* dll_name, const char* func_name) {
        HMODULE h_module = GetModuleHandleW(dll_name);
        if (!h_module) {
            h_module = LoadLibraryW(dll_name);
            if (!h_module) {
                return nullptr;
            }
        }
        return GetProcAddress(h_module, func_name);
    }
};