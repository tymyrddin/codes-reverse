#pragma once
#include <windows.h>
#include <string>
#include "hook_engine.h"
#include "logger.h"

// File System APIs
typedef HANDLE(WINAPI* create_file_w_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* write_file_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* read_file_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* delete_file_w_t)(LPCWSTR);

// Process/Thread APIs
typedef BOOL(WINAPI* create_process_w_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// Network APIs
typedef int (WSAAPI* connect_t)(SOCKET, const sockaddr*, int);

namespace api_hooks {
    HANDLE WINAPI hooked_create_file_w(LPCWSTR lp_file_name, DWORD desired_access, DWORD share_mode,
                                    LPSECURITY_ATTRIBUTES security_attrs, DWORD creation_disp,
                                    DWORD flags_and_attrs, HANDLE template_file);

    BOOL WINAPI hooked_write_file(HANDLE file, LPCVOID buffer, DWORD bytes_to_write,
                                LPDWORD bytes_written, LPOVERLAPPED overlapped);

    BOOL WINAPI hooked_read_file(HANDLE file, LPVOID buffer, DWORD bytes_to_read,
                               LPDWORD bytes_read, LPOVERLAPPED overlapped);

    BOOL WINAPI hooked_delete_file_w(LPCWSTR file_name);

    BOOL WINAPI hooked_create_process_w(LPCWSTR app_name, LPWSTR cmd_line,
                                      LPSECURITY_ATTRIBUTES proc_attrs,
                                      LPSECURITY_ATTRIBUTES thread_attrs, BOOL inherit_handles,
                                      DWORD creation_flags, LPVOID env, LPCWSTR current_dir,
                                      LPSTARTUPINFOW startup_info, LPPROCESS_INFORMATION proc_info);

    int WSAAPI hooked_connect(SOCKET s, const sockaddr* name, int name_len);
}

class api_monitor {
public:
    static void install_hooks() {
        // File System
        install_hook("kernel32.dll", "CreateFileW", api_hooks::hooked_create_file_w);
        install_hook("kernel32.dll", "WriteFile", api_hooks::hooked_write_file);
        install_hook("kernel32.dll", "ReadFile", api_hooks::hooked_read_file);
        install_hook("kernel32.dll", "DeleteFileW", api_hooks::hooked_delete_file_w);

        // Process
        install_hook("kernel32.dll", "CreateProcessW", api_hooks::hooked_create_process_w);

        // Network
        install_hook("ws2_32.dll", "connect", api_hooks::hooked_connect);
    }

    static void remove_hooks() {
        for (auto& hook : hooks_) {
            hook_engine::remove_hook(hook.second);
        }
        hooks_.clear();
    }

private:
    static void install_hook(const char* dll_name, const char* func_name, LPVOID hook_func) {
        LPVOID target_func = hook_engine::get_function_address(dll_name, func_name);
        if (!target_func) {
            logger::log(std::string("Failed to find ") + func_name + " in " + dll_name);
            return;
        }

        hook_info info;
        if (hook_engine::install_hook(target_func, hook_func, info)) {
            hooks_[target_func] = info;
            logger::log(std::string("Successfully hooked ") + func_name);
        } else {
            logger::log(std::string("Failed to hook ") + func_name);
        }
    }

    static std::map<LPVOID, hook_info> hooks_;
};

std::map<LPVOID, hook_info> api_monitor::hooks_;