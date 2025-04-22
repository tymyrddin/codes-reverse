#include "api_monitor.h"
#include <tlhelp32.h>
#include <iostream>

DWORD find_process_id(const std::wstring& process_name) {
    PROCESSENTRY32W process_info;
    process_info.dwSize = sizeof(process_info);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32FirstW(snapshot, &process_info);
    if (!process_name.compare(process_info.szExeFile)) {
        CloseHandle(snapshot);
        return process_info.th32ProcessID;
    }

    while (Process32NextW(snapshot, &process_info)) {
        if (!process_name.compare(process_info.szExeFile)) {
            CloseHandle(snapshot);
            return process_info.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return 0;
}

DWORD WINAPI injection_thread(LPVOID lp_param) {
    DWORD pid = *reinterpret_cast<DWORD*>(lp_param);
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!process) {
        logger::log("Failed to open target process");
        return 1;
    }

    api_monitor::install_hooks();
    logger::log("Hooks installed successfully");

    while (true) {
        Sleep(1000);
    }

    api_monitor::remove_hooks();
    CloseHandle(process);
    return 0;
}

int main() {
    logger::init();

    std::wstring target_process;
    std::wcout << L"Enter target process name (e.g., notepad.exe): ";
    std::wcin >> target_process;

    DWORD pid = find_process_id(target_process);
    if (pid == 0) {
        logger::log("Target process not found");
        logger::shutdown();
        return 1;
    }

    logger::log("Found target process with PID: " + std::to_string(pid));

    HANDLE thread = CreateThread(nullptr, 0, injection_thread, &pid, 0, nullptr);
    if (!thread) {
        logger::log("Failed to create injection thread");
        logger::shutdown();
        return 1;
    }

    logger::log("Monitoring started. Press Enter to stop...");
    std::cin.ignore();
    std::cin.get();

    TerminateThread(thread, 0);
    CloseHandle(thread);
    api_monitor::remove_hooks();
    logger::shutdown();
    return 0;
}