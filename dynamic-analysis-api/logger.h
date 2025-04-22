#pragma once
#include <windows.h>
#include <string>
#include <mutex>
#include <iomanip>
#include <sstream>

class logger {
public:
    static void init(const std::wstring& log_file = L"api_monitor.log") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (h_log_file_ == INVALID_HANDLE_VALUE) {
            h_log_file_ = CreateFileW(
                log_file.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
        }
    }

    static void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);

        SYSTEMTIME st;
        GetLocalTime(&st);

        std::stringstream ss;
        ss << "[" << std::setw(2) << st.wHour << ":"
           << std::setw(2) << st.wMinute << ":"
           << std::setw(2) << st.wSecond << "."
           << std::setw(3) << st.wMilliseconds << "] "
           << message << "\n";

        std::cout << ss.str();

        if (h_log_file_ != INVALID_HANDLE_VALUE) {
            DWORD bytes_written;
            WriteFile(h_log_file_, ss.str().c_str(), static_cast<DWORD>(ss.str().length()), &bytes_written, nullptr);
        }
    }

    static void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (h_log_file_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_log_file_);
            h_log_file_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    static HANDLE h_log_file_;
    static std::mutex mutex_;
};

HANDLE logger::h_log_file_ = INVALID_HANDLE_VALUE;
std::mutex logger::mutex_;