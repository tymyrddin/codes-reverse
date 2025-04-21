#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

class AntiREAnalyzer {
public:
    AntiREAnalyzer(DWORD pid) : processId(pid), hProcess(NULL) {
        initialize();
    }

    ~AntiREAnalyzer() {
        if (hProcess) CloseHandle(hProcess);
    }

    void analyze() {
        check_debugger_presence();
        check_process_integrity();
        scan_for_anti_re_techniques();
        dump_analysis();
    }

private:
    DWORD processId;
    HANDLE hProcess;
    std::map<std::string, std::vector<std::string>> detectedTechniques;

    void initialize() {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            throw std::runtime_error("Failed to open process");
        }
    }

    void check_debugger_presence() {
        // IsDebuggerPresent check
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(hProcess, &isDebugged);
        if (isDebugged) {
            detectedTechniques["Debugger Detection"].push_back("IsDebuggerPresent/CheckRemoteDebuggerPresent");
        }

        // NtGlobalFlag check
        DWORD ntGlobalFlag = 0;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            PPEB pPeb = nullptr;
            if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPeb, sizeof(pPeb), nullptr))) {
                ntGlobalFlag = pPeb->BeingDebugged ? 0x70 : 0;
                if (pPeb->BeingDebugged) {
                    detectedTechniques["Debugger Detection"].push_back("PEB.BeingDebugged flag");
                }
            }
        }

        // Hardware breakpoint detection
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                detectedTechniques["Debugger Detection"].push_back("Hardware breakpoints detected");
            }
        }
    }

    void check_process_integrity() {
        // Check for known analysis tools
        const char* analysisTools[] = {
            "ollydbg.exe", "idaq.exe", "idaq64.exe", "windbg.exe",
            "x32dbg.exe", "x64dbg.exe", "immunity debugger.exe", "wireshark.exe",
            "procmon.exe", "processhacker.exe", "fiddler.exe", "regshot.exe"
        };

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                for (const char* tool : analysisTools) {
                    if (processName == tool) {
                        detectedTechniques["Analysis Tool Detection"].push_back(tool);
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);

        // Check for virtualization/sandbox
        check_sandbox_indicators();
    }

    void check_sandbox_indicators() {
        // Check for common sandbox artifacts
        const char* sandboxFiles[] = {
            "C:\\analysis\\", "C:\\sandbox\\", "C:\\sample\\", "C:\\malware\\",
            "C:\\virus\\", "C:\\danger\\", "C:\\dangerous\\", "C:\\suspicious\\"
        };

        for (const char* path : sandboxFiles) {
            if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
                detectedTechniques["Sandbox Detection"].push_back(std::string("Sandbox path detected: ") + path);
            }
        }

        // Check for small memory (common in sandboxes)
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) { // Less than 2GB
            detectedTechniques["Sandbox Detection"].push_back("Low memory detected (possible sandbox)");
        }

        // Check for fast execution time (sandboxes often have accelerated clocks)
        DWORD tickCount = GetTickCount();
        Sleep(1000);
        if ((GetTickCount() - tickCount) < 900) {
            detectedTechniques["Sandbox Detection"].push_back("Accelerated clock detected");
        }
    }

    void scan_for_anti_re_techniques() {
        scan_for_debug_checks();
        scan_for_timing_checks();
        scan_for_code_obfuscation();
        scan_for_api_hooking();
    }

    void scan_for_debug_checks() {
        // Scan for common debug check patterns
        BYTE int3Pattern[] = { 0xCC };
        BYTE int2dPattern[] = { 0xCD, 0x03 };
        BYTE debugCheckPattern[] = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00 }; // PEB access

        scan_memory_for_pattern(int3Pattern, sizeof(int3Pattern), "INT3 breakpoint instruction");
        scan_memory_for_pattern(int2dPattern, sizeof(int2dPattern), "INT 2D debugger trap");
        scan_memory_for_pattern(debugCheckPattern, sizeof(debugCheckPattern), "Direct PEB access for debug check");
    }

    void scan_for_timing_checks() {
        // Scan for RDTSC instructions
        BYTE rdtscPattern[] = { 0x0F, 0x31 };
        scan_memory_for_pattern(rdtscPattern, sizeof(rdtscPattern), "RDTSC timing check");

        // Scan for QueryPerformanceCounter calls
        scan_for_api_call("kernel32.dll", "QueryPerformanceCounter", "Timing check");
    }

    void scan_for_code_obfuscation() {
        // Scan for common packer signatures
        const char* packers[] = {
            "UPX", "ASPack", "Themida", "VMProtect", "Armadillo", "Obsidium"
        };

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    for (const char* packer : packers) {
                        if (strstr(szModName, packer)) {
                            detectedTechniques["Code Obfuscation"].push_back(std::string("Packer detected: ") + packer);
                        }
                    }
                }
            }
        }

        // Scan for TLS callbacks (common in protectors)
        scan_for_tls_callbacks();
    }

    void scan_for_api_hooking() {
        // Check for IAT hooks
        scan_for_iat_hooks();

        // Check for inline hooks
        scan_for_inline_hooks();
    }

    void scan_memory_for_pattern(const BYTE* pattern, size_t patternSize, const std::string& technique) {
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = 0;

        while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i < bytesRead - patternSize; i++) {
                        if (memcmp(buffer.data() + i, pattern, patternSize) == 0) {
                            detectedTechniques["Anti-RE Techniques"].push_back(technique);
                            break;
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
    }

    void scan_for_api_call(const char* moduleName, const char* apiName, const std::string& technique) {
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (!hModule) return;

        FARPROC apiAddr = GetProcAddress(hModule, apiName);
        if (!apiAddr) return;

        BYTE callPattern[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 }; // CALL rel32
        DWORD offset = (DWORD)apiAddr - (DWORD)hModule - 5;
        memcpy(callPattern + 1, &offset, 4);

        scan_memory_for_pattern(callPattern, sizeof(callPattern), technique + " (" + apiName + ")");
    }

    void scan_for_tls_callbacks() {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;

        if (!ReadProcessMemory(hProcess, (LPCVOID)0x400000, &dosHeader, sizeof(dosHeader), NULL)) return;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(0x400000 + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL)) return;

        IMAGE_DATA_DIRECTORY tlsDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDirectory.VirtualAddress) {
            detectedTechniques["Code Obfuscation"].push_back("TLS callbacks detected");
        }
    }

    void scan_for_iat_hooks() {
        // Simplified IAT hook detection
        HMODULE hModule = GetModuleHandleA(NULL);
        IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + pDosHeader->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDesc->Name) {
            char* moduleName = (char*)((BYTE*)hModule + pImportDesc->Name);
            IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);

            while (pThunk->u1.AddressOfData) {
                IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + pThunk->u1.AddressOfData);
                FARPROC originalFunc = GetProcAddress(GetModuleHandleA(moduleName), (char*)pImport->Name);
                FARPROC iatFunc = (FARPROC)((BYTE*)hModule + pThunk->u1.Function);

                if (originalFunc != iatFunc) {
                    detectedTechniques["API Hooking"].push_back(std::string("IAT hook detected: ") + moduleName + "!" + (char*)pImport->Name);
                }
                pThunk++;
            }
            pImportDesc++;
        }
    }

    void scan_for_inline_hooks() {
        // Check for jumps at function prologues
        HMODULE hModule = GetModuleHandleA("kernel32.dll");
        FARPROC apiAddr = GetProcAddress(hModule, "CreateFileA");

        BYTE prologue[5];
        if (ReadProcessMemory(hProcess, apiAddr, prologue, sizeof(prologue), NULL)) {
            if (prologue[0] == 0xE9 || prologue[0] == 0xEB) { // JMP or JMP rel8
                detectedTechniques["API Hooking"].push_back("Inline hook detected in kernel32!CreateFileA");
            }
        }
    }

    void dump_analysis() {
        std::cout << "=== Anti-RE Analysis Report ===\n";
        std::cout << "Process ID: " << processId << "\n\n";

        for (const auto& [category, techniques] : detectedTechniques) {
            std::cout << "[" << category << "]\n";
            for (const auto& tech : techniques) {
                std::cout << "  * " << tech << "\n";
            }
            std::cout << "\n";
        }

        if (detectedTechniques.empty()) {
            std::cout << "No anti-RE techniques detected.\n";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>\n";
        return 1;
    }

    try {
        DWORD pid = atoi(argv[1]);
        AntiREAnalyzer analyzer(pid);
        analyzer.analyze();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}