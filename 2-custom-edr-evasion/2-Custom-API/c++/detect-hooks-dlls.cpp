#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "psapi.lib")

std::vector<std::string> suspicious_keywords = {
    "openhid", "edr", "sensor", "agent"
};

bool IsSuspiciousModule(const std::string& modName) {
    for (auto& keyword : suspicious_keywords) {
        if (modName.find(keyword) != std::string::npos)
            return true;
    }
    return false;
}

void ListModules(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process: " << pid << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    char szModName[MAX_PATH];

    std::cout << "\n[+] Loaded modules for PID: " << pid << std::endl;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string mod = szModName;
                std::cout << "  " << mod << std::endl;
                if (IsSuspiciousModule(mod)) {
                    std::cout << "  --> [!!] Suspicious module detected!" << std::endl;
                }
            }
        }
    }
    CloseHandle(hProcess);
}

bool CheckInlineHook(LPCSTR dll, LPCSTR function) {
    HMODULE hMod = GetModuleHandleA(dll);
    if (!hMod) return false;

    FARPROC pFunc = GetProcAddress(hMod, function);
    if (!pFunc) return false;

    BYTE* bytes = reinterpret_cast<BYTE*>(pFunc);

    if (bytes[0] == 0xE9) {
        std::cout << "[!] Inline hook detected on " << dll << "!" << std::endl;
        return true;
    }

    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        std::cout << "[!] Push-Ret hook detected on " << dll << "!" << std::endl;
        return true;
    }

    return false;
}

bool CompareFuncBytes(LPCSTR dll, LPCSTR func) {
    HMODULE hMod = GetModuleHandleA(dll);
    FARPROC pFunc = GetProcAddress(hMod, func);

    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat_s(sysPath, "\\");
    strcat_s(sysPath, dll);

    HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, fileSize, NULL);
    if (!hMap) return false;

    LPVOID lpMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!lpMap) return false;

    HMODULE hRefMod = LoadLibraryExA(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    FARPROC pRefFunc = GetProcAddress(hRefMod, func);

    bool tampered = memcmp((void*)pFunc, (void*)pRefFunc, 16) != 0;

    if (tampered)
        std::cout << "[!!] Memory/disk mismatch for " << func << " in " << dll << std::endl;

    FreeLibrary(hRefMod);
    UnmapViewOfFile(lpMap);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return tampered;
}

int main() {
    DWORD pid = GetCurrentProcessId();
    ListModules(pid);

    std::vector<std::pair<const char*, const char*>> apis = {
        {"kernel32.dll", "CreateFileW"},
        {"ntdll.dll", "NtOpenProcess"},
        {"kernel32.dll", "WriteFile"},
        {"kernel32.dll", "ReadFile"},
        {"kernel32.dll", "CreateRemoteThread"},
        {"kernel32.dll", "VirtualAllocEx"}
    };

    std::cout << "\n[+] Checking for inline hooks..." << std::endl;
    for (auto& api : apis) {
        CheckInlineHook(api.first, api.second);
    }

    std::cout << "\n[+] Comparing memory vs disk for tampering..." << std::endl;
    for (auto& api : apis) {
        CompareFuncBytes(api.first, api.second);
    }

    return 0;
}
