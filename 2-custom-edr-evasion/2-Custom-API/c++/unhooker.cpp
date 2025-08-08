// UnhookerTool - Restore Hooked API Bytes (with PE header validation, trampoline detection, and hook source logging)

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

bool ComparePEHeaders(BYTE* loadedBase, BYTE* diskBase) {
    IMAGE_DOS_HEADER* dos1 = (IMAGE_DOS_HEADER*)loadedBase;
    IMAGE_DOS_HEADER* dos2 = (IMAGE_DOS_HEADER*)diskBase;
    if (dos1->e_magic != IMAGE_DOS_SIGNATURE || dos2->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS* nt1 = (IMAGE_NT_HEADERS*)(loadedBase + dos1->e_lfanew);
    IMAGE_NT_HEADERS* nt2 = (IMAGE_NT_HEADERS*)(diskBase + dos2->e_lfanew);

    return (nt1->OptionalHeader.SizeOfImage == nt2->OptionalHeader.SizeOfImage) &&
           (nt1->FileHeader.TimeDateStamp == nt2->FileHeader.TimeDateStamp);
}

void DumpHookTarget(void* addr) {
    BYTE* p = (BYTE*)addr;
    if (p[0] == 0xE9) { // JMP rel32
        int32_t offset = *(int32_t*)(p + 1);
        BYTE* dest = p + 5 + offset;
        std::cout << "[!] JMP Hook detected → 0x" << std::hex << (void*)dest;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            for (size_t i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                MODULEINFO mi;
                GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi));
                if ((BYTE*)dest >= (BYTE*)mi.lpBaseOfDll && (BYTE*)dest < ((BYTE*)mi.lpBaseOfDll + mi.SizeOfImage)) {
                    char modName[MAX_PATH];
                    GetModuleFileNameA(hMods[i], modName, MAX_PATH);
                    std::cout << " in " << modName;
                }
            }
        }
        std::cout << std::endl;
    }
    else if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) { // mov rax, addr; jmp rax
        void* dest = *(void**)(p + 2);
        std::cout << "[!] 64-bit trampoline → 0x" << std::hex << dest;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            for (size_t i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                MODULEINFO mi;
                GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi));
                if ((BYTE*)dest >= (BYTE*)mi.lpBaseOfDll && (BYTE*)dest < ((BYTE*)mi.lpBaseOfDll + mi.SizeOfImage)) {
                    char modName[MAX_PATH];
                    GetModuleFileNameA(hMods[i], modName, MAX_PATH);
                    std::cout << " in " << modName;
                }
            }
        }
        std::cout << std::endl;
    }
}

bool RestoreFunctionFromDisk(const char* dllName, const char* funcName) {
    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) return false;

    FARPROC hookedFunc = GetProcAddress(hMod, funcName);
    if (!hookedFunc) return false;

    DumpHookTarget((void*)hookedFunc);

    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat_s(sysPath, "\\");
    strcat_s(sysPath, dllName);

    HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, fileSize, NULL);
    BYTE* diskBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    BYTE* memBase = (BYTE*)hMod;

    if (!ComparePEHeaders(memBase, diskBase)) {
        std::cout << "[-] PE headers differ for " << dllName << ". Using fallback.\n";

        DWORD oldProtect;
        if (VirtualProtect((LPVOID)hookedFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            BYTE* patch = (BYTE*)hookedFunc;
            if (patch[0] == 0xE9) {
                std::cout << "[~] JMP stub found. Neutralizing inline hook for " << funcName << std::endl;
                memset(patch, 0x90, 5);
            } else if (patch[0] == 0x48 && patch[1] == 0xB8 && patch[10] == 0xFF && patch[11] == 0xE0) {
                std::cout << "[~] 64-bit trampoline detected. Neutralizing for " << funcName << std::endl;
                memset(patch, 0x90, 12);
            } else {
                std::cout << "[!] No known hook pattern for " << funcName << std::endl;
            }
            VirtualProtect((LPVOID)hookedFunc, 16, oldProtect, &oldProtect);
        }

        UnmapViewOfFile(diskBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    HMODULE cleanMod = LoadLibraryExA(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!cleanMod) return false;

    FARPROC cleanFunc = GetProcAddress(cleanMod, funcName);
    if (!cleanFunc) return false;

    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)hookedFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        FreeLibrary(cleanMod);
        return false;
    }

    memcpy((void*)hookedFunc, cleanFunc, 16);

    VirtualProtect((LPVOID)hookedFunc, 16, oldProtect, &oldProtect);
    FreeLibrary(cleanMod);
    UnmapViewOfFile(diskBase);
    CloseHandle(hMap);
    CloseHandle(hFile);

    std::cout << "[+] Unhooked " << funcName << " in " << dllName << std::endl;
    return true;
}

int main() {
    std::vector<std::pair<const char*, const char*>> targets = {
        {"ntdll.dll", "NtOpenProcess"},
        {"kernel32.dll", "CreateFileW"},
        {"kernel32.dll", "VirtualAllocEx"},
        {"kernel32.dll", "ReadFile"},
        {"kernel32.dll", "WriteFile"},
    };

    for (auto& target : targets) {
        RestoreFunctionFromDisk(target.first, target.second);
    }

    return 0;
}
