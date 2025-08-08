// UnhookerTool - Restore Hooked API Bytes (with PE header validation, trampoline detection, and hook source logging)
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdint>   // for int32_t
#include <cstring>   // for memset, memcmp

#pragma comment(lib, "psapi.lib")

static bool ComparePEHeaders(BYTE* loadedBase, BYTE* diskBase) {
    if (!loadedBase || !diskBase) return false;

    IMAGE_DOS_HEADER* dos1 = (IMAGE_DOS_HEADER*)loadedBase;
    IMAGE_DOS_HEADER* dos2 = (IMAGE_DOS_HEADER*)diskBase;
    if (dos1->e_magic != IMAGE_DOS_SIGNATURE || dos2->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS* nt1 = (IMAGE_NT_HEADERS*)(loadedBase + dos1->e_lfanew);
    IMAGE_NT_HEADERS* nt2 = (IMAGE_NT_HEADERS*)(diskBase + dos2->e_lfanew);
    if (nt1->Signature != IMAGE_NT_SIGNATURE || nt2->Signature != IMAGE_NT_SIGNATURE)
        return false;

    return (nt1->OptionalHeader.SizeOfImage == nt2->OptionalHeader.SizeOfImage) &&
           (nt1->FileHeader.TimeDateStamp   == nt2->FileHeader.TimeDateStamp);
}

static void DumpHookTarget(void* addr) {
    if (!addr) return;

    BYTE* p = (BYTE*)addr;

    // Pattern 1: JMP rel32 (E9 xx xx xx xx)
    if (p[0] == 0xE9) {
        int32_t offset = *(int32_t*)(p + 1);
        BYTE* dest = p + 5 + offset;
        std::cout << "[!] JMP Hook detected -> 0x" << std::hex << (void*)dest;

        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            const size_t count = cbNeeded / sizeof(HMODULE);
            for (size_t i = 0; i < count; ++i) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi))) {
                    if ((BYTE*)dest >= (BYTE*)mi.lpBaseOfDll &&
                        (BYTE*)dest <  (BYTE*)mi.lpBaseOfDll + mi.SizeOfImage) {
                        char modName[MAX_PATH]{};
                        GetModuleFileNameA(hMods[i], modName, MAX_PATH);
                        std::cout << " in " << modName;
                        break;
                    }
                }
            }
        }
        std::cout << std::endl;
        return;
    }

    // Pattern 2: 64-bit trampoline "mov rax, imm64; jmp rax"  ->  48 B8 <8 bytes> FF E0
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
        void* dest = *(void**)(p + 2);
        std::cout << "[!] 64-bit trampoline -> 0x" << std::hex << dest;

        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            const size_t count = cbNeeded / sizeof(HMODULE);
            for (size_t i = 0; i < count; ++i) {
                MODULEINFO mi{};
                if (GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi))) {
                    if ((BYTE*)dest >= (BYTE*)mi.lpBaseOfDll &&
                        (BYTE*)dest <  (BYTE*)mi.lpBaseOfDll + mi.SizeOfImage) {
                        char modName[MAX_PATH]{};
                        GetModuleFileNameA(hMods[i], modName, MAX_PATH);
                        std::cout << " in " << modName;
                        break;
                    }
                }
            }
        }
        std::cout << std::endl;
    }
}

static bool RestoreFunctionFromDisk(const char* dllName, const char* funcName) {
    if (!dllName || !funcName) return false;

    HMODULE hMod = GetModuleHandleA(dllName);
    if (!hMod) return false;

    FARPROC hookedFunc = GetProcAddress(hMod, funcName);
    if (!hookedFunc) return false;

    DumpHookTarget((void*)hookedFunc);

    char sysPath[MAX_PATH]{};
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat_s(sysPath, "\\");
    strcat_s(sysPath, dllName);

    HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* diskBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!diskBase) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    BYTE* memBase = (BYTE*)hMod;

    if (!ComparePEHeaders(memBase, diskBase)) {
        std::cout << "[-] PE headers differ for " << dllName << ". Using fallback.\n";

        DWORD oldProtect = 0;
        if (VirtualProtect((LPVOID)hookedFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            BYTE* patch = (BYTE*)hookedFunc;

            if (patch[0] == 0xE9) {
                std::cout << "[~] JMP stub found. Neutralizing inline hook for " << funcName << std::endl;
                memset(patch, 0x90, 5); // NOP the 5-byte JMP
            } else if (patch[0] == 0x48 && patch[1] == 0xB8 && patch[10] == 0xFF && patch[11] == 0xE0) {
                std::cout << "[~] 64-bit trampoline detected. Neutralizing for " << funcName << std::endl;
                memset(patch, 0x90, 12); // NOP the whole trampoline
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

    // Safe path: copy pristine bytes from a clean mapped instance
    HMODULE cleanMod = LoadLibraryExA(sysPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!cleanMod) {
        UnmapViewOfFile(diskBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    FARPROC cleanFunc = GetProcAddress(cleanMod, funcName);
    if (!cleanFunc) {
        FreeLibrary(cleanMod);
        UnmapViewOfFile(diskBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect((LPVOID)hookedFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        FreeLibrary(cleanMod);
        UnmapViewOfFile(diskBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }
    std::memcpy(
        reinterpret_cast<void*>(hookedFunc),
        reinterpret_cast<const void*>(cleanFunc),
        16
    );

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
        {"ntdll.dll",  "NtOpenProcess"},
        {"kernel32.dll","CreateFileW"},
        {"kernel32.dll","VirtualAllocEx"},
        {"kernel32.dll","ReadFile"},
        {"kernel32.dll","WriteFile"},
    };

    for (auto& target : targets) {
        RestoreFunctionFromDisk(target.first, target.second);
    }

    return 0;
}
