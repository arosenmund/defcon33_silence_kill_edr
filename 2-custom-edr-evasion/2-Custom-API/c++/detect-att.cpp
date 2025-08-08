// EDRSpy - Full Tool with Remote PEB Walk and Batch Scan

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <winternl.h>
#include <fstream>

#pragma comment(lib, "psapi.lib")

// === Custom Types for PEB LDR Walk ===
typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY_REMOTE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_REMOTE;

typedef struct _PEB_LDR_DATA_REMOTE {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_REMOTE;

typedef struct _PEB_REMOTE {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA_REMOTE* Ldr;
} PEB_REMOTE;

typedef struct _PROCESS_BASIC_INFORMATION_REMOTE {
    PVOID Reserved1;
    PEB_REMOTE* PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_REMOTE;

std::vector<std::string> suspicious_keywords = {"openhid", "edr", "sensor", "agent"};

bool IsSuspiciousModule(const std::string& modName) {
    for (auto& keyword : suspicious_keywords) {
        if (modName.find(keyword) != std::string::npos)
            return true;
    }
    return false;
}

bool IsBackedByFileRemote(HANDLE hProc, void* baseAddr) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQueryEx(hProc, baseAddr, &mbi, sizeof(mbi)))
        return false;

    if (mbi.Type != MEM_IMAGE)
        return false;

    char filename[MAX_PATH];
    if (GetMappedFileNameA(hProc, baseAddr, filename, MAX_PATH) == 0)
        return false;

    return true;
}

bool ReadRemoteUnicodeString(HANDLE hProc, UNICODE_STRING remoteStr, std::wstring& out) {
    if (!remoteStr.Buffer || remoteStr.Length == 0)
        return false;

    wchar_t* buffer = new wchar_t[(remoteStr.Length / 2) + 1]{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, remoteStr.Buffer, buffer, remoteStr.Length, &bytesRead)) {
        delete[] buffer;
        return false;
    }

    out.assign(buffer, remoteStr.Length / 2);
    delete[] buffer;
    return true;
}

void RemotePEBWalk(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        return;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION_REMOTE pbi = {};
    if (NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
        CloseHandle(hProc);
        return;
    }

    PEB_REMOTE peb = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        CloseHandle(hProc);
        return;
    }

    PEB_LDR_DATA_REMOTE ldr = {};
    if (!ReadProcessMemory(hProc, peb.Ldr, &ldr, sizeof(ldr), &bytesRead)) {
        CloseHandle(hProc);
        return;
    }

    LIST_ENTRY* head = (LIST_ENTRY*)&ldr.InMemoryOrderModuleList;
    LIST_ENTRY currEntry = {};
    if (!ReadProcessMemory(hProc, head->Flink, &currEntry, sizeof(currEntry), &bytesRead)) {
        CloseHandle(hProc);
        return;
    }

    std::cout << "\n[+] Remote PEB Module Walk (PID: " << pid << "):\n";
    void* startAddr = head->Flink;
    while ((PVOID)currEntry.Flink != (PVOID)head) {
        LDR_DATA_TABLE_ENTRY_REMOTE entry = {};
        if (!ReadProcessMemory(hProc, CONTAINING_RECORD(startAddr, LDR_DATA_TABLE_ENTRY_REMOTE, InMemoryOrderLinks), &entry, sizeof(entry), &bytesRead))
            break;

        std::wstring fullDll;
        if (!ReadRemoteUnicodeString(hProc, entry.FullDllName, fullDll))
            break;

        std::string modName(fullDll.begin(), fullDll.end());
        std::cout << "  " << modName;

        bool sus = IsSuspiciousModule(modName);
        bool backed = IsBackedByFileRemote(hProc, entry.DllBase);

        if (sus) std::cout << " --> [!!] Keyword match";
        if (!backed) std::cout << " --> [!!] NOT backed by file";

        std::cout << std::endl;
        startAddr = currEntry.Flink;
        if (!ReadProcessMemory(hProc, startAddr, &currEntry, sizeof(currEntry), &bytesRead))
            break;
    }
    CloseHandle(hProc);
}

void BatchScanAllProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create snapshot." << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        RemotePEBWalk(pe32.th32ProcessID);
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        std::string arg = argv[1];
        if (arg == "--all") {
            BatchScanAllProcesses();
            return 0;
        }
        DWORD targetPid = std::stoi(arg);
        RemotePEBWalk(targetPid);
        return 0;
    }

    std::cout << "[*] No PID specified. Use: EDRSpy.exe <pid> or --all\n";
    return 0;
}
