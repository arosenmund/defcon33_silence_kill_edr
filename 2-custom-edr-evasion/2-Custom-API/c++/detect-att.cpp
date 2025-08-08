// EDRSpy - Full Tool with Remote PEB Walk and Batch Scan
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <winternl.h>   // use official UNICODE_STRING, PEB, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, PROCESS_BASIC_INFORMATION
#include <fstream>
#include <cstddef>      // offsetof
#include <cstdint>      // fixed-width ints
#include <cstring>      // memset etc.

#pragma comment(lib, "psapi.lib")

// NtQueryInformationProcess prototype (already in winternl.h on most toolchains; keep a pointer type)
typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

// --- Suspicious keywords ---
static std::vector<std::string> suspicious_keywords = {"openhid", "edr", "sensor", "agent"};

static bool IsSuspiciousModule(const std::string& modName) {
    for (const auto& kw : suspicious_keywords) {
        if (modName.find(kw) != std::string::npos) return true;
    }
    return false;
}

// --- Check if a module base is backed by a file in the target process ---
static bool IsBackedByFileRemote(HANDLE hProc, void* baseAddr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(hProc, baseAddr, &mbi, sizeof(mbi)))
        return false;

    if (mbi.Type != MEM_IMAGE)
        return false;

    char filename[MAX_PATH]{};
    if (GetMappedFileNameA(hProc, baseAddr, filename, MAX_PATH) == 0)
        return false;

    return true;
}

// --- Read remote UNICODE_STRING contents into std::wstring ---
static bool ReadRemoteUnicodeString(HANDLE hProc, const UNICODE_STRING& remoteStr, std::wstring& out) {
    if (!remoteStr.Buffer || remoteStr.Length == 0) return false;

    size_t wcharCount = remoteStr.Length / sizeof(WCHAR);
    std::vector<wchar_t> buf(wcharCount + 1, L'\0');

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, remoteStr.Buffer, buf.data(), remoteStr.Length, &bytesRead))
        return false;

    out.assign(buf.data(), wcharCount);
    return true;
}

// --- Remote PEB Walk via InMemoryOrderModuleList ---
static void RemotePEBWalk(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        // std::cerr << "[-] OpenProcess failed for PID " << pid << " (" << GetLastError() << ")\n";
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryInformationProcess =
        reinterpret_cast<pNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) {
        CloseHandle(hProc);
        return;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    if (NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress) {
        CloseHandle(hProc);
        return;
    }

    // Read remote PEB
    PEB peb{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead) || !peb.Ldr) {
        CloseHandle(hProc);
        return;
    }

    // Read remote PEB_LDR_DATA
    PEB_LDR_DATA ldr{};
    if (!ReadProcessMemory(hProc, peb.Ldr, &ldr, sizeof(ldr), &bytesRead)) {
        CloseHandle(hProc);
        return;
    }

    // Compute the REMOTE address of InMemoryOrderModuleList head
    BYTE* remoteLdrBase = reinterpret_cast<BYTE*>(peb.Ldr);
    BYTE* remoteListHeadAddr = remoteLdrBase + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

    // Read the head LIST_ENTRY (remote)
    LIST_ENTRY remoteHead{};
    if (!ReadProcessMemory(hProc, remoteListHeadAddr, &remoteHead, sizeof(remoteHead), &bytesRead)) {
        CloseHandle(hProc);
        return;
    }

    std::cout << "\n[+] Remote PEB Module Walk (PID: " << pid << "):\n";

    // Iterate the circular doubly-linked list
    void* remoteFlink = remoteHead.Flink;
    while (remoteFlink && remoteFlink != remoteListHeadAddr) {
        // Each entry address = Flink - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
        BYTE* remoteEntryAddr = reinterpret_cast<BYTE*>(remoteFlink) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        LDR_DATA_TABLE_ENTRY remoteEntry{}; // definition from <winternl.h>
        if (!ReadProcessMemory(hProc, remoteEntryAddr, &remoteEntry, sizeof(remoteEntry), &bytesRead))
            break;

        std::wstring wFullDll;
        if (!ReadRemoteUnicodeString(hProc, remoteEntry.FullDllName, wFullDll)) {
            // Move to next anyway to avoid getting stuck
        }

        std::string modName(wFullDll.begin(), wFullDll.end());
        if (!modName.empty()) {
            std::cout << "  " << modName;
            bool sus    = IsSuspiciousModule(modName);
            bool backed = IsBackedByFileRemote(hProc, remoteEntry.DllBase);

            if (sus)     std::cout << " --> [!!] Keyword match";
            if (!backed) std::cout << " --> [!!] NOT backed by file";
            std::cout << '\n';
        }

        // Advance to next entry
        remoteFlink = remoteEntry.InMemoryOrderLinks.Flink;
        if (!remoteFlink) break; // corrupted list guard
    }

    CloseHandle(hProc);
}

static void BatchScanAllProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create snapshot.\n";
        return;
    }

#ifdef UNICODE
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return;
    }
    do {
        RemotePEBWalk(pe32.th32ProcessID);
    } while (Process32NextW(snapshot, &pe32));
#else
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return;
    }
    do {
        RemotePEBWalk(pe32.th32ProcessID);
    } while (Process32Next(snapshot, &pe32));
#endif

    CloseHandle(snapshot);
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        std::string arg = argv[1];
        if (arg == "--all") {
            BatchScanAllProcesses();
            return 0;
        }
        DWORD targetPid = 0;
        try {
            targetPid = static_cast<DWORD>(std::stoul(arg));
        } catch (...) {
            std::cerr << "[-] Invalid PID.\n";
            return 1;
        }
        RemotePEBWalk(targetPid);
        return 0;
    }

    std::cout << "[*] No PID specified. Use: EDRSpy.exe <pid> or --all\n";
    return 0;
}
