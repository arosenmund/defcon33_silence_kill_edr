
// main.cpp - Patched with PsInitialSystemProcess resolution for Windows 20348.3932

#include <windows.h>
#include <psapi.h>
#include <string>
#include <iostream>
#include "headers/driver_interface.h"
#include "headers/logging.h"

// Convert to hex string
std::string ToHexString(uint64_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%llx", value);
    return std::string(buffer);
}

// Retrieve kernel base address
uintptr_t GetKernelBase() {
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        WriteLog("[-] EnumDeviceDrivers failed.");
        return 0;
    }
    return reinterpret_cast<uintptr_t>(drivers[0]);
}

// Get Windows build number
DWORD GetWindowsBuildNumber() {
    OSVERSIONINFOEXW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (!GetVersionExW((OSVERSIONINFOW*)&osvi)) {
        return 0;
    }
    return osvi.dwBuildNumber;
}

int main() {
    HANDLE driverHandle = OpenDriver();
    if (!driverHandle || driverHandle == INVALID_HANDLE_VALUE) {
        WriteLog("[-] Failed to open driver handle.");
        return 1;
    }

    uintptr_t kernelBase = GetKernelBase();
    if (!kernelBase) {
        WriteLog("[-] Failed to get kernel base.");
        return 1;
    }
    WriteLog("[*] Kernel base: 0x" + ToHexString(kernelBase));

    DWORD build = GetWindowsBuildNumber();
    WriteLog("[*] Detected Windows build: " + std::to_string(build));

    uintptr_t psInitOffset = 0;
    if (build == 20348) {
        psInitOffset = 0x8755E0; // Verified for Windows Server 2022
    } else if (build == 26100) {
        psInitOffset = 0x886B20; // Insider build example
    } else {
        WriteLog("[-] Unsupported Windows build: " + std::to_string(build));
        return 1;
    }

    uintptr_t psInitVA = kernelBase + psInitOffset;
    WriteLog("[*] PsInitialSystemProcess VA: 0x" + ToHexString(psInitVA));

    uint64_t systemEP = 0;
    if (!ReadPhys(driverHandle, psInitVA, &systemEP, sizeof(systemEP))) {
        WriteLog("[-] Failed to read PsInitialSystemProcess.");
        return 1;
    }

    WriteLog("[+] PsInitialSystemProcess EPROCESS: 0x" + ToHexString(systemEP));

    CloseHandle(driverHandle);
    return 0;
}
