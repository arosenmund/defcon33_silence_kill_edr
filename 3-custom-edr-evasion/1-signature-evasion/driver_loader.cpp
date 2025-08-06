#define UNICODE
#define _UNICODE
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

void WriteLog(const std::string& msg) {
    std::ofstream log("C:\\Windows\\Temp\\driver_loader.log", std::ios::app);
    log << msg << std::endl;
    log.close();
}

bool LoadDriver(const std::wstring& driverName, const std::wstring& driverPath) {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        WriteLog("[-] Failed to open Service Control Manager.");
        return false;
    }

    // Remove service if it already exists
    SC_HANDLE existing = OpenService(scManager, driverName.c_str(), SERVICE_ALL_ACCESS);
    if (existing) {
        WriteLog("[*] Driver service already exists. Deleting it...");
        DeleteService(existing);
        CloseServiceHandle(existing);
    }

    // Create the new service entry
    SC_HANDLE service = CreateService(
        scManager,
        driverName.c_str(),
        driverName.c_str(),
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driverPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!service) {
        DWORD err = GetLastError();
        WriteLog("[-] Failed to create service. Error: " + std::to_string(err));
        CloseServiceHandle(scManager);
        return false;
    }

    WriteLog("[+] Driver service created successfully.");

    // Start the service
    if (!StartService(service, 0, nullptr)) {
        DWORD err = GetLastError();
        WriteLog("[-] Failed to start driver service. Error: " + std::to_string(err));
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return false;
    }

    WriteLog("[+] Driver started successfully.");

    // Optionally delete the service afterward to clean up
    DeleteService(service);
    WriteLog("[*] Service entry deleted (driver still running).");

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

int main() {
    const std::wstring driverName = L"MyRTCore64";
    const std::wstring driverPath = L"C:\\Windows\\Temp\\RTCore64.sys";

    WriteLog("[*] Starting driver loader...");

    if (LoadDriver(driverName, driverPath)) {
        WriteLog("[+] Driver loaded and running.");
    } else {
        WriteLog("[-] Driver load failed.");
    }

    return 0;
}

