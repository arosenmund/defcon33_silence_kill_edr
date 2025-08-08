## Advanced


Hooking the hookers.

Identify API hooks of edr. 

DLL injects etc.

Unhook hooks. Unload DLLs, etc.


OPENEDR often injects DLLs like openhidsvc.dll or openhidsvc64.dll into user processes.


| Tool/Lib                                                        | Use                                             |
| --------------------------------------------------------------- | ----------------------------------------------- |
| [`Blackbone`](https://github.com/DarthTon/Blackbone)            | Memory reading, module enumeration, PEB parsing |
| [`HookShark`](https://github.com/CheckPointSW/HookShark)        | Detects common EDR hook types                   |
| [`HollowHunter`](https://github.com/hasherezade/hollows_hunter) | Scans for code injection, hooks, etc.           |
| [`PE-sieve`](https://github.com/hasherezade/pe-sieve)           | Detects inline hooks, manual mapping, hollowing |


Try opening target processes with high rights like PROCESS_ALL_ACCESS
If you receive Access Denied (ERROR_ACCESS_DENIED) but you’re SYSTEM, it’s probably PPL/PP
Known PPLs: lsass.exe, winlogon.exe, csrss.exe, services.exe

EDRSpy.exe <pid>
EDRSpy.exe --all


✅ Lists modules via EnumProcessModules
✅ Walks the PEB → LDR → InMemoryOrderModuleList
✅ Detects suspicious DLLs by keyword
✅ Detects inline API hooks
✅ Compares function bytes (memory vs disk)
✅ Flags modules not backed by files (e.g., memory-only DLLs)
✅ Detects protected processes (PPL / Credential Guard)
✅ Reads registry to check if Credential Guard is enabled
