# BYOVD LSASS Dumper (PPL Bypass)

## Overview
This tool:
- Loads RTCore64.sys as a vulnerable driver
- Uses kernel R/W to locate EPROCESS for LSASS and SYSTEM
- Steals a SYSTEM handle to LSASS
- Dumps LSASS memory (bypassing PPL) with XOR encoding

## Requirements
- RTCore64.sys at `C:\Windows\Temp\RTCore64.sys`
- Run as Administrator
- Test signing mode or unsigned driver support enabled

## Build (Linux)
```bash
x86_64-w64-mingw32-g++ main.cpp -o lsass_dumper.exe -static
```

## Output
- Dump: `C:\Windows\Temp\lsass_encoded.dmp`
- Logs: `C:\Windows\Temp\lsass_dumper.log`


