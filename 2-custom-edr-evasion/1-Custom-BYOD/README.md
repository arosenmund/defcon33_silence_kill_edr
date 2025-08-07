# Signature Evasion


In thos module we are going to create a custom capability using a BYOD, to avoid signatures and defeat not only EDR, but the monitored PPL and CG processes, using LSASS as an example.

In the process, we will learn how it works, and walk away with a baseline to create our own tools that avoid signatured public tooling.

As with the previous modules. This is post compromise, and you have already escalated to some version of local admin on the device.


Identify EDR with Seatbelt. 


Access to protected processes!

- Vulnerable Drive PPL Bypass
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL


### Dump That Ass

x86_64-w64-mingw32-g++ lsass_dumper.cpp -o lsass_dumper.exe -static
x86_64-w64-mingw32-g++ decode_lsass.cpp -o decode_lsass.exe -static
x86_64-w64-mingw32-g++ system_launcher.cpp -o system_launcher.exe -static

### Strip Debug Symbols

x86_64-w64-mingw32-strip lsass_dumper.exe


## Vulnerable Driver

https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/

RTCore64.sys


x86_64-w64-mingw32-g++ main.cpp -Iheaders -o lsass_dumper.exe -static

