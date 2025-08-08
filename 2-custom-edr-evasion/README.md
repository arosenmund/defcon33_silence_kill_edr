# Custom EDR Evasion




## 1 Signature & Sandbox Evasion
Lots of examples for this. But first, remember that different signature sets are used for on disk vs in memory execution detection.  However, all of these signature lists simply use string detection. Obfuscated binararies are great but still have to decomplie in memory and will get caught with in memory scans by EDR.

Always add arguments, but not arguments that can be used for signatures.

- [ ] slides to make:
    - [ ] Signatures
    - [ ] On Disk vs. In Mem.
    - [ ] Defender Check not as useful as it use to be.


1. PPL - Vulnerable Drive PP/PPL Bypass
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL

2. Credential Guard
3. What process are protected.

2. Evade in mem.
3. LSASS dump in mem with encryption ;). (Maybe I can get this right this time with Nikito's help.)


## 2 Hooked Windows API Calls
Certain Windows API Calls are hooked by the EDR and the edr is waitning for you like one of those creepy spiders that builds a trap door.  Ew Spiders, right? So, a couple options here:

1. Don't use those API calls.
2. DeHook the EDR
3. Hook the Hookers (Not the PC way to say that.)


BYOD

## Custom EDR Evasion SETUP

1. In the lab environment, open up the **Operator Desktop**, once loaded and the terminal pops up, change the permissions on the lab folder.
`sudo chown pslearner:pslearner -R /home/pslearner/lab`
2. Now change directory to that folder.
`cd /home/pslearner/lab`
3. Open VSCODE.
`code .`
5. Once open, accept any pop ups. Trusting the author etc.
6. In the top left, use the mouse to click "terminal" then "new terminal" to launch a bash terminal in the bottom pane.
7. In the terminal in the bottom plane, run python simple server to host the files.
8. SWITCH TO THE WINDOWS TARGET 2 desktop.
9. On this windows machine, untouched from the previous activity, open a firefox browser, and browse to http://172.31.24.30:8000
10. This will bring up the browseable folders with the code so you can download as you edit and compile.
11. Now, open a command prompt as administrator.  In the search bar in the bottom, type cmd.exe and then right click the result and choose "Run As Administrator"
12. With that open, you are now ready to begin! 

Proceed to [1-Custom-BYOD](./1-Custom-BYOD/README.md)

