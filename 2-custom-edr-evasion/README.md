# Custom EDR Evasion

## 1 Signature & Sandbox In Memory VS On Disk Evasion
Lots of examples for this. But first, remember that different signature sets are used for on disk vs in memory execution detection.  However, all of these signature lists simply use string detection. Obfuscated binararies are great but still have to decomplie in memory and will get caught with in memory scans by EDR.

Always add arguments, but not arguments that can be used for signatures.

- [ ] slides to make:
    - [ ] Signatures
    - [ ] On Disk vs. In Mem.
    - [ ] Defender Check not as useful as it use to be.
    - [ ] Maybe show off rapid detection from RSA talk.
    - [ ] 

1. PPL - Vulnerable Drive PPL Bypass
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




