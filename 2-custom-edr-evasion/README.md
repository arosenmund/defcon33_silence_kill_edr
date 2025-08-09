# Custom EDR Evasion

Welcome to Custom EDR Evasion. This module of the workshop has two parts. The first, covers EDR evasion through the method that is used by EDR Sandblast to acheive the priveleges required to disable EDR called BYOD. or Bring Your Own Driver.  Then second part goes over different methods of evading EDR or operation on a device that has it, up to and including the concepts of de-hooking.

There is a lot of custom code here, most of it is pre compiled, which means you can just use the program without going through the compile steps, but the compile steps are provdied.  There is intetionally more than we will be able to cover in depth, but it hopefully provides you with inspiration, and a good baseline understanding of this kind of malware development.  The intetn is not to hand you fully function advanced malware, but rather to cover the concepts that advanced malware can/has/will leverage. 

1. ## [Custom BYOD Implementation](./1-Custom-BYOD/README.md)
2. ## [Custom EDR Evasion Techniques](./2-Custom-API/README.md)

Proceed to [1-Custom-BYOD](./1-Custom-BYOD/README.md)







## 1 Signature & Sandbox Evasion
Lots of examples for this. But first, remember that different signature sets are used for on disk vs in memory execution detection.  However, all of these signature lists simply use string detection. Obfuscated binararies are great but still have to decomplie in memory and will get caught with in memory scans by EDR.

Always add arguments, but not arguments that can be used for signatures.

- [ ] slides to make:
    - [ ] Signatures
    - [ ] On Disk vs. In Mem.
    - [ ] Defender Check not as useful as it use to be.


1. PPL - Vulnerable Drive PP/PPL Bypass
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL

2. Evade in mem.
3. LSASS dump in mem with encryption ;). (Maybe I can get this right this time with Nikito's help.)


## 2 Hooked Windows API Calls
Certain Windows API Calls are hooked by the EDR and the edr is waitning for you like one of those creepy spiders that builds a trap door.  Ew Spiders, right? So, a couple options here:

1. Don't use those API calls.
2. DeHook the EDR
3. Hook the Hookers (Not the PC way to say that.)





