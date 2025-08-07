# Custom EDR Evasion

## 1 Signature & Sandbox In Memory VS On Disk Evasion
Lots of examples for this. But first, remember that different signature sets are used for on disk vs in memory execution detection.  However, all of these signature lists simply use string detection. Obfuscated binararies are great but still have to decomplie in memory and will get caught with in memory scans by EDR.

Always add arguments, but not arguments that can be used for signatures.

1. Evade on disk.
2. Evade in mem.
3. LSASS dump in mem with encryption ;). (Maybe I can get this right this time with Nikito's help.)


## 2 Hooked Windows API Calls
Certain Windows API Calls are hooked by the EDR and the edr is waitning for you like one of those creepy spiders that builds a trap door.  Ew Spiders, right? So, a couple options here:

1. Don't use those API calls.
2. DeHook the EDR
3. Hook the Hookers (Not the PC way to say that.)


## 3 EDR Server Detections

1. Firewall rule block the EDR server from the client.
2. Redirect via DNS or local mac cache to local host/null.
3. Intercept and spoof network traffic to EDR server. (Yup Badass, like a hiest!).





**Original Outline for Guideline**
- Detection Evasion Techniques
    - Sandbox evasion with an argument
    - 
- Review ransomware antivirus evasion techniques
- Binary Obfuscation
- In memory execution
- C2 Obfuscation
- Run live code snippets
- Configure code snippets to evade current detections
- Analysis Evasion Techniques
- Review ransomware/malware anti analysis features
- Internet access checks
- OS & Hardware checks
- Execution Jitter
- Run live code snippets
- Configure code snippets to evade current methods