# EDR Killing

## Overview

In this workshop, we'll be working with the Comodo Security's OpenEDR:
- [Website](https://www.openedr.com/)
- [GitHub repo](https://github.com/ComodoSecurity/openedr)

For part 1 of our workshop, we'll be "killing" OpenEDR via [EDRSandBlast](https://github.com/wavestone-cdt/EDRSandblast), a well-known EDR killer that has been used by a number of threat actors including ransomware actors.

The flow for this section is as follows:
- Review OpenEDR's logs to review how it logs telemetry
- Kill OpenEDR using EDRSandBlast
- Perform actions following the killing of OpenEDR and verifying that the actions do not show up in the EDR's telemetry

## 1 Review OpenEDR Logging

OpenEDR has been installed on the Windows host within our lab environment. Let's take a moment to review how OpenEDR operates. To begin, we'll review the logs created by OpenEDR:

1. In the Windows host in your lab, run `powershell.exe`

1. In the PowerShell prompt, run the following commands:

  1. `whoami`
  
  1. `powershell -c "Write-Host 'Testing123'"`
  
  1. `exit` to exit the PowerShell prompt

1. Wait 2-3 minutes, then:

1. Navigate to `C:\ProgramData\edrsvc\log\output_events` via Explorer

1. Open the `.log` file for the current day (most _likely_ labeled `2025-08-09.log`) via NotePad++

1. Search via `Ctrl+F` for the test commands

  1. Look for `whoami` and `write-host`
  
  1. If you do not find the logs for these executions, wait a few minutes, reloud the `.log` file, and search again

  You should see logged process execution that looks like the following, in this case for the `Testing123` command:
  
  ```
  {"baseEventType":1,"baseType":1,"childProcess":{"cmdLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"Write-Host 'Testing123'\"","creationTime":1754165190878,"elevationType":3,"flsVerdict":3,"id":11906735664066085287,"imageHash":"044a0cf1f6bc478a7172bf207eef1e201a18ba02","imagePath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","pid":9136,"scriptContent":"<undefined>","verdict":1},"customerId":"","deviceName":"DESKTOP-2C3IQHO","endpointId":"","eventType":null,"processes":[{"creationTime":1706054816443,"flsVerdict":3,"id":11653246184937143266,"imageHash":"","imagePath":"System","pid":4,"userName":"SYSTEM@NT AUTHORITY","verdict":1},{"creationTime":1706054816451,"flsVerdict":3,"id":7794509012031835316,"imageHash":"d1af138271c0aaf33231ca6b69ec292825e4344f","imagePath":"C:\\Windows\\System32\\smss.exe","pid":288,"userName":"SYSTEM@NT AUTHORITY","verdict":1},{"creationTime":1706054821002,"flsVerdict":3,"id":368153235877317417,"imageHash":"d1af138271c0aaf33231ca6b69ec292825e4344f","imagePath":"C:\\Windows\\System32\\smss.exe","pid":448,"userName":"SYSTEM@NT AUTHORITY","verdict":1},{"creationTime":1706054821517,"flsVerdict":3,"id":7980340891454918504,"imageHash":"0b4a5b6d33b7ce2bae151e2bccd492bd9b3f934a","imagePath":"C:\\Windows\\System32\\winlogon.exe","pid":532,"userName":"SYSTEM@NT AUTHORITY","verdict":1},{"creationTime":1754053499107,"flsVerdict":3,"id":17816383769483083890,"imageHash":"a6a64cc07500e327970d2ffafbbf6f70855f9419","imagePath":"C:\\Windows\\System32\\LaunchTM.exe","pid":2760,"userName":"LegitUser@DESKTOP-2C3IQHO","verdict":1},{"creationTime":1754053499140,"flsVerdict":1,"id":1781598605651026540,"imageHash":"a0bdfac3ce1880b32ff9b696458327ce352e3b1d","imagePath":"C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe","pid":1728,"userName":"LegitUser@DESKTOP-2C3IQHO","verdict":1},{"creationTime":1754053506281,"flsVerdict":3,"id":13846455323943565512,"imageHash":"a879626bd1fa2e96ca8017ce40b10a51668e093d","imagePath":"C:\\Windows\\explorer.exe","pid":3584,"userName":"LegitUser@DESKTOP-2C3IQHO","verdict":1},{"creationTime":1754165178268,"flsVerdict":3,"id":9135481545039002649,"imageHash":"044a0cf1f6bc478a7172bf207eef1e201a18ba02","imagePath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","pid":1848,"userName":"LegitUser@DESKTOP-2C3IQHO","verdict":1}],"sessionUser":"LegitUser@DESKTOP-2C3IQHO","time":1754165190880,"type":"RP1.1","version":"1.1"}
  ```
  
  - Note that the above example log includes a different hostname, execution time, etc. from what you'll see in our workshop lab environment. But you get the idea.

_Ryan to lead log review with workshop attendees._

## 2 Kill OpenEDR via EDRSandBlast

Next we'll kill OpenEDR using EDRSandBlast. Technically, we'll unhook the various functions used by OpenEDR in order to launch a `cmd.exe` command prompt, run a few commands, and then review the OpenEDR logs to verify that the commands we executed do not show up in the logged telemetry.

1. In Explorer, access our cloned workshop GitHub repo on the desktop

1. blah blah
