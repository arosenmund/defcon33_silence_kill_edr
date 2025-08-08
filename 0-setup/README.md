# SETUP

## Pluralsight Lab Environment
You MUST have a free PluralSight account to use the online platform. You can attempt to follow along on a VM or your own device, but we can't guarantee everything will work.

## Environment Setup

1. Open the **Windows Target**, open PowerShell **AS ADMIN!!**.
- Note: You MUST launch PowerShell as Admin!
2. Change dir to the lab files setup folder on the Public user's desktop:
- `cd C:\Users\Public\Desktop\LAB_FILES\0-setup`
3. Run the OpenEDR install script. It is interactive, you need to click through the items.
- `.\Install-OpenEDR.ps1`
4. In the powershell terminal, from the same directory, install filebeat!
- `.\Install-Filebeat.ps1`
5. Exit the PowerShell console and double click the ICON ond the desktop for the firefox browser link to the Elastic Stack.
6. Login with UN: **pslearner** PW: **alwaysbelearning**
7. Browse in the top left to "DISCOVER"
8. In the top left, choose the indexe "filebeat-*"


You are now ready to go!



