# SETUP

## Pluralsight Lab Environment
You MUST have a free PluralSight account to use the online platform. You can attempt to follow along on a VM or your own device, but we can't guarantee everything will work.

First you need an account, or if you don't already have one, a free acount. 

This does require a free trial. And as of today ( because it used to be different ) this does require a free trial.

https://www.pluralsight.com/individuals/pricing

1. Chose any of these options, 10 day free trial.
2. Fill out required information, including the credit card.... I know, I know, but I don't make the rules. Cloud resources do cost money so I kinda get it.
3. Set a calendar reminder to cancle your subscription. (No, seriously, otherwise you know darn well you won't do it.)
4. Login and access the lab (Defcon 33 Workshop: Killing and Silencing EDR Agents) at this link.
`https://app.pluralsight.com/labs/detail/28895c03-00f9-4f5d-bd7d-5e05c57aa275/toc`

Once done with this we can move in. If you would prefer to emulate the lab on your own device or on a vm, you will need the following:

1. OpenEDR installed. https://github.com/ComodoSecurity/openedr
2. Filebeat installed and forwarding to an ELK stack. https://www.elastic.co/docs/reference/beats/filebeat/filebeat-installation-configuration
3. Lots of understanding built in.  Otherwise, follow along in the provided platform.



## Environment Setup
Once in the lab above. Clicke the start environment button, and wait a few minutes for it to build.  Once it is done loading the button will say "open environment", and when you click that, it will take you into the lab in a new tab.

To bring up the side panel use "ctl+shft+alt" and then click the "pluralsight" word in the top left. This will allow you to navigate to other devices, as well as give you access to copy paste functionality.


1. Open the **Windows Target**, open PowerShell **AS ADMIN!!**.
- Note: You MUST launch PowerShell as Admin!
2. Change dir to the lab files setup folder on the Public user's desktop:
- `cd C:\Users\Public\Desktop\LAB_FILES\0-setup`
3. Run the OpenEDR install script. It is interactive, you need to click through the items.
- `.\Install-OpenEDR.ps1`
4. You may need to run it a second time if you see errors, and then it will go through. (No idea why.)
5. Once complete, run the following the check and make sure the service is running:
`get-service edrsvc`
4. Next, in the powershell terminal, from the same directory, install filebeat!
- `.\Install-Filebeat.ps1` 
> You may need to close out the explorer window, and/or in the powershell prompt press enter to "kick" it a bit. The phase where it is running filebeat setup will take a bit to install all the dashboards.
5. Exit the PowerShell console and double click the ICON ond the desktop for the firefox browser link to the Elastic Stack.
6. Login with UN: **elastic** PW: **alwaysbelearning**
7. Browse in the top left, clikc the "hamburger" and then click "DISCOVER"
8. In the top left, choose the index "filebeat-*"
9. You should see events that started when you installed filebeat and continue.

You are now ready to go!



