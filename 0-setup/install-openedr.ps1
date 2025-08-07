# Start Edr Installer.

Write-Host "Starting OpenEDR Install. Follow Prompts."

start-process -FilePath "C:\OpenEDR-Installation-2.5.1.msi" -ArgumentList "/passive" -Wait

# Follow Prompts.

start-process -FilePath "C:\Program Files\COMODO\EdrAgentV2\edrsvc.exe" -Wait

Write-host "Starting EDR Service"

Set-service -Name "edrsvc" -StartupType Automatic
Start-service -Name "edrsvc"

Write-Host "OpenEDR Install Complete. Log Files Found in C:\ProgramData\edrsvc\logs\output_events"

Write-Host "Ironcat Meow"
