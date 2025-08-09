# Start Filebeat Installer

Write-Host "Starting Filebeat Install. Follow prompts."

start-process -FilePath "C:\filebeat-8.12.0-windows-x86_64.msi" -Wait

start-sleep 10

Write-Host "Copying Filebeat configuration files..."

copy-item -Path "C:\Users\Public\Desktop\LAB_FILES\0-setup\filebeat.yml" -Destination "C:\Program Files\Elastic\Beats\8.12.0\filebeat\filebeat.yml"

Write-host "Starting Filebeat Setup - Wait for Completion..."

"C:\Program Files\Elastic\Beats\8.12.0\filebeat\filebeat.exe" setup -e

Write-Host "Installing Filebeat Service"

"C:\Program Files\Elastic\Beats\8.12.0\filebeat\install-service-filebeat.ps1"

Write-Host "Starting Filebeat Service"

Start-Service Filebeat