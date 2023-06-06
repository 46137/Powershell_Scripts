<#
Script intent:
- To setup sysmon and winlogbeats agents on a remote device.
- You will need 4 files: 
    - 'Sysmon.exe' or 'Sysmon64.exe' installer.
    - Sysmon pre-built config (https://github.com/ion-storm/sysmon-config).
    - winlog.msi installer (Can download from SecurityOnion).
    - winlogbeat.yml config (disable elasticsearch, enable logstash and change IP to SecurityOnion)   
- Run each line one at a time.
#>

#Manually run the 4 lines below to store your 'Credential' variable.
$User = "TL\Heady"
$PWord = Get-Content 'C:\Users\Heady\Documents\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 

#Change the destination IP as needed.
$Session = New-PSSession -ComputerName 192.168.20.4 -Credential $Credential
#Test to see if the services are already running. If you get an error that can't find the service, they will need to be installed.
Invoke-Command -Session $Session -ScriptBlock{get-service *sysmon*}
Invoke-Command -Session $Session -ScriptBlock{get-service winlogbeat}

#Installing Sysmon.
Copy-Item -Path 'C:\Users\Heady\Documents\win\Sysmon64.exe' -ToSession $Session -Destination 'C:\Sysmon64.exe'
Copy-Item -Path 'C:\Users\Heady\Documents\win\sysmonconfig-export.xml' -ToSession $Session -Destination 'C:\sysmonconfig-export.xml'
Invoke-Command -Session $Session -ScriptBlock{C:\Sysmon64.exe -accepteula -i C:\sysmonconfig-export.xml} 
Invoke-Command -Session $Session -ScriptBlock{start-service Sysmon64}
#Removing files.
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\Sysmon64.exe' -Recurse -Force}
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\sysmonconfig-export.xml' -Recurse -Force}

#Installing Winlogbeats.
Copy-Item -Path 'C:\Users\Heady\Documents\win\winlog.msi' -ToSession $Session -Destination 'C:\winlog.msi'
Invoke-Command -Session $Session -ScriptBlock{Start-Process msiexec.exe -Wait -ArgumentList '/I C:\winlog.msi /quiet'}
Copy-Item -Path 'C:\Users\Heady\Documents\win\winlogbeat.yml' -ToSession $Session -Destination 'C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml'
Invoke-Command -Session $Session -ScriptBlock{Start-Service Winlogbeat}   
#Removing file.
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\winlog.msi' -Recurse -Force}

#TROUBLESHOOTING
#Ensure on SecurityOnion terminal logon, services are running.
sudo so-status
#Ensure on SecurityOnion terminal logon, logstash is configured to receive from the required subnets.
sudo so-allow
#Check if Sysmon logs are generating locally on the endpoint.
Invoke-Command -Session $Session -ScriptBlock{Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"}
#Restart service if logs aren't ingesting into SecurityOnion.
Invoke-Command -Session $Session -ScriptBlock{restart-service winlogbeat}
#Uninstalling Sysmon, must be the same binary that installed it.
Invoke-Command -Session $Session -ScriptBlock{C:\Sysmon64.exe -u force}