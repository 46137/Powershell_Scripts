<#
Script intent:
- To setup sysmon and winlogbeats agents on a remote device.
- Run each line one at a time.
#>

$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 

foreach ($H in $Hosts){
$Session = New-PSSession -ComputerName $H -Credential $Credential

    #sysmon installation
    # You can get pre-built config from https://github.com/SwiftOnSecurity/sysmon-config
    # Or a more modular config from https://github.com/olafhartong/sysmon-modular (default - sysmonconfig.xml)
    Copy-Item -Path 'C:\Sysmon.exe' -ToSession $Session -Destination 'C:\Sysmon.exe'
    Copy-Item -Path 'C:\Sysmon-Config.xml' -ToSession $Session -Destination 'C:\Sysmon-Config.xml'
    Invoke-Command -ComputerName $H -Credential $Credential -ScriptBlock {
        C:\Sysmon.exe -accepteula -i C:\Sysmon-Config.xml
        Get-Service sysmon
    }

    #winlogbeat installer
    Copy-Item -Path 'C:\winlog.msi' -ToSession $Session -Destination 'C:\winlog.msi'
    Invoke-Command -ComputerName $H -Credential $Credential -ScriptBlock {
        Start-Process msiexec.exe -Wait -ArgumentList '/I C:\winlog.msi /quiet' #msiexec.exe can run .msi files to bypass the window prompts.
        Get-Service winlogbeat # should be stopped so the .yml can get sent to the right folder.
    }

    #winlogbeat config placement
    Copy-Item -Path 'C:\winlogbeat.yml' -ToSession $Session -Destination 'C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml' #disable elasticsearch section and enable logstash with the host of seconion ip
    Invoke-Command -ComputerName $H -Credential $Credential -ScriptBlock {
        Get-Service winlogbeat |Start-Service
        Get-Service winlogbeat #should be running
    }
    Get-PSSession | Remove-PSSession #removes all sessions at the end
}

$User = "GVS\Head" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Administrator.GVS-WIN-HUNT-5\Documents\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

$Session = New-PSSession -ComputerName 192.168.20.4 -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock{get-service *sysmon*}
Invoke-Command -Session $Session -ScriptBlock{get-service winlogbeat}
Invoke-Command -Session $Session -ScriptBlock{restart-service winlogbeat}

Copy-Item -Path 'C:\Users\Administrator.GVS-WIN-HUNT-5\Documents\win\Sysmon64.exe' -ToSession $Session -Destination 'C:\Sysmon64.exe'
Copy-Item -Path 'C:\Users\Administrator.GVS-WIN-HUNT-5\Documents\win\sysmonconfig-export.xml' -ToSession $Session -Destination 'C:\sysmonconfig-export.xml'

Invoke-Command -Session $Session -ScriptBlock{C:\Sysmon64.exe -accepteula -i C:\sysmonconfig-export.xml}
#Invoke-Command -Session $Session -ScriptBlock{C:\Sysmon64.exe -u force}
Invoke-Command -Session $Session -ScriptBlock{start-service Sysmon64}

Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\Sysmon64.exe' -Recurse -Force}
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\sysmonconfig-export.xml' -Recurse -Force}

Invoke-Command -Session $Session -ScriptBlock{get-service winlogbeat}
Copy-Item -Path 'C:\Users\Administrator.GVS-WIN-HUNT-5\Documents\win\winlog.msi' -ToSession $Session -Destination 'C:\winlog.msi'
Invoke-Command -Session $Session -ScriptBlock{Start-Process msiexec.exe -Wait -ArgumentList '/I C:\winlog.msi /quiet'}
Copy-Item -Path 'C:\Users\Administrator.GVS-WIN-HUNT-5\Documents\win\winlogbeat.yml' -ToSession $Session -Destination 'C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml'
Invoke-Command -Session $Session -ScriptBlock{Start-Service Winlogbeat}   

Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path 'C:\winlog.msi' -Recurse -Force}