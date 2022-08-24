#Script intent: To setup winlogbeat and sysmon on a remote device. Run the winlogbeat section first, then sysmon to ensure it works correctly.
<#
Tasks:
- Delete files at the end
- Add source IP list file
- If statement to see if service is already running, else install.
- Wait command between installs
#>

$Hosts = Get-Content -Path C:\Users\Heady\Desktop\220824-Hosts-Port-5985.txt
$User = "546CMT\Administrator"
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