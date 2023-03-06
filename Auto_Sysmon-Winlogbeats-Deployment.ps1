#Script intent: To setup winlogbeat and sysmon on a remote device.

$Hosts = Get-Content -Path 'C:\Users\Heady\Desktop\230302-Hosts-Port-5985.txt'
$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 

foreach ($H in $Hosts){
$Session = New-PSSession -ComputerName $H -Credential $Credential
    if((Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name Sysmon }).Status -ne 'Running'){
        # sysmon installation
        # You can get pre-built config from https://github.com/SwiftOnSecurity/sysmon-config
        # Or a more modular config from https://github.com/olafhartong/sysmon-modular (default - sysmonconfig.xml)
        Copy-Item -Path 'C:\Users\Heady\Desktop\winlog\Sysmon.exe' -ToSession $Session -Destination 'C:\Sysmon.exe'
        Copy-Item -Path 'C:\Users\Heady\Desktop\winlog\Sysmon-Config.xml' -ToSession $Session -Destination 'C:\Sysmon-Config.xml'
        Invoke-Command -Session $Session -ScriptBlock{
            C:\Sysmon.exe -accepteula -i C:\Sysmon-Config.xml
            Start-Service sysmon
        }
        if((Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name Sysmon }).Status -ne 'Running'){
            Write-Host "$H - Sysmon Install Failed"
        }
        else{
            Write-Host "$H - Sysmon Running"
        }
        Invoke-Command -Session $Session -ScriptBlock{
            Remove-Item -Path 'C:\Sysmon.exe' -Recurse -Force
            Remove-Item -Path 'C:\Sysmon-Config.xml' -Recurse -Force
        }
    }
    else{
        Write-Host "$H - Sysmon Already Running"
    }

    if((Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name Winlogbeat }).Status -ne 'Running'){
        #winlogbeat installer
        Copy-Item -Path 'C:\Users\Heady\Desktop\winlog\winlog.msi' -ToSession $Session -Destination 'C:\winlog.msi'
        Invoke-Command -Session $Session -ScriptBlock{
            Start-Process msiexec.exe -Wait -ArgumentList '/I C:\winlog.msi /quiet' #msiexec.exe can run .msi files to bypass the window prompts.
        }
        Start-Sleep -Seconds 2 #Waiting 2 seconds to make sure there is no issues copying the following config into the newly created folder.
        Copy-Item -Path 'C:\Users\Heady\Desktop\winlog\winlogbeat.yml' -ToSession $Session -Destination 'C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml' #disable elasticsearch section and enable logstash with the host of seconion ip
        Invoke-Command -Session $Session -ScriptBlock{
            Start-Service Winlogbeat
        }    
        if((Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name Winlogbeat }).Status -ne 'Running'){
            Write-Host "$H - Winlogbeat Install Failed"
        }
        else{
            Write-Host "$H - Winlogbeat Running"
        }
        Invoke-Command -Session $Session -ScriptBlock{
            Remove-Item -Path 'C:\winlog.msi' -Recurse -Force
        }
    }
    else{
        Write-Host "$H - Winlogbeat Already Running"
    }
    Remove-PSSession $Session #removes session
}# Once done, add the required subnets to security onion. 'sudo so-allow' then choose logstash, and enter the required subnets for injestion.