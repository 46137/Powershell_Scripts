#Run each section individually to ensure it works correctly

$ip = 192.168.5.6 #Can also use hostname
$creds = Get-Credential 296s225PPTRG.AD\546.cmt #Domain credentials for easier deployment
$session = New-PSSession -ComputerName $ip -Credential $creds

#winlogbeat installer
Copy-Item -Path 'C:\winlog.msi' -ToSession $session -Destination 'C:\winlog.msi'
Invoke-Command -ComputerName $ip -Credential $creds -ScriptBlock {
    Start-Process -FilePath 'C:\winlog.msi' -Wait
    Get-Service winlogbeat
}

#winlogbeat config placement
Copy-Item -Path 'C:\winlogbeat.yml' -ToSession $session -Destination 'C:\ProgramData\Elastic\Beats\winlogbeat\winlogbeat.yml'
Invoke-Command -ComputerName $ip -Credential $creds -ScriptBlock {
    Get-Service winlogbeat |Start-Service
    Get-Service winlogbeat
}

#sysmon installation
# You can get pre-built config from https://github.com/SwiftOnSecurity/sysmon-config
# Or a more modular config from https://github.com/olafhartong/sysmon-modular (default - sysmonconfig.xml)
Copy-Item -Path 'C:\Sysmon.exe' -ToSession $session -Destination 'C:\Sysmon.exe'
Copy-Item -Path 'C:\Sysmon-Config.xml' -ToSession $session -Destination 'C:\Sysmon-Config.xml'
Invoke-Command -ComputerName $ip -Credential $creds -ScriptBlock {
    Start-Process 'C:\Sysmon.exe' -accepteula -i 'C:\Sysmon-Config.xml'
    Get-Service sysmon
}