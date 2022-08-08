$ErrorActionPreference = 'SilentlyContinue' # Disables errors.
[System.DateTime]::now
[System.TimeZoneInfo]::Local
Get-ComputerInfo
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |Select-Object -Property *
Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object -Property *
Get-WmiObject -Class win32_useraccount |Select-Object -Property *
Get-WmiObject -Class win32_userprofile |Select-Object -Property *
Get-LocalGroupMember -Group Administrators |Select-Object -Property *
Get-NetIPConfiguration -Detailed
Get-NetIPAddress
Get-DnsClientCache |Format-Table -Wrap
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table #looking for established or listen & adds process and creation time
Get-Content C:\Windows\System32\drivers\etc\hosts
Get-Content C:\Windows\System32\drivers\etc\services
Get-Content C:\Windows\System32\drivers\etc\networks
Get-WmiObject -Class Win32_NetworkAdapter |Select-Object -Property NetConnectionStatus,ServiceName,Name,NetConnectionID,AdapterType,MACAddress |Sort-Object -Property NetConnectionStatus -Descending |Format-Table #MAC
Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending #ARP IPv4
Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending #ARP IPv6
Get-WmiObject -Class win32_process |ForEach-Object {New-Object -Type PSCustomObject -Property @{'CreationDate' = $_.converttodatetime($_.creationdate); 'PID' = $_.ProcessID; 'PPID' = $_.ParentProcessID; 'Name' = $_.Name; 'Path' = $_.ExecutablePath}} |Select-Object -Property CreationDate, PID, PPID, Name, Path |Sort-Object -Property CreationDate -Descending |Format-Table # Recent processes with path.
Get-WmiObject -Class Win32_Process |Select-Object -Property *
Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap #shows pid, additional path
Get-WmiObject -Class Win32_Service |Select-Object -Property *
Get-ScheduledTask |Select-Object -Property *
Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending |Format-Table -Wrap #recently run tasks
Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Get-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-WMIObject -Namespace root\Subscription -Class __EventFilter #Shows the query property.
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer # List event consumers.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding #Shows detailed path.
Get-ChildItem -Path C:\Windows\Temp |Sort-Object -Property *
Get-AuthenticodeSignature -FilePath C:\Windows\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid
(Get-ChildItem -Path C:\Windows\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files
Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp |Sort-Object -Property *
Get-AuthenticodeSignature -FilePath C:\Users\Administrator\AppData\Local\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid 
(Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |Select-Object -Property *
(Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_}
Get-PnpDevice |Where-Object {$_.Class -eq 'USB'} |Format-Table -Wrap #USB connections
Get-ItemProperty -Path HKLM:\system\currentcontrolset\enum\USBSTOR\*\*
Get-FileShare
Get-SmbShare |Select-Object -Property *
Get-ChildItem \\.\pipe\ |Select-Object -Property *

