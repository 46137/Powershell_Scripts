# Overview: This is a legacy script not for grading just for my references.

# If Get-ExecutionPolicy is set to Restricted, no scripts will run. Set-ExecutionPolicy remotesigned.

# To do: $psversiontable to run different versions
# To do: Current accounts to objects 
# To do: Logons - extract info from message block
# To do: IPconfig as objects
# To do: Network connections as objects
# To do: DNS history as objects
# To do: Firewall as objects
# To do: Recently access files - do it for all users who have logged onto target host
# To do: Prefetch files - extract aditional information from the contents of the file
# To do: Group policy as objects
# To do: autoruns as objects, each object should accurately represent a single runkey. 
# To do: commandline history - get history of all users. Also have consideration for the limitations of the Get-History cmdlet. hint. powershell -nop
# To do: find files, show content

# Variable output.
$Output="$env:USERPROFILE\Desktop\Windows_Baseline_Powershell_v3.txt"

Write-Output "==================================================================================================================================================================================
============================================================================= POWERSHELL v3 BASELINE ============================================================================= 
==================================================================================================================================================================================" |Out-File -FilePath $Output

# Empty line used (`n).
Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=============================================================================== SYSTEM INFORMATION ==============================================================================" |Out-File -Append -FilePath $Output
[System.DateTime]::now |Out-File -Append -FilePath $Output
[System.TimeZoneInfo]::Local |Select-Object -Property DisplayName |Format-List |Out-File -Append -FilePath $Output
Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=============================================================================== SYSTEM PATCH LEVEL ==============================================================================" |Out-File -Append -FilePath $Output
Get-WmiObject -Class Win32_QuickFixEngineering |Sort-Object -Property InstalledOn -Descending |Format-Table -Wrap |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "========================================================================= INSTALLED APPLICATIONS (64 Bit) ============================================================================" |Out-File -Append -FilePath $Output     
# The uninstall registry key is used because the Win32_Product class is really slow.
Get-ItemProperty -Path HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object -Property InstallDate, DisplayName, DisplayVersion, InstallSource |Sort-Object -Property InstallDate -Descending |Format-Table -Wrap |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "========================================================================= INSTALLED APPLICATIONS (32 Bit) ============================================================================" |Out-File -Append -FilePath $Output     
# The uninstall registry key is used because the Win32_Product class is really slow.
Get-ItemProperty -Path HKLM:\software\Wow6432Node\microsoft\windows\currentversion\Uninstall\* |Select-Object -Property InstallDate, DisplayName, DisplayVersion, InstallSource |Sort-Object -Property InstallDate -Descending |Format-Table -Wrap |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================ PROCESS SNAPSHOT ==============================================================================" |Out-File -Append -FilePath $Output
# Chose Win32_Process over Get-Process to get the parent process id parameter. 
Get-WmiObject -Class Win32_Process |Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |Format-Table -Wrap |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================ SERVICES SNAPSHOT =============================================================================" |Out-File -Append -FilePath $Output
Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================ CURRENT ACCOUNTS ==============================================================================" |Out-File -Append -FilePath $Output
Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap |Out-File -Append -FilePath $Output
Write-Output "ADMINISTRATORS GROUP" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-LocalGroupMember -Group Administrators |Select-Object -Property ObjectClass, Name, PrincipalSource, SID |Out-File -Append -FilePath $Output
net localgroup Administrators |Out-File -Append -FilePath $Output
Write-Output "USERS GROUP" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-LocalGroupMember -Group Users |Select-Object -Property ObjectClass, Name, PrincipalSource, SID |Out-File -Append -FilePath $Output
net localgroup Users |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output     
Write-Output "============================================================================ SUCCESSFUL LOGON (RECENT 20) ========================================================================" |Out-File -Append -FilePath $Output
# Admin privileges requried for Get-Eventlog commandlet.
Write-Output "Logon Types: 2=Logon via console, 3=Network Logon, 4=Batch Logon, 5=Windows Service Logon, 7=Credentials used to unlock screen, 8=Network logon sending credentials (cleartext),
             9=Different credentials used than logged on user, 10=Remote interactive logon (RDP), 11=Cached credentials used to logon, 12=Cached remote interactive, 13=Cached unlock." |Out-File -Append -FilePath $Output
Write-Output `n |Out-File -Append -FilePath $Output
Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output     
Write-Output "============================================================================= FAILED LOGON (RECENT 20) ===========================================================================" |Out-File -Append -FilePath $Output
# Admin privileges requried for Get-Eventlog commandlet.
Get-EventLog -LogName Security -InstanceId 4625 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output     
Write-Output "=========================================================================== LOGON WITH ADMIN (RECENT 20) =========================================================================" |Out-File -Append -FilePath $Output
# Admin privileges requried for Get-Eventlog commandlet.
Get-EventLog -LogName Security -InstanceId 4672 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output     
Write-Output "=========================================================================== ACCOUNT CREATED (RECENT 20) =========================================================================" |Out-File -Append -FilePath $Output
# Admin privileges requried for Get-Eventlog commandlet.
Get-EventLog -LogName Security -InstanceId 4720 -Newest 20 |Format-List |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output     
Write-Output "================================================================================== RDP HISTORY  ==============================================================================" |Out-File -Append -FilePath $Output
# Admin privileges requried for Get-Eventlog commandlet.
Get-EventLog -LogName Security -InstanceId 4778,4779 -Newest 20 |Format-List |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=================================================================================== ARP HISTORY ===============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending |Out-File -Append -FilePath $Output
arp -a |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=============================================================================== IP CONFIGURATIONS ============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetIPConfiguration |Select-Object -Property InterfaceAlias,InterfaceDescription,IPv4Address,IPv4DefaultGateway,IPv6Address,IPv6DefaultGateway |Format-Table -Wrap
ipconfig /all |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=============================================================================== NETWORK CONNECTIONS ============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess |Format-Table |Out-File -Append -FilePath $Output
netstat -ano |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=============================================================================== NETWORK INTERFACES =============================================================================" |Out-File -Append -FilePath $Output
Write-Output "NetConnectionStatus: 0=Disconnected, 2=Connected, 7=Media Disconnected, 12=Credentials Required." |Out-File -Append -FilePath $Output
Get-WmiObject -Class Win32_NetworkAdapter |Select-Object -Property NetConnectionStatus,ServiceName,Name,NetConnectionID,AdapterType,MACAddress |Sort-Object -Property NetConnectionStatus -Descending |Format-Table |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=================================================================================== DNS HISTORY ================================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-DnsClientCache |Format-Table -Wrap |Out-File -Append -FilePath $Output
ipconfig /displaydns |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================= SCHEDULED TASKS ===============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-ScheduledTask |Out-File -Append -FilePath $Output
schtasks /query |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output
Write-Output "=========================================================================== FIREWALL PROFILES/SETTINGS ==============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetFirewallSetting |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetFirewallProfile |Out-File -Append -FilePath $Output
netsh firewall show config |Out-File -Append -FilePath $Output
netsh firewall show currentprofile |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output
Write-Output "================================================================================= FIREWALL RULES ==============================================================================" |Out-File -Append -FilePath $Output
# Not on WIN7: Get-NetFirewallRule |Format-Table |Out-File -Append -FilePath $Output
netsh advfirewall firewall show rule name=all dir=in |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output        
Write-Output "================================================================================== USB HISTORY ==================================================================================" |Out-File -Append -FilePath $Output
Get-ItemProperty -Path HKLM:\system\currentcontrolset\enum\USBSTOR\*\* |Select-Object -Property ClassGUID,FriendlyName |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "======================================================================== RECENTLY ACCESSED WINDOWS FILES ===========================================================================" |Out-File -Append -FilePath $Output
# The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
Get-ChildItem -path $env:APPDATA\Microsoft\Windows\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastAccessTime -Descending |Format-Table -Wrap |Out-File -Append -FilePath $Output
# This uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath.
Write-Output "====ASSOCIATED FILE LOCATIONS====" |Out-File -Append -FilePath $Output
$linkfiles_windows = Get-ChildItem -path $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent |Sort-Object -Property LastAccessTime -Descending
$WScript_windows = New-Object -ComObject WScript.Shell
$linkfiles_windows | ForEach-Object {$WScript_windows.CreateShortcut($_.FullName).TargetPath} |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "========================================================================= RECENTLY ACCESSED OFFICE FILES ===========================================================================" |Out-File -Append -FilePath $Output
# The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
Get-ChildItem -path $env:APPDATA\Microsoft\Office\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastWriteTime -Descending |Format-Table -Wrap |Out-File -Append -FilePath $Output 
# This uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath.
Write-Output "====ASSOCIATED FILE LOCATIONS====" |Out-File -Append -FilePath $Output
$linkfiles_office = Get-ChildItem -path $env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent |Sort-Object -Property LastAccessTime -Descending
$WScript_office = New-Object -ComObject WScript.Shell
$linkfiles_office | ForEach-Object {$WScript_office.CreateShortcut($_.FullName).TargetPath} |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================== FILE CONTENT ================================================================================" |Out-File -Append -FilePath $Output
# Locating last written text file on user's file system and getting the content.
Get-ChildItem -Path $env:USERPROFILE\ *.exe -Recurse |Sort-Object -Property LastAccessTime -Descending |Select-Object -First 1 -Property FullName |Out-File -Append -FilePath $Output 
Get-ChildItem -Path $env:USERPROFILE\ *.exe -Recurse |Sort-Object -Property LastWriteTime -Descending |Select-Object -First 1 |Get-Content |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "================================================================================== NAMED PIPES =================================================================================" |Out-File -Append -FilePath $Output
# Using .net framework but using get-childitem will provide more property objects.
[System.IO.Directory]::GetFiles("\\.\\pipe\") |Out-File -Append -FilePath $Output
# Get-ChildItem -Path \\.\pipe\ |Select-Object -Property FullName

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "========================================================================= PREFETCH FILES (CREATION TIME) ================================================================================" |Out-File -Append -FilePath $Output
# Admin privileges required to access C:\Windows\Prefetch.
Get-ChildItem -Path C:\Windows\Prefetch |Select-Object -Property CreationTime,Length,Name |Sort-Object -Property CreationTime -Descending |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "======================================================================= PREFETCH FILES (MODIFICATION TIME) ================================================================================" |Out-File -Append -FilePath $Output
# Admin privileges required to access C:\Windows\Prefetch.
Get-ChildItem -Path C:\Windows\Prefetch |Select-Object -Property LastWriteTime,Length,Name |Sort-Object -Property LastWriteTime -Descending |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "=========================================================================== GROUP POLICY CONFIGURATION ==========================================================================" |Out-File -Append -FilePath $Output
# Get-ADUser and Get-GPO
# This is a slow command to run. /v for verbose mode to providing additional information.
gpresult /v |Out-File -Append -FilePath $Output
 
Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "==================================================================================== AUTORUNS ===================================================================================" |Out-File -Append -FilePath $Output
Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ |Out-File -Append -FilePath $Output
Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ |Out-File -Append -FilePath $Output
Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ |Out-File -Append -FilePath $Output
Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ |Out-File -Append -FilePath $Output

Write-Output `n |Out-File -Append -FilePath $Output         
Write-Output "============================================================================== COMMANDLINE HISTORY ==============================================================================" |Out-File -Append -FilePath $Output
Get-History |Out-File -Append -FilePath $Output





