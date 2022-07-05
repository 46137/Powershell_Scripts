
param(
[Parameter(Mandatory=$False)]
[Switch]$a
)

$banner = @"
 _ __ __ _ _ __ ___ .
| '__/ _` | '_ ` _  :
| | | (_| | | | | | |
|_|  \__,_|_| |_| |_|    
   

   Tactical Survey collector forIncident Responders
   Run ./ram.ps1 for basic enum
   Use -a for the following deeper enum (named pipes etc)


"@ 

<#
.NAME
RAM version 1.0

.SYNOPSIS
Tactical survey Incident Response tool.

.EXAMPLE
    PS C:\> .\ram.ps1
        Simply run the script or provide the argument -a for advanced investigation 
#>

Write-host "$banner" -ForegroundColor Green
$ErrorActionPreference= 'silentlycontinue'
# Check for Admin Rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host 'You must run RAM using elevated privileges session...'
    Exit 1
}

$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$cname = (gi env:\Computername).Value
Write-Host "Collecting data for $cname ($ip) | $(Get-Date -Format dd/MM/yyyy-H:mm:ss)"

$data = {
"==== GENERAL INFORMATION ===="
#Get-ComputerInfo | Format-List -Property CsDNSHostName, CsDomain, OsName, OsVersion, OsBuildNumber, OsArchitecture, OsUptime, OsLocalDateTime, TimeZone, OsSerialNumber, OsMuiLanguages, OsHotFixes, WindowsRegisteredOrganization, WindowsRegisteredOwner, WindowsSystemRoot, OsPagingFiles, CsManufacturer, CsModel, CsName, CsProcessors, CsNetworkAdapters, BiosBIOSVersion, BiosSeralNumber, BiosFirmwareType, CsDomainRole, OsStatus, OsSuites, LogonServer, DeviceGuardSmartStatus, DeviceGuardRequiredSecurityProperties, DeviceGuardAvailableSecurityProperties, DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning, DeviceGuardCodeIntegrityPolicyEnforcementStatus, DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus
systeminfo
"----------------------------------------
"

"==== NETWORK INFORMATION ===="
"--- Active Network Interfaces ---"
Get-NetAdapter | ? status -eq "up" |  Get-NetIPAddress | Select IPAddress,InterfaceIndex, InterfaceAlias, AddressFamily,PrefixOrigin |Sort InterfaceAlias | Format-Table -Wrap
"----------------------------------------
"

"--- DNS Cache ---"
Get-DnsClientCache -Status 'Success' | Select Name, Data
"----------------------------------------
"

"--- Shared folders ---"
net use
"----------------------------------------
"

"--- Process Connections ---"
$nets = netstat -bano|select-string 'TCP|UDP'; 
foreach ($n in $nets)    
{
$p = $n -replace ' +',' ';
$nar = $p.Split(' ');
$pname = $(Get-Process -id $nar[-1]).Path;
$n -replace "$($nar[-1])","$($ppath) $($pname)";
}
"----------------------------------------
"

"==== PROCESS INFORMATION ===="
"--- Running processes ---"
tasklist /v /fo table /fi "STATUS ne Unknown"
"----------------------------------------
"

"--- Process List ---"
Get-Process -IncludeUserName | Format-Table -Property Name, Id, Path, UserName, Company, Handles, StartTime, HasExited -Wrap
"----------------------------------------
"

"--- Process Commandline ---"
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine | Sort Name | Format-Table -Wrap
"----------------------------------------
"

"==== PERSISTENCE ===="
"--- Commands on Startup ---"
Get-CimInstance -Class Win32_StartupCommand | Format-Table -Property Name, Command, User, Location -Wrap
"----------------------------------------
"

"--- Scheduled Tasks ---"
(Get-ScheduledTask).Where({$_.State -ne "Disabled"}) | Sort TaskPath | Format-Table -Wrap
"----------------------------------------
"

"--- Services ---"
Get-WmiObject win32_service | Select-Object Name, PathName, StartName, StartMode, State, ProcessId | Sort PathName| Format-Table -Wrap
#Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Name, PathName, ProcessId, StartMode, State | Format-Table
"----------------------------------------
"

"==== USER ACTIVITY ===="
"--- Recently used USB devices ---"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName
"----------------------------------------
"

"--- Recently modified files ---"
$RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File
$RecentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime
"----------------------------------------
"

"--- PowerShell history ---"
history
"----------------------------------------
"

"--- Kerberos sessions ---"
klist sessions
"----------------------------------------
"

"--- SMB sessions ---"
Get-SmbSession
"----------------------------------------
"

"--- RDP sessions ---"
qwinsta /server:localhost
"----------------------------------------
"

if ($a -eq $true)
{
"==== ADVANCED INVESTIGATION ===="
"--- Total Process Instances ---"
Get-Process | Group-Object ProcessName | Select Count, Name | Sort Count -Descending
"----------------------------------------
"

"--- Prefetch files ---"
gci C:\Windows\Prefetch\ | Sort Name | Format-Table Name,CreationTime,LastWriteTime,LastAccessTime
"----------------------------------------
"

"--- DLL List ---"
gps | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
"----------------------------------------
"

"--- WMI ---"
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | FT Consumer,Filter,__SERVER -wrap
"----------------------------------------
"

"--- WMI Filters ---"
Get-WmiObject -Class __EventFilter -Namespace root\subscription | FT Name, Query, PSComputerName -wrap
"----------------------------------------
"

"--- WMI Consumers ---"
Get-WmiObject -Class __EventConsumer -Namespace root\subscription | FT Name,ScriptingEngine,ScriptText -wrap
"----------------------------------------
"

"--- Windows Defender Exclusions ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
"----------------------------------------
"

"--- Named Pipes List ---"
Get-ChildItem -Path '\\.\pipe\' |  Sort Length | Format-Table FullName, Length, IsReadOnly, Exists, CreationTime, LastAccessTime
"----------------------------------------
"

}

}

& $data | Out-File -FilePath $pwd\RAM_$cname.txt
Write-Host "Collection saved in $pwd\RAM_$cname.txt" -ForegroundColor Green