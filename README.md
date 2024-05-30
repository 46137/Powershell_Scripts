# POWERSHELL

This collection of commands & scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network. The readme.md below contains short commands that can be used for quick analysis.

# Commands Table of Contents
- [Powershell Overview](#powershell-overview)
- [Scanning](#scanning)
- [Remoting](#remoting)
  - [WinRM](#winrm)
  - [WMIC](#wmic)
  - [PSexec.exe](#psexecexe)
  - [Runas.exe](#runasexe)
  - [RDP](#rdp)
- [Running Scripts](#running-scripts)
- [System Information](#system-information)
- [Local Users & Groups](#local-users--groups)
- [IP & Network Connections](#ip--network-connections)
- [Processes & Services](#processes--services)
- [Files](#files)
- [Persistence Methods](#Persistence-methods)
- [Events](#events)
- [Active Directory](#active-directory)
  - [Domain](#domain)
  - [AD Users](#ad-users)
  - [AD Vulnerabilities](#ad-vulnerabilities)
  - [AD Groups](#ad-groups)
  - [Shares](#shares)
  - [AD Sinkhole](#ad-sinkhole)
- [Tasks](#readmemd-tasks)

## **Powershell Overview**
```powershell
#Updating
Update-Help

#Searching for commandlets.
Get-Help process

#Displays the command types of the search.
Get-Command *process

#Lists the powershell version.
(Get-Host).version

#Show how long it takes to run a command.
(Measure-Command{[COMMAND]}).TotalSeconds
```

## **Scanning**
### Ping Scans
```powershell
#Slow ping sweep.
1..254 | ForEach-Object { Test-Connection -count 1 127.0.0.$_ -ErrorAction SilentlyContinue}
```
```powershell
#Fast ping sweep.
$Subnets = '10.10.10'#,'10.10.11'
#Creates an array of active hosts via ICMP.
$Up_Hosts = @()
foreach ($Subnet in $Subnets){
    $IPs = 1..254 | ForEach-Object {"$($Subnet).$_"}
    $Ping = $IPs|ForEach-Object {
        #(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250) 
        [Net.NetworkInformation.Ping]::New().SendPingAsync($_, 250) #PowerShell v5
    }
    [Threading.Tasks.Task]::WaitAll($Ping)
    $Ping.Result | ForEach-Object {
        if($_.Status -eq 'Success'){
            $Up_Hosts += $_.Address.IPAddressToString
            $IP = $_.Address.IPAddressToString
            "$IP - Hosts Up"
        }
    }
}
$Up_Hosts
```
```powershell
#Enabling ping on Win10 which could have it disabled by default.
New-NetFirewallRule -DisplayName "Allow Ping" -Direction Inbound -Protocol ICMPv4 -Action Allow -Enabled True -Profile Any -LocalPort Any -EdgeTraversalPolicy Allow
#Enabling ping on Win7 which could have it disabled by default.
netsh firewall set icmpsetting 8
```
### Port Scans
```powershell
#Slow port test. Common ports: 135(Domain),445(SMB),5985/6(WinRM),22(SSH),3389(RDP)
Test-NetConnection -Port [PORT] -ComputerName [IP ADDRESS]
```
```powershell
#Fast port test.
New-Object System.Net.Sockets.TcpClient -ArgumentList [IP ADDRESS],[PORT]
```
```powershell
#Fast port scan.
$Subnets = "10.10.10."#,"10.10.11."
$IPs = 1..255
$Port = 135 #Common ports: 135(Domain),445(SMB),5985/6(WinRM),22(SSH),3389(RDP)
$TimeoutMilliseconds = 50
#Creates an array of active hosts.
$Open_Port = @()
foreach ($Subnet in $Subnets){
    $IPs | ForEach-Object{
        $IP = $Subnet + $_
        $Socket = [System.Net.Sockets.TcpClient]::new()
        $Result = $Socket.BeginConnect($IP, $Port, $null, $null) # Null 1 is optional callback methods, null 2 is operation state for callback method.
        $Success = $Result.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)
            if ($Success -and $Socket.Connected){
                $Open_Port += $IP
                "$IP - Open Port: $Port"
                $Socket.Close()
            }
        Write-Progress -Activity "Scanning Network" -Status "$Subnet$_" -PercentComplete (($_/($IPs.Count))*100) # Progress bar.
    }
}
```

## **Remoting**
### WinRM
```powershell
#Tests if the WinRM service is running on that endpoint.
Test-WSMan -ComputerName [NAME\IP]
```
```powershell
#Needs to be enabled on the endpoint before trying to remote to it.
Enable-PSRemoting -Force
```
```powershell
#Checking current localhost configuration.
Get-Item WSMan:\localhost\client\trustedhosts
#Modify localhost to allow a connection to a specific subnet.
Set-Item WSMan:\localhost\client\trustedhosts "172.15.2.*"
#Modify localhost to allow a connection to all endpoints.
Set-Item WSMan:\localhost\client\trustedhosts
```
```powershell
#Opening port 5985 on endpoint if 'Enable-PsRemoting' doesn't work.
New-NetFirewallRule -DisplayName "Allow WinRM Port 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
```
```powershell
#Starting a new local or domain session. Using a IP Address will use NTLM authentication & Computer Name will use Kerberos authentication.
New-PSSession -ComputerName [NAME\IP] -Credential [DOMAIN\USER]
#Displays the active sessions.
Get-PSSession
#Entering session
Enter-PSSession [NUMBER]
#Removing all sessions. 
Get-PSSession |Remove-PSSession
```
```powershell
#Running a local script on a remote endpoint.
Invoke-Command -ComputerName [NAME\IP] -Credential [DOMAIN\USER] -FilePath C:\windows\file.ps1
```
```powershell
#Running a command on a remote endpoint.
Invoke-Command -ComputerName [NAME\IP] -Credential [DOMAIN\USER] -ScriptBlock {[COMMAND]}
```
```powershell
#Running a command on a remote endpoint with esablished credentials.
$User = [DOMAIN\USER]
$PWord = Get-Content [PATH\TO\SECURE\FILE] | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
Invoke-Command -ComputerName [NAME\IP] -Credential $Credential -ErrorAction SilentlyContinue -ScriptBlock {[COMMAND]}
```
```powershell
#Moving & removing files in a session.
#Create session.
$Session = New-PSSession [NAME\IP] -Credential [DOMAIN\USER]
#Copy local file to remote endpoint.
Copy-Item -Path [LOCAL\FILE\PATH] -ToSession $Session -Destination [REMOTE\FILE\PATH]
#Removing file on remote endpoint.
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path [PATH\TO\FILE] -Recurse -Force}
#Copy remote file to local host.
Copy-Item -Path [REMOTE\FILE\PATH] -Destination [LOCAL\FILE\PATH] -FromSession $Session
```

### WMIC
WMIC commands use DCOM over port 135 to communicate with remote endpoints.
```powershell
#Displays hostname of the remote endpoint. (May need authentication)
wmic /NODE:[NAME\IP] ComputerSystem GET Name
```
```powershell
#Displays OS name.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] OS GET Name
```
```powershell
#Starting a service.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] Service where caption="Windows Remote Management (WS-Management)" call startservice
```
```powershell
#Enabling PSRemoting.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] process call create "powershell.exe -NoProfile -Command Enable-PSRemoting -Force"
```

### PSexec.exe
```powershell
#Opening powershell on a remote endpoint. (May need authentication)
psexec.exe \\[NAME\IP] powershell.exe
```
```powershell
#Enabling PSRemoting.
psexec.exe \\[NAME\IP] -u [DOMAIN\USER] -p [PASSWORD] -h -s powershell.exe Enable-PSRemoting -Force
```

### Runas.exe
```powershell
#Starting a powershell or cmd session.
runas.exe /noprofile /user:[DOMAIN\USER] powershell
```

### RDP
```powershell
#Blocking RDP firewall rule.
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
#Removing RDP block rule.
Remove-NetFirewallRule -DisplayName "Block RDP"
```

## **Running Scripts**
```powershell
#Displays the the current state of the policies of the endpoint.
Get-ExecutionPolicy -List
#Setting to 'RemoteSigned' where downloaded scripts must be signed by a trusted publisher. (May need elevated privileges)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```
```powershell
#Creating a new powershell session to bypass the need for elevated privileges.
Powershell.exe -ExecutionPolicy Bypass
#Creating a new powershell version 2 session to bypass language mode.
Powershell.exe -Version 2 -ExecutionPolicy Bypass
```
```powershell
#Displays the the current language mode state. ConstrainedLanguage constrains the use of certain features, NoLanguage disables all.
$ExecutionContext.SessionState.LanguageMode
#Changing language mode for that powershell session.
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```
```powershell
#Generates a secure password file to be used in scripts credentials. 
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File [OUTPUT\FILE\LOCATION]
```

## **System Information**
```powershell
#Displays the the system information of the endpoint.
Systeminfo.exe
#Or via powershell. (Slow)
Get-ComputerInfo
#Or via powershell. (Quick)
Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property CSName, Caption, Version |Format-List
```
```powershell
#Displays the system date & time.
[System.DateTime]::now
[System.TimeZoneInfo]::Local
```
```powershell
#Installed applications. (Not accurate)
Get-WmiObject -Class Win32_Product
#Installed 32bit applications.
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -AutoSize
#Installed 64bit applications.
Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap
```
```powershell
#Displays the driver information.
Get-WindowsDriver -Online -All
```

## **Local Users & Groups**
### Users
```powershell
#Name of logged in user.
whoami.exe
#Or via powershell.
(Get-CimInstance Win32_ComputerSystem).Username
```
```powershell
#Displays the user accounts.
net.exe user
#Or via powershell. (Basic)
Get-LocalUser
#Displays the detailed accounts.
Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap
#Displays the last login time in association with details above.
Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap
```
```powershell
#To remove a localuser.
Remove-LocalUser -Name [NAME]
#To remove legacy profiles left after an account is deleted.
Get-CimInstance -class Win32_UserProfile |Where-Object {$_.SID -eq [SID]} | Remove-CimInstance
```
### Groups
```powershell
#Displays the local group details. (Basic)
net.exe localgroup [GROUPNAME]
#Or via powershell.
Get-LocalGroupMember -Group [GROUPNAME] |Select-Object -Property ObjectClass, Name, PrincipalSource, SID
```

## **IP & Network Connections**
### IP Information
```powershell
#Displays the IP information.
ipconfig.exe /all
#Or via powershell.
Get-NetIPAddress
```
```powershell
#Displays the all interfaces. (Filtered)
Get-NetIPConfiguration |Select-Object -Property InterfaceAlias,IPv4Address,InterfaceIndex,IPv4DefaultGateway
```
```powershell
#Displays the active interfaces. (Filtered)
Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,InterfaceIndex,IPv4DefaultGateway
```
```powershell
#Displays the all interfaces incuding MAC address.
Get-NetAdapter
```
```powershell
#Routing information on chosed interface.
Get-NetRoute -InterfaceIndex [NUMBER]
```
### DNS
```powershell
#Displays the local FQDN->IP resolution.
Get-Content C:\Windows\System32\drivers\etc\hosts
#Displays the DNS cache.
ipconfig.exe /displaydns
#Or via powershell.
Get-DnsClientCache |Format-Table -Wrap
#Displays the IP address of the DNS name.
Resolve-DnsName [FQDN]
#Reverse DNS lookup.
Resolve-DnsName [IP ADDRESS]
```
```powershell
#Clear DNS cache.
ipconfig.exe /flushdns
#Or via powershell.
Clear-DNSClientCache
```
### Network Connections
```powershell
#Displays the network connections.
netstat.exe -nao
```
```powershell
#Or via powershell.
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess |Format-Table
```
```powershell
#Displays the TCP network connections with linked process and creation time.
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table
```
```powershell
#Displays the TCP network connections with linked process and creation time. (Filetered)
Get-NetTCPConnection |Where-Object {$_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::" -and $_.LocalAddress -ne "::1"} |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Sort-Object -Property CreationTime -Descending |Format-Table
```
```powershell
#Displays the UDP with linked process.
Get-NetUDPEndpoint |Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table -Wrap
```
```powershell
#Displays file content. File generally used by apps doing loopback connections.
Get-Content C:\Windows\System32\drivers\etc\networks
```
```powershell
#Displays the MAC information.
Get-WmiObject -Class Win32_NetworkAdapter |Select-Object -Property NetConnectionStatus,ServiceName,Name,NetConnectionID,AdapterType,MACAddress |Sort-Object -Property NetConnectionStatus -Descending |Format-Table
```
```powershell
#Displays the ARP IPv4
Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending
#Displays the ARP IPv6
Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending
```

## **Processes & Services**
### Processes
```powershell
#Displays the processes.
tasklist.exe
#Or via powershell. (Basic)
Get-Process
#Displays the processes with PPID & path.
Get-WmiObject -Class Win32_Process |Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |Format-Table -Wrap
```
```powershell
#Displays the recent processes with PPID & path.
Get-WmiObject -Class win32_process |ForEach-Object {New-Object -Type PSCustomObject -Property @{'CreationDate' = $_.converttodatetime($_.creationdate); 'PID' = $_.ProcessID; 'PPID' = $_.ParentProcessID; 'Name' = $_.Name; 'Path' = $_.ExecutablePath}} |Select-Object -Property CreationDate, PID, PPID, Name, Path |Sort-Object -Property CreationDate -Descending |Format-Table
```
```powershell
#Displays the all processes that have a main window.
Get-Process |Where-Object {$_.mainWindowTitle} |Select-Object -Property Id,ProcessName,MainWindowTitle
```
```powershell
#Displays the PID information. (Can also use -Name)
Get-Process -Id [NUMBER] -FileVersionInfo -ErrorAction SilentlyContinue |Format-List
#Kill process. (Can also use -Name)
Stop-Process -Id 18252
```
### Services
```powershell
#Displays the services.
sc.exe query
#Or via powershell. (Basic)
Get-Service |Format-Table -Wrap
```
```powershell
#Displays the services with linked PID and path.
Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap
```
```powershell
#Displays the running services with linked PID and path.
Get-WmiObject -Class Win32_Service |Where-Object {$_.State -eq "Running"} |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap
```
```powershell
#Stopping a service.
Stop-Service -Name [NAME]
#Remove a service
Remove-Service -Name [NAME]
#Or
sc.exe delete [NAME]
```
```powershell
#List port numbers for well known services.
Get-Content C:\Windows\System32\drivers\etc\services
```

## **Files**
Common paths to look at for malicious files:
- C:\Windows\Temp
- C:\Users\Administrator\Downloads
- C:\Users\Administrator\AppData\Local\Temp

```powershell
#Displays the content of folder.
Get-ChildItem -Path [FOLDER\PATH] |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName
```
```powershell
#Displays the content of folder including file hashes.
(Get-ChildItem -Path [FOLDER\PATH]).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_}
```
```powershell
#Checks folder for invalid files. Look at: 'C:\Windows' & 'C:\Windows\System32'
Get-ChildItem [FOLDER\PATH]\*.* |ForEach-Object {Get-AuthenticodeSignature $_} |Where-Object {$_.Status -ne "Valid"}
```
```powershell
#Checks a drive for specific files.
Get-ChildItem -Path [DRIVE] -Recurse -Force -ErrorAction SilentlyContinue -Include @([FILE1], [FILE2]) | Format-List FullName
```
```powershell
#Checks a drive for files types.
Get-ChildItem -Path [DRIVE] -Recurse -Force -ErrorAction SilentlyContinue -Include @("*.exe", "*.log") | Format-List FullName
```
```powershell
#Recently executed binaries on a drive.
Get-ChildItem -Path [DRIVE] -Recurse -Force -ErrorAction SilentlyContinue -Include "*.exe" |Sort-Object -Property LastWriteTime -Descending |Select-Object -First 20 |Format-Table LastWriteTime,FullName
```
```powershell
#Displays the files created around a certain time, e.g. malicious task running.
Get-ChildItem [DRIVE] -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt "10/25/2018 11:29:00 AM" -and $_.CreationTime -lt "10/26/2018 11:40:00 AM"} |Sort-Object CreationTime, Name |Format-Table CreationTime, Name
```
```powershell
#Displays the named pipes used for inter-process communication (IPC).
Get-ChildItem \\.\pipe\ |ForEach-Object {[PSCustomObject]@{FullPath = "\\.\pipe\$($_.Name)"}}
```
Displays recently accessed Windows files by looking at link files. Common paths:
- C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\Recent
- C:\Users\[USER]\AppData\Roaming\Microsoft\Office\Recent
```powershell
#List all link files in the specified directory.
$lnkfiles = Get-ChildItem -Path [PATH\TO\LNK]]
#Process each link file to retrieve its properties and target path.
$lnkfiles | ForEach-Object {
    #Create a WScript.Shell COM object
    $shell = New-Object -ComObject WScript.Shell
    #Get the shortcut's target path
    $lnkfile = $shell.CreateShortcut($_.FullName)
    #Create a custom object with the required properties
    [PSCustomObject]@{
        CreationTime = $_.CreationTime
        FileName = $_.Name
        TargetPath = $lnkfile.TargetPath
    }
} |Sort-Object -Property CreationTime -Descending
```
```powershell
#Commands for a specific file, i.e. suspicious or malicious.
#Verified the digital signature of a file.
Get-AuthenticodeSignature -FilePath [PATH\TO\FILE]
#Displays the owner of a file.
(Get-ItemProperty [PATH\TO\FILE]).GetAccessControl() |Format-Table -Wrap
#Displays the human-readable content of a file.
Get-Content [PATH\TO\FILE] | Out-String
#Displays the hash of a file.
Get-FileHash -Algorithm SHA256 [PATH\TO\FILE]
#Compresses a file for assessing.
Compress-Archive -Path [PATH\TO\FILE] -DestinationPath [PATH\NAME.ZIP]
```
```powershell
#Displays USB running connections.
Get-ItemProperty -Path HKLM:\system\currentcontrolset\enum\USBSTOR\*\* |Select-Object -Property ClassGUID,FriendlyName
#Displays USB connections.
Get-PnpDevice |Where-Object {$_.Class -eq 'USB'} |Format-Table -Wrap
```
```powershell
#Displays recycle bin files of the current user's SID.
(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() | Select-Object ModifyDate, Name, Size, Path |Sort-Object -Property modifydate -Descending
#Or
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |Sort-Object -Property lastwritetime
```
```powershell
#Displays recycle bin files of the current user's SID and includes the origional path.
(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() |Select-Object @{n="OriginalLocation";e={$_.ExtendedProperty("{9B174B33-40FF-11D2-A27E-00C04FC30871} 2")}},Name
```
```powershell
#Gets hashes of recycle bin files of the current user's SID.
(Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_}
```
## **Persistence Methods**
### Scheduled Tasks
```powershell
#Displays recently created tasks.
Get-ScheduledTask |Select-Object -Property Date,State,TaskName,TaskPath |Sort-Object -Property Date -Descending | Select-Object -First 20 |Format-Table -Wrap
```
```powershell
#Displays recently run tasks.
Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending |Format-Table -Wrap
```
```powershell
#Displays running tasks.
Get-ScheduledTask |Where-Object {$_.state -eq "Running"}
```
```powershell
Get-ScheduledTask -TaskName [NAME] |Select-Object * #Task information.
Get-ScheduledTaskInfo [NAME]
Stop-ScheduledTask -TaskName [NAME] #Stops task.
Disable-ScheduledTask -TaskName [NAME] #Dsables task. 
Unregister-ScheduledTask -TaskName [NAME] #Deletes task.
(Get-ScheduledTask -TaskName [NAME]).Actions
```
### Run Keys
```powershell
Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
### BitsTransfer
```powershell
#Displays the BitsJob objects for all users.
Get-BitsTransfer -AllUsers -Name *
#Displays specific job.
Get-BitsTransfer -AllUsers -Name [NAME]
```
```powershell
#Suspending or Removing BitsJob.
$remove = Get-BitsTransfer -AllUsers -Name [NAME]
Remove-BitsTransfer -BitsJob $remove
```
### WMI Event Subscriptions
```powershell
#Detect with SysmonID:19. Displays the trigger for execution.
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
#Removing.
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter “Name=[NAME]” | Remove-WmiObject -Verbose
```
```powershell
#Detect with SysmonID:20. Displays the actions, e.g. Base64 encoded string, executing files.
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
#Removing.
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter “Name=[NAME]” | Remove-WmiObject -Verbose
```
```powershell
#Detect with SysmonID:21. Binds Filter and Consumer Classes.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
#Removing.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter “__Path LIKE ‘%[NAME]%’” | Remove-WmiObject -Verbose
```
### Printnightmare
```powershell
#Displays persistence related to printnightmare.
Get-PrinterDriver |Select-Object -Property Name, PrinterEnvironment, Manufacturer, DataFile, ConfigFile |Format-Table -Wrap
#Further information.
Get-smbopenfile
#Validating through hashing the driver files.
(Get-ChildItem -Path 'C:\Windows\system32\spool\DRIVERS\x64\3\' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_}
```
```powershell
#Remediate through:
#Stopping service. (Optional)
Get-Service spooler |Stop-Service
#Stopping spoolsv process. (Optional, can also reset machine)
Stop-Process -id [PID]
#Deleting the driver.
Remove-PrinterDriver -Name [NAME]
#Closing SMB connections linked to the DLL drivers so the file can be deleted.
Get-SmbOpenFile |Where-Object {$_.path -Like "*[NAME].DLL" } |Close-SmbOpenFile
#Delete the malicious DLL.
Remove-Item -Path C:\Windows\system32\spool\DRIVERS\x64\3\[NAME].dll -Force
```

## **Events**
```powershell
Get-EventLog -list
Get-EventLog -LogName Application |Format-Table -Wrap
Get-EventLog -LogName Security -InstanceId [EVENTID] -Newest 20 |Format-List
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```
```powershell
#Analysis of log file.
Get-WinEvent -Path [LOGS].evtx |Out-GridView
Get-WinEvent -Path [LOGS].evtx |Where-Object{$_.Message -like "*fail*"} |Format-Table -Wrap
```

## **Active Directory**
### Domain
```powershell
#Displays the information on the domain.
Get-ADDomain
#Displays the functional level (e.g. Windows2012R2). This defines the features of AD DS that can be used by the DC.
(Get-ADDomain).domainmode
#Displays the functional level (e.g. Windows2012R2). This defines the features of AD DS that can are available in the forest.
(Get-ADForest).forestmode
```
```powershell
#Displays default domain password policy. (Compare to ISM)
Get-ADDefaultDomainPasswordPolicy
```
```powershell
#Displays domain hostnames, OS, OS versions and IPs.
Get-ADComputer -Filter {OperatingSystem -like "*"} -Properties Name, OperatingSystem, OperatingSystemVersion, IPv4Address |Select-Object -Property Name, OperatingSystem, OperatingSystemVersion, IPv4Address
#Displays domain hostnames & associated IP addresses via DNS lookup. (More accurate)
(Get-ADComputer -Filter *).name |Foreach-Object {Resolve-DnsName $_}
#Or
Get-DnsServerResourceRecord -ZoneName [DNS.FQDN] -rrtype "A"
```

### AD Users
```powershell
#Displays domain user names.
(Get-ADUser -Filter *).SamAccountName
#Total enabled domain users.
(Get-ADUser -Filter {enabled -eq $true}).count
#Total disabled domain users.
(Get-ADUser -Filter {enabled -ne $true}).count
#Recently created domain users.
Get-ADUser -Filter * -Properties WhenCreated | Sort-Object WhenCreated -Descending |Select-Object -Property SamAccountName, WhenCreated -First 20
```
```powershell
#Looking for specific names.
Get-ADUser -Filter {Name -like "*[NAME]*"}
#Or
Get-ADUser -Filter {SamAccountName -like "A*"}
```
```powershell
#Specific user queries.
#Displays all properties of a domain user.
Get-ADObject -Filter * -SearchBase '[DISTINGUISHED NAME]' -Properties *
#Displays the groups of a domain user.
(Get-ADUser -Identity [SAMACCOUNTNAME] -Properties MemberOf).MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name
#Displays the groups of a domain user. (Slow)
Get-ADPrincipalGroupMembership lhead_ctf |Select-Object Name
#Enable, disable & remove.
Enable-ADAccount -identity '[DISTINGUISHED NAME]'
Disable-ADAccount -identity '[DISTINGUISHED NAME]'
Remove-ADUser -identity '[DISTINGUISHED NAME]'
```

### AD Vulnerabilities
Service Principal Names
```powershell
#Displays domain user accounts with a SPN & password last set.
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties PasswordLastSet, ServicePrincipalName |Sort-Object PasswordLastSet | Select-Object Name, PasswordLastSet, ServicePrincipalName
#Displays when the KerberosTGT account's password was last set.
Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet, ServicePrincipalName | Select-Object Name, PasswordLastSet, ServicePrincipalName
```
```powershell
#Displays SQL domain objects with SPNs.
Get-ADObject -Filter {servicePrincipalName -like '*sql*'} -Properties servicePrincipalName | Select-Object Name, servicePrincipalName
```
User Descriptions
```powershell
#Displays domain user's descriptions. Looking for passwords.
Get-ADUser -Filter {Description -notlike "*[STANDARD WORDING]*" -and Description -notlike "*[STANDARD WORDING]*"} -properties Description |Select-Object samaccountname,description
```
AS-REP Roasting
```powershell
#Looking for AS-Response roastable domain users, which involves obtaining the AS-REP and attempting to crack the hash offline. Pre-authentication requires users to prove their identity before receiving a TGT.
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
userPasswords
```powershell
#Displays plaintext password stored in the UserPassword attribute, decode with cyberchef. Was deprecated in server 2003 for the unicodePwd attribute.
Get-ADUser -Filter {UserPassword -like "*"} -Properties UserPassword |Select-Object SamAccountName,UserPassword
```
cPasswords
```powershell
#Displays pattern matched results in domain policy files.
#E.g. 'cpassword' which is a component of AD's group policy preference (GPP) that allows admins to set passwords via group policy.
Get-ChildItem -Recurse -Path \\[DOMAIN]\SYSVOL\[FQDN]\Policies\ -Include *.xml -ErrorAction SilentlyContinue |Select-String -Pattern "password"
#Decrypt cpasswords with the following Powersploit module.
Import-Module Get-DecryptedCpassword
Get-DecryptedCpassword 'RI133B2Wl2CiI0Cau1DtrtTe3wdFwzCiWB5PSAxXMDstchJt3bL0Uie0BaZ/7rdQjugTonF3ZWAKa1iRvd4JGQ'
```
Passwords
```powershell
#Displays domain users who DON'T require a password.
(Get-ADUser -Filter {PasswordNotRequired -eq $true}).SamAccountName
#Displays domain users whose password never expires. (May be weak)
(Get-ADUser -Filter {PasswordNeverExpires -eq $true}).SamAccountName
```
LAPS
```powershell
#Displays accounts with local admin password solution (LAPS) enabled. If there is a value in ms-MCS-AdmPwd attribute, it is enabled.
(Get-ADComputer -Filter {ms-MCS-AdmPwdExpirationTime -like '*'}).SamAccountName
#Displays accounts with LAPS disabled.
(Get-ADComputer -Filter {ms-MCS-AdmPwdExpirationTime -notlike '*'}).SamAccountName
#Displaying the LAPS password of a specific account. (Need account with read LAPS permissions)
Get-LapsADPassword -Identity [FQDN] -AsPlainText
```
DC Sync Objects\
Checking users for the following permission to conduct a DCSync:
- DS-Replication-Get-Changes (Rights-GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- DS-Replication-Get-Changes-All (Rights-GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- DS-Replication-Get-Changes-In-Filtered-Set (Rights-GUID 89e95b76-444d-4c62-991a-0facbeda640c)
```powershell
#Displays AD's distinguished name.
(Get-ADDomain).DistinguishedName
#Using the distinguished name to display AD objects that have DS replication permissions.
(Get-Acl "ad:\[DistinguishedName]").Access |Where-Object {($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" ) } |Select-Object IdentityReference, ObjectType
```
### AD Groups
```powershell
#Displays all AD groups.
Get-AdGroup -Filter *
#Displays selected groups.
Get-AdGroup -Filter {SamAccountName -like "*admin*"}
```
```powershell
#Displays members of a AD group, e.g. Domain Admins.
(Get-ADGroupMember -Identity '[GROUP]').SamAccountName
```

### Shares
```powershell
#Displays shared resources, e.g. mapped network drives
net.exe use
#Displays the share folder permissions.
Get-Acl -Path \\[SHARE]\ADMIN$\ |Format-List
```

### AD Sinkhole
```powershell
#Adding DNS block, from AD.
add-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "[FQDN]"
#Modifying the DNS block.
set-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "[FQDN],[NEW FQDN]"
#Check block.
get-dnsserverqueryresolutionpolicy
#Clear local cache on all/effected hosts.
Clear-DnsClientCache
```

## **Readme.md Tasks**
```powershell

```
- Commands for recyclebin,prefetch (include hashes).
  - Recycle bin command to get files from all users (SIDS), hash bin files?
- Alternate data streams.
- Add section for get-mail (mailserver).
- Network shares ADMIN$, IPC$, c$

## **Host Enumeration Tasks**
- Rework 'Payload_KeyTerrain-Survey'.
- Decide if to complete 'Manual_Full-Survey'.
- Create 'Auto CIM-OS-Detection'?

## **Modules Framework Tasks**
- Find a better way in 'Auto_Invoke-Modules' to call modules (not via a txt file).
- Complete 'BT-Persistence' module.
- Complete 'BT-PII' module.
- Complete 'Payload_KeyTerrain-Survey-Modules'.
- Create 'BT-ADServer' module.
- Create 'BT-MailServer' module.
- Create 'BT-WebServer' module.
- Create 'BT-RDSHashes' module?