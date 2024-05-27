# POWERSHELL

This collection of commands & scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network. The readme.md below contains short commands that can be used for quick analysis.

## Test
**Test**
## **Test**

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
- [Network Connections](#network-connections)
- [Processes & Services](#processes--services)
- [Shares & Files](#shares--files)
- [Persistence Methods](#Persistence-methods)
- [Events](#events)
- [Active Directory](#active-directory)
  - [Domain](#domain)
  - [AD Users](#ad-users)
  - [AD Groups](#ad-groups)
  - [AD Sinkhole](#ad-sinkhole)
- [Tasks](#readmemd-tasks)

### **Powershell Overview**
```powershell
#Updating
Update-Help

#Searching for commandlets.
Get-Help process

#Shows command types of the search.
Get-Command *process

#Lists the powershell version.
(Get-Host).version

#Show how long it takes to run a command.
(Measure-Command{[COMMAND]}).TotalSeconds
```

### **Scanning**
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

### **Remoting**
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
#Shows active sessions.
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
runas /noprofile /user:dwc\ubolt powershell
```

### RDP
```powershell
#Blocking RDP firewall rule.
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
#Removing RDP block rule.
Remove-NetFirewallRule -DisplayName "Block RDP"
```

### **Running Scripts**
```powershell
#Shows the current state of the policies of the endpoint.
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
#Shows the current language mode state. ConstrainedLanguage constrains the use of certain features, NoLanguage disables all.
$ExecutionContext.SessionState.LanguageMode
#Changing language mode for that powershell session.
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```
```powershell
#Generates a secure password file to be used in scripts credentials. 
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File [OUTPUT\FILE\LOCATION]
```

### **System Information**
```powershell
whoami
Get-ComputerInfo
Systeminfo
[System.DateTime]::now
[System.TimeZoneInfo]::Local
Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory #condensed OS information
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -AutoSize #lists 32bit programs
Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap #lists 64bit programs
Get-WmiObject -Class Win32_Product
Get-WindowsDriver -Online -All #Shows driver information.
```

### **Local Users & Groups**
```powershell
Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap #finds detailed accounts
Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap #finds account lastusetime, link with info from above
    Get-CimInstance -class Win32_UserProfile |Where-Object {$_.SID -eq 'S-1-5-21-4181923950-2520291949-3870243015-9999'} | Remove-CimInstance #removes legacy profile info that is left after an account is deleted. 
net user #uses net.exe which is bad.
Get-LocalUser #basic but get-wmi above is better
    Remove-LocalUser -Name "Bob"
net use # checks for shared resources like mapped drives
Get-LocalGroupMember -Group Administrators |Select-Object -Property ObjectClass, Name, PrincipalSource, SID #detailed
net localgroup "Administrators"
```

### **Network Connections**
```powershell
ipconfig /all 
Get-NetIPConfiguration -Detailed # shows all fields.
Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # better ipconfig, shows active interfaces.
Get-NetIPConfiguration |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # shows all interfaces
Get-NetIPAddress
Get-NetAdapter # shows interfaces including MAC addresses.
ipconfig /displaydns #shows history of the dns resolver
Get-DnsClientCache |Format-Table -Wrap
Get-NetIPInterface #shows ip interfaces
    Get-NetRoute -InterfaceIndex 5 #shows routing for chosen interface

netstat -nao
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess |Format-Table #better netstat
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table #adds process and creation time
Get-NetTCPConnection |Where-Object {$_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::" -and $_.LocalAddress -ne "::1"} |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Sort-Object -Property CreationTime -Descending |Format-Table #simplfied with process
    tasklist /svc |findstr 21664 #shows further information on the suspect PID
Get-NetUDPEndpoint |Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table -Wrap
Get-Content C:\Windows\System32\drivers\etc\hosts
Get-Content C:\Windows\System32\drivers\etc\services
Get-Content C:\Windows\System32\drivers\etc\networks

Get-WmiObject -Class Win32_NetworkAdapter |Select-Object -Property NetConnectionStatus,ServiceName,Name,NetConnectionID,AdapterType,MACAddress |Sort-Object -Property NetConnectionStatus -Descending |Format-Table #MAC
Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending #ARP IPv4
Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending #ARP IPv6
```

### **Processes & Services**
```powershell
Get-Process
    Get-Process svchost -FileVersionInfo -ErrorAction SilentlyContinue |Format-List
    Stop-Process -Name "notepad"
    Stop-Process -Id 18252
Get-WmiObject -Class Win32_Process |Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |Format-Table -Wrap #shows additional path
Get-WmiObject -Class win32_process |ForEach-Object {New-Object -Type PSCustomObject -Property @{'CreationDate' = $_.converttodatetime($_.creationdate); 'PID' = $_.ProcessID; 'PPID' = $_.ParentProcessID; 'Name' = $_.Name; 'Path' = $_.ExecutablePath}} |Select-Object -Property CreationDate, PID, PPID, Name, Path |Sort-Object -Property CreationDate -Descending |Format-Table # Recent processes with path.
Get-Process |Where-Object {$_.mainWindowTitle} |Select-Object -Property Id,ProcessName,MainWindowTitle #gets all processes that have a main window

Get-Service |Format-Table -Wrap
Get-Service |Where-Object {$_.Status -eq "Running"} |Format-Table -Wrap
Get-Service "wmi*"
    Stop-Service -Name "sysmon"
    .\sc.exe delete sysmon
Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap #shows pid, additional path
```

### **Shares & Files**
```powershell
#Common paths to look at for malicious files:
    #C:\Windows\Temp
    #C:\Users\Administrator\Downloads
    #C:\Users\Administrator\AppData\Local\Temp

(Get-ChildItem -Path C:\Windows\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_}
Get-ChildItem -Path C:\Windows\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
Get-AuthenticodeSignature -FilePath C:\Windows\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid
(Get-ChildItem -Path C:\Windows\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files
Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
Get-AuthenticodeSignature -FilePath C:\Users\Administrator\AppData\Local\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid 
(Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files

Get-PnpDevice |Where-Object {$_.Class -eq 'USB'} |Format-Table -Wrap #USB connections
Get-ItemProperty -Path HKLM:\system\currentcontrolset\enum\USBSTOR\*\* |Select-Object -Property ClassGUID,FriendlyName #USB running connections

Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue -Include @("msupdater.exe", "ssdpsvc.dll", "msacem.dll", "mrpmsg.dll", "restore.dat", "index.dat", "sethc.exe") | Format-List FullName
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue -Include @("AcroRd32Info.exe", "igfxHK", "news.rinpocheinfo.com", "d.txt", "127.0.0.1.txt", "mim.exe", "shell.gif", "tests.jsp") | Format-List FullName
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue -Include @("*.exe", "*.log") | Format-List FullName
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue -Include "test.txt"  | Format-List FullName
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue |Sort-Object -Property LastWriteTime -Descending |Select-Object -First 20 |Format-Table LastWriteTime,FullName #recent files used, also try 'LastAccessTime' or 'CreationTime'
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue -Include "*.exe" |Sort-Object -Property LastWriteTime -Descending |Select-Object -First 20 |Format-Table LastWriteTime,FullName #recent executables used
Get-ChildItem \\.\pipe\ #shows named pipes
Get-AuthenticodeSignature -FilePath C:\Users\Administrator\Downloads\bad.exe #malicious file tend to be unsigned
Get-Acl -Path \\fs1\ADMIN$\ |Format-List #Shows folder permissions.
Get-ChildItem C:\Windows\*.* |ForEach-Object {Get-AuthenticodeSignature $_} |Where-Object {$_.Status -ne "Valid"} #malicious files tend to be unsigned
    (Get-ItemProperty .\sethc.exe).GetAccessControl() |Format-Table -Wrap #Shows owner of the file.
    Get-Content C:\Users\Administrator\AppData\Local\Temp\sethc.exe | Out-String
    Get-FileHash -Algorithm SHA256 C:\Users\Administrator\AppData\Local\Temp\sethc.exe
    Compress-Archive -Path C:\Users\Work\Downloads -DestinationPath C:\compressed.zip
#looking at files created around the time of a task running
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt "10/25/2018 11:29:00 AM" -and $_.CreationTime -lt "10/26/2018 11:40:00 AM"} |Sort-Object CreationTime, Name |Format-Table CreationTime, Name
#looking/decrypting cpasswords. cpassword is a component of AD's group policy preference (GPP) that allows admins to set passwords via group policy.
Get-ChildItem -Recurse -Path \\dwc\SYSVOL\dwc.gov.au\Policies\ -Include *.xml -ErrorAction SilentlyContinue |Select-String -Pattern "password"
    Import-Module Get-DecryptedCpassword #Function from Powersploit to decrypt.
    Get-DecryptedCpassword 'RI133B2Wl2CiI0Cau1DtrtTe3wdFwzCiWB5PSAxXMDstchJt3bL0Uie0BaZ/7rdQjugTonF3ZWAKa1iRvd4JGQ'

Get-FileShare
Get-SmbShare

#Recycle Bin files
#Currently one run for the local user, need to determine how to choose users.
(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() |Select-Object @{n="OriginalLocation";e={$_.ExtendedProperty("{9B174B33-40FF-11D2-A27E-00C04FC30871} 2")}},Name #Shows Origional path
(New-Object -ComObject Shell.Application).NameSpace(0x0a).Items() | Select-Object ModifyDate, Name, Size, Path |Sort-Object -Property modifydate -Descending #Shows modify date
Get-childItem  'C:\$Recycle.Bin' -Force -ErrorAction SilentlyContinue #lists user SIDs recyclebin folders
Get-ChildItem  'C:\$Recycle.Bin\S-1-5-21-2597032353-3689133737-3729642783-1006' -Force -ErrorAction SilentlyContinue |Sort-Object -Property lastwritetime -Descending #lists files but not the names, just types.
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |Sort-Object -Property lastwritetime
(Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 of all files in the bin.

# Recently accessed Windows files.
# The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
# No point using the $env:APPDATA as it will default to account creds you're using so you won't see the recent files of the target user. Fill in the target username as required.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Windows\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastAccessTime -Descending |Format-Table -Wrap
# Below uses the above .lnk fullname information ($linkfiles) and creates a new object to find the .lnk files targetpath.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Windows\Recent |ForEach-Object {(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath}

# Recently accessed Office files.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Office\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastWriteTime -Descending |Format-Table -Wrap
# Below uses the above .lnk fullname information ($linkfiles) and creates a new object to find the .lnk files targetpath.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Office\Recent |ForEach-Object {(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath}

```

### **Persistence Methods**
```powershell
Get-ScheduledTask |Select-Object -Property Date,State,TaskName,TaskPath |Sort-Object -Property Date -Descending | Select-Object -First 20 |Format-Table -Wrap #recently created tasks
Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending |Format-Table -Wrap #recently run tasks
Get-ScheduledTask |Where-Object {$_.state -eq "Running"} #looks for currently active tasks, keep in mind ready tasks also
    Stop-ScheduledTask -TaskName "sekurlsa" #stops task
    Disable-ScheduledTask -TaskName "sekurlsa" #disables task 
    Unregister-ScheduledTask -TaskName "sekurlsa" #deletes task
    Get-ScheduledTask -TaskName 'sekurlsa' |Select-Object * #Shows all fields.
    (Get-ScheduledTask -TaskName 'sekurlsa').Actions
    Get-ScheduledTaskInfo sekurlsa
    schtasks.exe /query /tn sekurlsa /v /fo list

Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Get-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Get-BitsTransfer -AllUsers -Name * #Shows BitsJob objects for all users
Get-BitsTransfer -AllUsers -Name "TestJob1"
    #Suspending or Removing
    $remove = Get-BitsTransfer -AllUsers -Name "TestJob1"
    Remove-BitsTransfer -BitsJob $remove

#Detect with SysmonID:19. Shows trigger for execution.
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter “Name=’Updater’” | Remove-WmiObject -Verbose #Removing
#Detect with SysmonID:20. Shows actions, e.g. Base64 encoded string, executing files.
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
    Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter “Name=’Updater’” | Remove-WmiObject -Verbose #Removing
#Detect with SysmonID:21. Binds Filter and Consumer Classes.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter “__Path LIKE ‘%Updater%’” | Remove-WmiObject -Verbose #Removing

#PRINTNIGHTMARE PRIV-ESC AND REMOVAL
Get-PrinterDriver |Select-Object -Property Name, PrinterEnvironment, Manufacturer, DataFile, ConfigFile |Format-Table -Wrap #To find persistence related to printnightmare
Get-smbopenfile #further info  
(Get-ChildItem -Path 'C:\Windows\system32\spool\DRIVERS\x64\3\' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Hashes all the driver files
    #Get-Service spooler |Stop-Service (Optional)
    #Stop-Process -id 1685 (Optional). For 'spoolsv', if not reset machine. 
    remove-printerdriver -name HP2057 #removes the driver
    get-smbopenfile |where-object {$_.path -like "*NIGHTMARE.DLL" } |close-smbopenfile #closes smb connections linked to the dll drivers so we can delete the file
    remove-item -Path C:\Windows\system32\spool\DRIVERS\x64\3\nightmare.dll -Force #removes the bad DLL

```

### **Events**
```powershell
Get-EventLog -list
Get-EventLog -LogName Application |Format-Table -Wrap
Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #successful logon
Get-EventLog -LogName Security -InstanceId 4672 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #admin logon
Get-EventLog -LogName Security -InstanceId 4720 -Newest 20 |Format-List #account created
Get-EventLog -LogName Security -InstanceId 4778,4779 -Newest 20 |Format-List #RDP history
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
Get-WinEvent -Path example.evtx |Out-GridView #Static analysis in GUI.
Get-WinEvent -Path example.evtx |Where-Object{$_.Message -like "*fail*"} |Format-Table -Wrap
```

### **Active Directory**
### Domain
```powershell
Get-ADDomain #Shows information on the domain, inc DNS name.
(Get-ADDomain).domainmode #Shows functional level (e.g. Windows2012R2). This defines the features of AD DS that can be used by the DC.
(Get-ADForest).forestmode #Shows functional level (e.g. Windows2012R2). This defines the features of AD DS that can are available in the forest.
(Get-ADComputer -Filter *).name # lists all the hostnames.
(Get-ADComputer -Filter {ms-MCS-AdmPwdExpirationTime -like '*'} |Select-Object SamAccountName).count #Total accounts with local admin password solution (LAPS) enabled. If there is a value in ms-MCS-AdmPwd attribute, it is enabled. 
Resolve-DnsName DC1.dwc.gov.au # Lists the IP address of the DNS name.
Resolve-DnsName 10.10.10.10 # Reverse DNS lookup.
(get-adcomputer -filter *).name |foreach {Resolve-DnsName $_} # lists the dns(hostname) & associated IPs.
get-dnsserverresourcerecord -zonename "int-vpa.com" -rrtype "A" # lists the hostnames & associated IPs.
(Get-ADUser -Filter *).name # list names of all domain accounts.
Get-ADUser -Filter * -Properties * |Select-Object -Property Name, WhenCreated | Sort-Object WhenCreated
Get-ADComputer -filter 'OperatingSystem -like "*"' -properties Name, OperatingSystem, OperatingSystemVersion, IPv4Address |select-object -property Name, OperatingSystem, OperatingSystemVersion, IPv4Address
```

### AD Users
```powershell
Get-ADUser -Filter * #for all domain accounts
Get-ADUser -Filter 'Name -like "*Leigh"' # Looks for specific names.
Get-ADUser -Filter 'SamAccountName -like "A*"' #Looks for username accounts starting with A.
    (Get-ADUser -Identity "Heady" -Properties MemberOf).MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name #Listing what groups a domain user is a part of.
    Get-ADObject -Filter * -SearchBase 'CN=heady,CN=Users,DC=546,DC=cmt' -Properties * # shows all properties related to the ADUser
    Get-ADPrincipalGroupMembership heady |Select-Object Name # Lists groups of the member
    Enable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' #best to use the 'distinguishedname' field rather than 'name'.
    Disable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # disables account
    Remove-ADUser -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # removes account
Get-ADUser -Identity 'krbtgt' -Properties 'passwordlastset' # Lists last time password was changed.
Get-ADUser -Filter {PasswordNotRequired -eq $true} # Users configured not to require a password.
Get-ADUser -Filter * -Properties PasswordNeverExpires | Where-Object {$_.PasswordNeverExpires -eq $true} #Check users for password never expiring.
Get-ADUser -filter {Description -notlike "*CTF Player*" -and Description -notlike "*IT Admin of DWC*"} -properties Description |Select-Object samaccountname,description #checking domain accounts for passwords in descriptions.
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth #AS-Response roasting is obtaining the AS-REP and attempting to crack the hash offline. Pre-authentication requires users to prove their identity before receiving a TGT.
Get-ADUser -Filter {UserPassword -like "*"} -Properties UserPassword |Select-Object SamAccountName,UserPassword #To find plaintext password stored in the UserPassword attribute, decode with cyberchef. Was deprecated in server 2003 for the unicodePwd attribute.
Get-LapsADPassword -Identity ctf2.dwc.gov.au -AsPlainText #Get LAPS
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties PasswordLastSet, ServicePrincipalName |Sort-Object PasswordLastSet | Select-Object Name, PasswordLastSet, ServicePrincipalName #User accounts with SPNs and list password last set.
Get-ADObject -Filter {servicePrincipalName -like '*'} -Properties servicePrincipalName |Where-Object {$_.name -notlike "Win10Client*"} | Select-Object Name, servicePrincipalName #Objects with SPNs.

```

### AD Groups
```powershell
Get-AdGroup -Filter * # lists all AD groups
Get-ADGroupMember -Identity 'Administrators'
(Get-ADGroupMember -Identity 'Domain Admins').name #Lists all domain admins.
Get-GPO
Get-ADDefaultDomainPasswordPolicy #Compare to ISM.
```

### AD Sinkhole
```powershell
add-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "EQ,*.uan.ao,mincrosoft.com" #adding dns blocks
set-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "EQ,*.uan.ao,mincrosoft.com,smallcatmeow.com"  #modifying dns blocks
get-dnsserverqueryresolutionpolicy
Clear-DnsClientCache # Clear local cache on all/effected hosts.
```

### **Readme.md Tasks**
```powershell

```
- Commands for recyclebin,prefetch (include hashes).
  - Recycle bin command to get files from all users (SIDS), hash bin files?
- Alternate data streams.
- Add section for get-mail (mailserver).
- Network shares ADMIN$, IPC$, c$

### **Host Enumeration Tasks**
- Rework 'Payload_KeyTerrain-Survey'.
- Decide if to complete 'Manual_Full-Survey'.
- Create 'Auto CIM-OS-Detection'?

### **Modules Framework Tasks**
- Find a better way in 'Auto_Invoke-Modules' to call modules (not via a txt file).
- Complete 'BT-Persistence' module.
- Complete 'BT-PII' module.
- Complete 'Payload_KeyTerrain-Survey-Modules'.
- Create 'BT-ADServer' module.
- Create 'BT-MailServer' module.
- Create 'BT-WebServer' module.
- Create 'BT-RDSHashes' module?