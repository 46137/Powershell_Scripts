#File's intent: This is a collection of one-liners to be used when investigating a device. Best used with invoke-command or locally. 

<#Tasks:
- Test holly AD command
- Add section for get-mail (mailserver)
- Recycle bin command to get files from all users (SIDS), hash bin files?
- Network shares ADMIN$, IPC$, c$
- Combine recently access files commands
- Prefetch files
- System32: Get-AuthenticodeSignature -FilePath C:\Windows\System32\* |Where-Object {$_.Status -ne "Valid"}
- (get-scheduledtasks).actions 
#>



Update-Help
Get-Help process #searching for commandlets
Get-Command *process #shows command types of the search
(Measure-Command{Get-ComputerInfo}).TotalSeconds #show how long it takes to run a command    
(Get-Host).version #lists the powershell version

#REMOTING
1..254 | ForEach-Object { Test-Connection -count 1 127.0.0.$_ -ErrorAction SilentlyContinue} #VERY slow ping sweep.
Test-WSMan -ComputerName 172.16.12.10 #determines whether WinRM service is running on that endpoint
Test-NetConnection -Port 5985 -ComputerName 172.16.12.10 #tests if HTTP WinRM port related to WinRM are open on that endpoint, 5986 for HTTPS
New-Object System.Net.Sockets.TcpClient -ArgumentList 172.16.12.10,5985 #Quicker than Test-NetConnection
New-NetFirewallRule -DisplayName "Allow WinRM Port 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow #Opening port 5985 on endpoint if 'Enable-PsRemoting' doesn't work.
New-NetFirewallRule -DisplayName "Allow Ping" -Direction Inbound -Protocol ICMPv4 -Action Allow -Enabled True -Profile Any -LocalPort Any -EdgeTraversalPolicy Allow #Enable ping on Win10.
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block #Blocking a port.
Remove-NetFirewallRule -DisplayName "Block RDP" #Remove rules.
netsh firewall set icmpsetting 8 #Enable ping on Win7
    wmic #if winRM isn't enabled you can try and connect with wmic over port 135(RPC of TCP). Open terminal or cmd to enter a wmic prompt
    wmic /NODE:"172.16.12.10" computersystem get name #shows hostname of the endpoint
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" OS GET Name #shows OS name, can use as a test
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" service where caption="Windows Remote Management (WS-Management)" call startservice #starts service on a remote host
    psexec.exe \\172.16.12.10 cmd #can also try this or hostname to connect over 135 & 445. 
    psexec.exe \\172.16.12.10 -h -s powershell.exe Enable-PSRemoting -Force
    psexec.exe \\172.16.12.10 -u "yourdomain\administrator" -p "password" -s C:\Windows\System32\winrm.cmd quickconfig -q  
    Enable-PSRemoting -Force #needs to be enabled on the endpoint before trying to remote to it
    Set-Item WSMan:\localhost\client\trustedhosts "172.15.2.*" #done on the localhost to allow a connection to a specific subnet
    Set-Item WSMan:\localhost\client\trustedhosts * #done on the localhost to allow a connection to all endpoints
    Get-Item WSMan:\localhost\client\trustedhosts #shows the current localhost configuration
New-PSSession -ComputerName 172.16.12.10 -Credential Administrator #This will start a session but keep you local (For credentials it can be local or domain)
Get-PSSession #Shows active sessions.
Enter-PSSession 8 
Get-PSSession |Remove-PSSession #Removes all sessions.

#RUNNING SCRIPTS
Get-ExecutionPolicy -List #Shows the current state of the policies of the endpoint.
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned #RemoteSigned - Downloaded scripts must be signed by a trusted publisher.
Set-ExecutionPolicy -ExecutionPolicy Unrestricted #Unrestricted - No restrictions; all scripts can be run.

Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -FilePath C:\windows\file.ps1 #running a local script on a remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Start-Process -FilePath 'C:\file.exe'} #running a file on the remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Get-ChildItem C:\Users\Bob\Desktop} #viewing files on remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Get-Content C:\Users\Bob\Desktop\Names.txt} #viewing contents of file on remote box

$session=New-PSSession -ComputerName 172.16.1.51 -Credential Administrator #create session and copy item from it to local box
Copy-Item -Path 'C:\winlog.msi' -ToSession $session -Destination 'C:\winlog.msi' #copy a file to that session
Invoke-Command -ComputerName 172.16.1.51 -Credential Administrator -ScriptBlock {Start-Process -FilePath 'C:\winlog.msi' Get-Service winlogbeat} #run that file and show if the service is up

#SYSTEM INFORMATION
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

#ACTIVE DIRECTORY
Get-ADDomain #Shows information on the domain, inc DNS name.
(Get-ADComputer -Filter *).name # lists all the hostnames.
get-dnsserverresourcerecord -zonename "int-vpa.com" -rrtype "A" # lists the hostnames & associated IPs
(Get-ADUser -Filter *).name # list names of all domain accounts.
Get-ADUser -Filter * -Properties * |Select-Object -Property Name, WhenCreated | Sort-Object WhenCreated
Get-ADComputer -filter 'OperatingSystem -like "*"' -properties Name, OperatingSystem, OperatingSystemVersion, IPv4Address |select-object -property Name, OperatingSystem, OperatingSystemVersion, IPv4Address

Get-ADUser -Filter * #for all domain accounts
Get-ADUser -Filter 'SamAccountName -like "A*"' #Looks for accounts starting with A
    Get-ADObject -Filter * -SearchBase 'CN=heady,CN=Users,DC=546,DC=cmt' -Properties * # shows all properties related to the ADUser
    Get-ADPrincipalGroupMembership heady |Select-Object Name # Lists groups of the member
    Enable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' #best to use the 'distinguishedname' field rather than 'name'.
    Disable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # disables account
    Remove-ADUser -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # removes account

Get-AdGroup -Filter * # lists all AD groups
Get-ADGroupMember -Identity 'Administrators'
Get-GPO

#Sinkhole on DC
add-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "EQ,*.uan.ao,mincrosoft.com" #adding dns blocks
set-dnsserverqueryresolutionpolicy -name "BlackholePolicy" -action IGNORE -FQDN "EQ,*.uan.ao,mincrosoft.com,smallcatmeow.com"  #modifying dns blocks
get-dnsserverqueryresolutionpolicy
Clear-DnsClientCache # Clear local cache on all/effected hosts.

#USER/GROUPS
Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap #finds detailed accounts
Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap #finds account lastusetime, link with info from above
    Get-CimInstance -class Win32_UserProfile |Where-Object {$_.SID -eq 'S-1-5-21-4181923950-2520291949-3870243015-9999'} | Remove-CimInstance #removes legacy profile info that is left after an account is deleted. 
net user #uses net.exe which is bad.
Get-LocalUser #basic but get-wmi above is better
    Remove-LocalUser -Name "Bob"
net use # checks for shared resources like mapped drives
Get-LocalGroupMember -Group Administrators |Select-Object -Property ObjectClass, Name, PrincipalSource, SID #detailed
net localgroup "Administrators"

#IP/CONNECTIONS/NETWORK
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
Get-Content C:\Windows\System32\drivers\etc\hosts
Get-Content C:\Windows\System32\drivers\etc\services
Get-Content C:\Windows\System32\drivers\etc\networks

Get-WmiObject -Class Win32_NetworkAdapter |Select-Object -Property NetConnectionStatus,ServiceName,Name,NetConnectionID,AdapterType,MACAddress |Sort-Object -Property NetConnectionStatus -Descending |Format-Table #MAC
Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending #ARP IPv4
Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending #ARP IPv6

#PROCESS/SERVICES (wsmprovhost = is the process name of a remote powershell session)
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

#PERSISTANCE METHODS
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

Get-WMIObject -Namespace root\Subscription -Class __EventFilter #Shows the query property.
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer # List event consumers.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding #Shows detailed path.

#PRINTNIGHTMARE PRIV-ESC AND REMOVAL
Get-PrinterDriver |Select-Object -Property Name, PrinterEnvironment, Manufacturer, DataFile, ConfigFile |Format-Table -Wrap #To find persistence related to printnightmare
Get-smbopenfile #further info  
(Get-ChildItem -Path 'C:\Windows\system32\spool\DRIVERS\x64\3\' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Hashes all the driver files
    #Get-Service spooler |Stop-Service (Optional)
    #Stop-Process -id 1685 (Optional). For 'spoolsv', if not reset machine. 
    remove-printerdriver -name HP2057 #removes the driver
    get-smbopenfile |where-object {$_.path -like "*NIGHTMARE.DLL" } |close-smbopenfile #closes smb connections linked to the dll drivers so we can delete the file
    remove-item -Path C:\Windows\system32\spool\DRIVERS\x64\3\nightmare.dll -Force #removes the bad DLL

#USB/FILE SEARCH/FILE INFORMATION/RECENT FILES
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
Get-ChildItem C:\Windows\*.* |ForEach-Object {Get-AuthenticodeSignature $_} |Where-Object {$_.Status -ne "Valid"} #malicious files tend to be unsigned
    (Get-ItemProperty .\sethc.exe).GetAccessControl() |Format-Table -Wrap #Shows owner of the file.
    Get-Content C:\Users\Administrator\AppData\Local\Temp\sethc.exe | Out-String
    Get-FileHash -Algorithm SHA256 C:\Users\Administrator\AppData\Local\Temp\sethc.exe
    Compress-Archive -Path C:\Users\Work\Downloads -DestinationPath C:\compressed.zip
#looking at files created around the time of a task running
Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt "10/25/2018 11:29:00 AM" -and $_.CreationTime -lt "10/26/2018 11:40:00 AM"} |Sort-Object CreationTime, Name |Format-Table CreationTime, Name
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

#EVENTS
Get-EventLog -list
Get-EventLog -LogName Application |Format-Table -Wrap
Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #successful logon
Get-EventLog -LogName Security -InstanceId 4672 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #admin logon
Get-EventLog -LogName Security -InstanceId 4720 -Newest 20 |Format-List #account created
Get-EventLog -LogName Security -InstanceId 4778,4779 -Newest 20 |Format-List #RDP history
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"