#File's intent: This is a collection of one-liners to be used when investigating a device. Best used with invoke-command or locally. 

Update-Help
Get-Help process #searching for commandlets
Get-Command *process #shows command types of the search    

#REMOTING
Test-WSMan -ComputerName 172.16.12.10 #determines whether WinRM service is running on that endpoint
Test-NetConnection -Port 5985 -ComputerName 172.16.12.10 #tests if HTTP WinRM port related to WinRM are open on that endpoint, 5986 for HTTPS
    wmic #if winRM isn't enabled you can try and connect with wmic over port 135(RPC of TCP). Open terminal or cmd to enter a wmic prompt
    wmic /NODE:"172.16.12.10" computersystem get name #shows hostname of the endpoint
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" OS GET Name #shows OS name, can use as a test
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" service where caption="Windows Remote Management (WS-Management)" call startservice #starts service on a remote host
    psexec.exe \\172.16.12.10 cmd #can also try this or hostname to connect over 135 & 445. 
    psexec.exe \\172.16.12.10 -h -s powershell.exe Enable-PSRemoting -Force
    psexec.exe \\172.16.12.10 -u "yourdomain\administrator" -p "password" -s C:\Windows\System32\winrm.cmd quickconfig -q  
    Enable-PSRemoting -Force #needs to be enabled on the endpoint before trying to remote to it
    Set-Item WSMan:\localhost\client\trustedhosts '172.15.2.2' #done on the localhost to allow a connection to a specific endpoint
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
(Get-ADComputer -Filter *).name #lists all the hostnames on the DC.
[System.DateTime]::now
[System.TimeZoneInfo]::Local
Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory #condensed OS information
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -AutoSize #lists 32bit programs
Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap #lists 64bit programs

#USER/GROUPS
Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap #finds detailed accounts
Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap #finds account lastusetime, link with info from above
    Get-CimInstance -class Win32_UserProfile |Where-Object {$_.SID -eq 'S-1-5-21-4181923950-2520291949-3870243015-9999'} | Remove-CimInstance #removes legacy profile info that is left after an account is deleted. 
net user #uses net.exe which is bad.
Get-LocalUser #basic but get-wmi above is better
    Remove-LocalUser -Name "Bob"
Get-ADUser -Filter * #for all domain accounts
Get-ADUser -Filter 'SamAccountName -like "A*"' #Looks for accounts starting with A
    Get-ADObject -Filter * -SearchBase 'CN=heady,CN=Users,DC=546,DC=cmt' -Properties * # shows all properties related to the ADUser
    Enable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' #best to use the 'distinguishedname' field rather than 'name'.
    Disable-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # disables account
    Remove-ADAccount -identity 'CN=heady,CN=Users,DC=546,DC=cmt' # removes account
net use # checks for shared resources like mapped drives
Get-LocalGroupMember -Group Administrators |Select-Object -Property ObjectClass, Name, PrincipalSource, SID #detailed
net localgroup "Administrators"
Get-AdGroup -Filter * # lists all AD groups
Get-ADGroupMember -Identity 'Administrators'
Get-ADDomain #Shows information on the domain.
Get-GPO

#IP/CONNECTIONS/NETWORK
ipconfig /all 
Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # better ipconfig, shows active interfaces.
Get-NetIPConfiguration |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # shows all interfaces
ipconfig /displaydns #shows history of the dns resolver
Get-DnsClientCache |Format-Table -Wrap
Get-NetIPInterface #shows ip interfaces
    Get-NetRoute -InterfaceIndex 8 #shows routing for chosen interface

netstat -nao
Get-NetTCPConnection |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess |Format-Table #better netstat
Get-NetTCPConnection |Where-Object {$_.state -match "listen" -or $_.state -match "establish"} #looking for established or listen
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
Get-Process |Where-Object {$_.mainWindowTitle} | Format-Table Id, Name, mainWindowtitle -AutoSize #gets all processes that have a main window

Get-Service |Format-Table -Wrap
Get-Service |Where-Object {$_.Status -eq "Running"} |Format-Table -Wrap
Get-Service "wmi*"
    Stop-Service -Name "sysmon"
Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap #shows additional path

#TASKS/REGISTRY
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

#USB/FILE SEARCH/FILE INFORMATION/RECENT FILES
#Common paths to look at for malicious files:
    #C:\Windows\Temp
    #C:\Users\Administrator\Downloads
    #C:\Users\Administrator\AppData\Local\Temp
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

# Recently accessed Windows files.
# The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
# No point using the $env:APPDATA as it will default to account creds you're using so you won't see the recent files of the target user. Fill in the target username as required.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Windows\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastAccessTime -Descending |Format-Table -Wrap
# Below uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath.
$linkfiles_windows = Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Windows\Recent |Sort-Object -Property LastAccessTime -Descending
$WScript_windows = New-Object -ComObject WScript.Shell
$linkfiles_windows | ForEach-Object {$WScript_windows.CreateShortcut($_.FullName).TargetPath}

# Recently accessed Office files.
Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Office\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastWriteTime -Descending |Format-Table -Wrap
# Below uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath.
$linkfiles_office = Get-ChildItem -path C:\Users\"TargetUser"\AppData\Roaming\Microsoft\Office\Recent |Sort-Object -Property LastAccessTime -Descending
$WScript_office = New-Object -ComObject WScript.Shell
$linkfiles_office | ForEach-Object {$WScript_office.CreateShortcut($_.FullName).TargetPath}

#EVENTS
Get-EventLog -list
Get-EventLog -LogName Application |Format-Table -Wrap
Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #successful logon
Get-EventLog -LogName Security -InstanceId 4672 -Newest 20 |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-List #admin logon
Get-EventLog -LogName Security -InstanceId 4720 -Newest 20 |Format-List #account created
Get-EventLog -LogName Security -InstanceId 4778,4779 -Newest 20 |Format-List #RDP history
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"