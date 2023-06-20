#Script intent: If you're given keyterrain to survey daily throughout an exercise, this will create a local output of each host to look for anomalies.

        [System.DateTime]::now
        [System.TimeZoneInfo]::Local
        "=== OS SUMMARY ==="
        Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory #condensed OS information
        "=== ACTIVE INTERFACES ==="
        Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # better ipconfig, shows active interfaces.
        "=== RECENTLY INSTALLED APPLICATIONS ==="
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap #lists 5 most recently installed 32bit programs
        Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap #lists 5 most recently installed 64bit programs
        "=== RECENTLY USED ACCOUNTS ==="
        Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap #finds account lastusetime
        "=== ACCOUNTS DETAILS ==="
        Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap #finds detailed accounts
        "=== CONNECTIONS (NO LOOPBACK) ==="
        Get-NetTCPConnection |Where-Object {$_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::" -and $_.LocalAddress -ne "::1"} |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Sort-Object -Property CreationTime -Descending |Format-Table #simplfied with process
        Get-DnsClientCache |Format-Table -Wrap
        "=== PROCESSES ==="
        Get-WmiObject -Class win32_process |ForEach-Object {New-Object -Type PSCustomObject -Property @{'CreationDate' = $_.converttodatetime($_.creationdate); 'PID' = $_.ProcessID; 'PPID' = $_.ParentProcessID; 'Name' = $_.Name; 'Path' = $_.ExecutablePath}} |Select-Object -Property CreationDate, PID, PPID, Name, Path |Sort-Object -Property CreationDate -Descending |Format-Table # Recent processes with path.
        "=== RUNNING SERVICES ==="
        Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap #shows pid, additional path
        "=== RECENTLY CREATED TASKS ==="
        Get-ScheduledTask |Select-Object -Property Date,State,TaskName,TaskPath |Sort-Object -Property Date -Descending | Select-Object -First 20 |Format-Table -Wrap #recently created tasks
        "=== RECENTLY RUN TASKS ==="
        Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending |Format-Table -Wrap #recently run tasks
        "=== HOSTS FILE ==="
        Get-Content C:\Windows\System32\drivers\etc\hosts
        "=== REGISTRY RUNKEYS ==="
        Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        "=== SUBSCRIPTION EVENTS ==="
        Get-WMIObject -Namespace root\Subscription -Class __EventFilter #Shows the query property.
        Get-WMIObject -Namespace root\Subscription -Class __EventConsumer # List event consumers.
        Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding #Shows detailed path.
        "=== TEMP FILES ==="
        Get-ChildItem -Path C:\Windows\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
        Get-AuthenticodeSignature -FilePath C:\Windows\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid
        (Get-ChildItem -Path C:\Windows\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files
        Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
        Get-AuthenticodeSignature -FilePath C:\Users\Administrator\AppData\Local\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid 
        (Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 hash values for files
        "=== RECYCLE BIN ==="
        Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |Sort-Object -Property lastwritetime
        (Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue).FullName |ForEach-Object {Get-FileHash -Algorithm SHA1 -Path $_} #Gets SHA1 of all files in the bin.
        "=== NAMED PIPES ==="
        Get-ChildItem \\.\pipe\ |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows named pipes

